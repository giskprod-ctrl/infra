#!/usr/bin/env bash
set -euo pipefail

# === Configurable defaults ===
SAMPLE_DIR="${SAMPLE_DIR:-./samples}"
OUTPUT_DIR="${TRIAGE_OUTPUT_DIR:-$SAMPLE_DIR}"
YARA_RULE_DIR="${YARA_RULE_DIR:-./yara_rules}"
TIMEOUT_SECONDS="${TRIAGE_TIMEOUT_SECONDS:-30}"
PESIEVE_BIN="${PESIEVE_BIN:-/opt/pesieve/pe-sieve64.exe}"
RIZIN_CMD="${RIZIN_CMD:-rizin}"
FORCE_NONROOT="${FORCE_NONROOT:-1}"
WINEPREFIX="${WINEPREFIX:-$HOME/.wine-triage}"
LOCAL_AV_CONFIG="${LOCAL_AV_CONFIG:-./local_av_scanners.json}"
SUSPICION_THRESHOLD="${SUSPICION_THRESHOLD:-50}"
MAX_DLL_EXPORTS="${MAX_DLL_EXPORTS:-5}"
STATIC_STRINGS_LIMIT="${STATIC_STRINGS_LIMIT:-200}"

print_usage() {
  cat <<'USAGE'
Usage: ./triage.sh --file <sample_path> [--json <output_json>] [--debug]

Runs static/rapid dynamic triage for the specified PE file.
Environment variables override defaults defined at the top of the script.
USAGE
}

log() { echo "[triage] $*" >&2; }

if ! command -v jq >/dev/null 2>&1; then
  log "jq is required"
  exit 1
fi

if [[ "${FORCE_NONROOT}" == "1" && "$(id -u)" -eq 0 ]]; then
  log "Refusing to run as root. Override with FORCE_NONROOT=0 if you know what you're doing."
  exit 1
fi

SAMPLE=""
OUTPUT_JSON=""
DEBUG=0

while (("$#")); do
  case "$1" in
    -f|--file)
      SAMPLE="$2"; shift 2 ;;
    -o|--json)
      OUTPUT_JSON="$2"; shift 2 ;;
    --debug)
      DEBUG=1; shift ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      log "Unknown argument: $1"; print_usage; exit 1 ;;
  esac
done

if [[ -z "${SAMPLE}" ]]; then
  log "You must supply a sample with --file"; exit 1
fi

if [[ ! -f "${SAMPLE}" ]]; then
  log "Sample ${SAMPLE} not found"; exit 1
fi

SAMPLE_ABS="$(realpath "${SAMPLE}")"
SAMPLE_NAME="$(basename "${SAMPLE}")"
OUTPUT_JSON="${OUTPUT_JSON:-${OUTPUT_DIR}/${SAMPLE_NAME}.triage.json}"
mkdir -p "$(dirname "${OUTPUT_JSON}")"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

sha256=$(sha256sum "${SAMPLE_ABS}" | awk '{print $1}')
size=$(stat --printf="%s" "${SAMPLE_ABS}")
filetype=$(file -b "${SAMPLE_ABS}" || true)

entropy=$(python3 - "$SAMPLE_ABS" <<'PY'
import math, sys
path = sys.argv[1]
with open(path, 'rb') as fh:
    data = fh.read()
if not data:
    print('0')
    sys.exit(0)
freq = [0]*256
for b in data:
    freq[b]+=1
entropy = 0.0
for count in freq:
    if count:
        p = count/len(data)
        entropy -= p * math.log2(p)
print(f"{entropy:.4f}")
PY
)

run_wine() {
  local cmd="$1"; shift
  if command -v wine64 >/dev/null 2>&1; then
    WINEPREFIX="${WINEPREFIX}" wine64 "$cmd" "$@"
  elif command -v wine >/dev/null 2>&1; then
    WINEPREFIX="${WINEPREFIX}" wine "$cmd" "$@"
  else
    return 127
  fi
}

collect_static_metadata() {
  local sample_path="$1"
  local rizin_bin="$2"
  local out_file="$3"
  local max_exports="$4"
  local threshold="$5"
  local strings_limit="$6"
  local strings_dir="$7"
  python3 - "$sample_path" "$rizin_bin" "$out_file" "$max_exports" "$threshold" "$strings_limit" "$strings_dir" <<'PY'
import json
import math
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sample = Path(sys.argv[1])
rizin_bin = sys.argv[2]
out_path = Path(sys.argv[3])
max_exports = int(sys.argv[4])
threshold = float(sys.argv[5])
strings_limit = int(sys.argv[6])
strings_dir = Path(sys.argv[7])

analysis = {
    "rizin": {},
    "errors": [],
}

def shannon_entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    freq = [0] * 256
    for b in blob:
        freq[b] += 1
    entropy = 0.0
    length = len(blob)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return round(entropy, 4)

def run_rizin(command: str):
    try:
        result = subprocess.run(
            [rizin_bin, "-nq", "-c", command, str(sample)],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except FileNotFoundError:
        analysis.setdefault("errors", []).append("rizin_not_found")
        return None
    except Exception as exc:  # pragma: no cover - defensive
        analysis.setdefault("errors", []).append(f"rizin_error:{command}:{exc}")
        return None

    stdout = result.stdout.strip()
    if not stdout:
        return None
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        # Provide raw output for debugging rather than failing the whole triage.
        return {"raw": stdout}

rizin_commands = {
    "image": "iIj",
    "sections": "iSj",
    "imports": "iij",
    "exports": "iEj",
    "strings": "izj",
    "resources": "irj",
    "certificates": "icj",
}

for key, command in rizin_commands.items():
    data = run_rizin(command)
    if data is not None:
        analysis["rizin"][key] = data

def parse_pe_metadata(path: Path):
    result = {
        "is_pe": False,
        "is_dll": False,
        "timestamp": None,
        "timestamp_iso": None,
        "characteristics": [],
        "sections": [],
        "entry_point_rva": None,
        "entry_point_section": None,
        "overlay_size": 0,
        "size_of_image": None,
        "size_of_headers": None,
    }
    characteristics_map = {
        0x0002: "executable_image",
        0x2000: "dll",
        0x0004: "line_nums_stripped",
        0x0008: "local_syms_stripped",
        0x0020: "large_address_aware",
        0x0100: "32bit_machine",
        0x2000: "dll",
        0x1000: "system",
    }

    try:
        data = path.read_bytes()
    except Exception as exc:  # pragma: no cover - defensive
        analysis.setdefault("errors", []).append(f"read_error:{exc}")
        return result, data if 'data' in locals() else b""

    if len(data) < 0x40 or data[:2] != b"MZ":
        return result, data

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return result, data

    if e_lfanew + 0x18 >= len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return result, data

    result["is_pe"] = True

    try:
        machine, number_of_sections, timestamp, _, _, size_optional_header, characteristics = struct.unpack_from(
            "<HHIIIHH", data, e_lfanew + 4
        )
    except struct.error:
        return result, data

    result["characteristics_raw"] = characteristics
    for flag, name in characteristics_map.items():
        if characteristics & flag and name not in result["characteristics"]:
            result["characteristics"].append(name)

    result["is_dll"] = bool(characteristics & 0x2000)

    result["timestamp"] = int(timestamp)
    if timestamp:
        try:
            result["timestamp_iso"] = datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()
        except Exception:
            pass

    optional_offset = e_lfanew + 24
    optional_end = optional_offset + size_optional_header
    if optional_end > len(data):
        size_optional_header = max(0, len(data) - optional_offset)
        optional_end = optional_offset + size_optional_header

    try:
        magic = struct.unpack_from("<H", data, optional_offset)[0]
    except struct.error:
        magic = None

    entry_point_rva = None
    size_of_image = None
    size_of_headers = None
    image_base = None

    if magic == 0x10B and size_optional_header >= 0x5C:
        entry_point_rva = struct.unpack_from("<I", data, optional_offset + 0x10)[0]
        image_base = struct.unpack_from("<I", data, optional_offset + 0x1C)[0]
        size_of_image = struct.unpack_from("<I", data, optional_offset + 0x38)[0]
        size_of_headers = struct.unpack_from("<I", data, optional_offset + 0x3C)[0]
    elif magic == 0x20B and size_optional_header >= 0x6C:
        entry_point_rva = struct.unpack_from("<I", data, optional_offset + 0x10)[0]
        image_base = struct.unpack_from("<Q", data, optional_offset + 0x18)[0]
        size_of_image = struct.unpack_from("<I", data, optional_offset + 0x38)[0]
        size_of_headers = struct.unpack_from("<I", data, optional_offset + 0x3C)[0]

    result["entry_point_rva"] = entry_point_rva
    result["image_base"] = image_base
    result["size_of_image"] = size_of_image
    result["size_of_headers"] = size_of_headers

    section_table_offset = optional_offset + size_optional_header
    sections = []
    max_end = size_of_headers or 0
    for index in range(number_of_sections):
        entry_offset = section_table_offset + index * 40
        if entry_offset + 40 > len(data):
            break
        raw_name = data[entry_offset:entry_offset + 8]
        name = raw_name.split(b"\x00")[0].decode(errors="ignore") or f"sec_{index}"
        try:
            (
                virtual_size,
                virtual_address,
                size_of_raw_data,
                pointer_to_raw_data,
                _pointer_to_relocations,
                _pointer_to_linenumbers,
                _number_of_relocations,
                _number_of_linenumbers,
                characteristics_section,
            ) = struct.unpack_from("<IIIIIIHHI", data, entry_offset + 8)
        except struct.error:
            break

        section_data = b""
        if pointer_to_raw_data and size_of_raw_data:
            start = pointer_to_raw_data
            end = min(len(data), pointer_to_raw_data + size_of_raw_data)
            section_data = data[start:end]

        entropy = shannon_entropy(section_data)
        section_end = pointer_to_raw_data + size_of_raw_data
        if section_end > max_end:
            max_end = section_end

        sections.append({
            "name": name,
            "virtual_size": virtual_size,
            "virtual_address": virtual_address,
            "raw_size": size_of_raw_data,
            "raw_offset": pointer_to_raw_data,
            "entropy": entropy,
            "characteristics": characteristics_section,
            "executable": bool(characteristics_section & 0x20000000),
            "writable": bool(characteristics_section & 0x80000000),
        })

    result["sections"] = sections
    if len(data) > max_end:
        result["overlay_size"] = len(data) - max_end

    if entry_point_rva is not None:
        for section in sections:
            virtual_end = section["virtual_address"] + max(section["virtual_size"], section["raw_size"])
            if section["virtual_address"] <= entry_point_rva < virtual_end:
                result["entry_point_section"] = section["name"]
                break

    return result, data

pe_metadata, file_bytes = parse_pe_metadata(sample)
analysis["pe_metadata"] = pe_metadata

imports = analysis["rizin"].get("imports") or []
exports = analysis["rizin"].get("exports") or []
strings_raw = analysis["rizin"].get("strings")
if isinstance(strings_raw, dict) and "strings" in strings_raw:
    strings_list = strings_raw.get("strings") or []
elif isinstance(strings_raw, list):
    strings_list = strings_raw
else:
    strings_list = []
sections_rizin = analysis["rizin"].get("sections") or []

if isinstance(imports, dict) and "imports" in imports:
    imports = imports.get("imports")
if isinstance(exports, dict) and "exports" in exports:
    exports = exports.get("exports")

def extract_string_text(entry):
    if isinstance(entry, dict):
        value = entry.get("string") or entry.get("value") or ""
    else:
        value = str(entry)
    if not isinstance(value, str):
        value = str(value)
    return value

dependency_modules = []
suspect_imports = []
import_names = set()
if isinstance(imports, list):
    for entry in imports:
        if isinstance(entry, dict):
            lib = entry.get("lib") or entry.get("name")
            if lib:
                dependency_modules.append(lib)
            name = entry.get("name")
            if name:
                import_names.add(name)
        elif isinstance(entry, str):
            import_names.add(entry)

suspect_symbols = {
    "VirtualAlloc",
    "VirtualProtect",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "WinExec",
    "ShellExecuteA",
    "URLDownloadToFileA",
    "URLDownloadToFileW",
    "WSASocketA",
    "InternetOpenA",
    "InternetOpenUrlA",
    "InternetConnectA",
    "ZwUnmapViewOfSection",
    "NtCreateThreadEx",
}

for symbol in sorted(import_names):
    base = symbol.split("@")[0]
    if base in suspect_symbols:
        suspect_imports.append(symbol)

pe_metadata["dependency_modules"] = sorted({mod for mod in dependency_modules if mod})
pe_metadata["suspect_imports"] = suspect_imports

extracted_strings = []
if isinstance(strings_list, list):
    for entry in strings_list:
        value = extract_string_text(entry)
        if value:
            extracted_strings.append(value)

url_pattern = re.compile(r"https?://[\w\.-/:?=&%]+", re.IGNORECASE)
ipv4_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
registry_pattern = re.compile(r"HKEY_[A-Z_\\\\]+[\w\\\\/]+", re.IGNORECASE)
email_pattern = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)

def score_string(text: str) -> int:
    score = len(text)
    if url_pattern.search(text):
        score += 150
    if ipv4_pattern.search(text):
        score += 75
    if registry_pattern.search(text):
        score += 90
    if email_pattern.search(text):
        score += 110
    if any(ch in text for ch in ("\\", "%", ":")):
        score += 5
    return score

indicators = {
    "urls": [],
    "ipv4": [],
    "registry": [],
    "emails": [],
}

for text in extracted_strings[:10000]:  # safety guard
    indicators["urls"].extend(url_pattern.findall(text))
    indicators["ipv4"].extend(ipv4_pattern.findall(text))
    indicators["registry"].extend(registry_pattern.findall(text))
    indicators["emails"].extend(email_pattern.findall(text))

for key in list(indicators.keys()):
    unique = sorted({item.strip() for item in indicators[key] if item})
    indicators[key] = unique[:100]

analysis["indicators"] = indicators

stored_strings = list(strings_list) if isinstance(strings_list, list) else []
total_strings = len(stored_strings)
truncated_count = 0
overflow_artifact = None

if strings_limit > 0 and total_strings > strings_limit and isinstance(strings_list, list):
    scored_entries = []
    for entry in strings_list:
        text = extract_string_text(entry)
        scored_entries.append((score_string(text), len(text), entry))
    scored_entries.sort(key=lambda item: (item[0], item[1]), reverse=True)
    limited = []
    for _, _, entry in scored_entries[:strings_limit]:
        if isinstance(entry, dict):
            limited.append(dict(entry))
        else:
            limited.append(entry)
    stored_strings = limited
    truncated_count = total_strings - len(stored_strings)
    artifact_path = strings_dir / f"{sample.name}.strings.json"
    try:
        strings_dir.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(json.dumps(strings_list, indent=2))
        overflow_artifact = str(artifact_path)
    except Exception as exc:
        analysis.setdefault("errors", []).append(f"strings_artifact_error:{exc}")
elif strings_limit == 0 and isinstance(strings_list, list):
    stored_strings = []
    truncated_count = total_strings
    artifact_path = strings_dir / f"{sample.name}.strings.json"
    try:
        strings_dir.mkdir(parents=True, exist_ok=True)
        artifact_path.write_text(json.dumps(strings_list, indent=2))
        overflow_artifact = str(artifact_path)
    except Exception as exc:
        analysis.setdefault("errors", []).append(f"strings_artifact_error:{exc}")
else:
    artifact_path = strings_dir / f"{sample.name}.strings.json"
    remove_existing = False
    if strings_limit > 0:
        remove_existing = total_strings <= strings_limit
    else:
        remove_existing = True
    if remove_existing and artifact_path.exists():
        try:
            artifact_path.unlink()
        except Exception:
            pass

if isinstance(strings_raw, dict):
    limited_payload = dict(strings_raw)
    limited_payload["strings"] = stored_strings
    if "count" in limited_payload:
        limited_payload["count"] = total_strings
    analysis["rizin"]["strings"] = limited_payload
else:
    analysis["rizin"]["strings"] = stored_strings
analysis["string_stats"] = {
    "total": total_strings,
    "stored": len(stored_strings),
    "truncated": truncated_count,
    "limit": strings_limit if strings_limit >= 0 else None,
}
if overflow_artifact:
    analysis["string_stats"]["overflow_artifact"] = overflow_artifact

packed_sections = [
    section
    for section in pe_metadata.get("sections", [])
    if isinstance(section.get("entropy"), (int, float)) and section["entropy"] >= 7.2
]

heuristics = {
    "score": 0,
    "threshold": threshold,
    "reasons": [],
    "flags": {
        "packed_sections": [section.get("name") for section in packed_sections],
    },
    "suspicious_imports": suspect_imports,
}

def add_reason(reason: str, weight: int):
    heuristics["reasons"].append(reason)
    heuristics["score"] += weight

global_entropy = shannon_entropy(file_bytes)
analysis["global_entropy"] = global_entropy

if global_entropy >= 7.2:
    add_reason("High overall entropy suggests packing", 20)

if packed_sections:
    add_reason("Detected high-entropy sections", 15)

overlay_size = pe_metadata.get("overlay_size") or 0
if overlay_size:
    add_reason(f"Overlay detected ({overlay_size} bytes)", 10)

timestamp_value = pe_metadata.get("timestamp") or 0
if timestamp_value in (0, 1):
    add_reason("PE timestamp is zero or unset", 10)
else:
    try:
        if datetime.fromtimestamp(timestamp_value, tz=timezone.utc).year < 2000:
            add_reason("PE timestamp predates year 2000", 5)
    except Exception:
        pass

if suspect_imports:
    add_reason("Suspicious API imports present", 15)

if pe_metadata.get("is_dll") and not exports:
    add_reason("DLL exposes no exports", 10)

if pe_metadata.get("entry_point_section"):
    sections_by_name = {section["name"]: section for section in pe_metadata.get("sections", [])}
    entry_section = sections_by_name.get(pe_metadata["entry_point_section"])
    if entry_section and not entry_section.get("executable"):
        add_reason("Entry point located in non-executable section", 10)

heuristics["score"] = min(100, heuristics["score"])
heuristics["suggested_suspect"] = heuristics["score"] >= threshold
analysis["heuristics"] = heuristics

def select_exports(exports_list):
    selected = []
    seen = set()
    for entry in exports_list:
        name = None
        if isinstance(entry, dict):
            name = entry.get("name") or entry.get("demangled")
        elif isinstance(entry, str):
            name = entry
        if not name:
            continue
        base = name.strip()
        if not base or base in seen:
            continue
        seen.add(base)
        selected.append(base)
        if len(selected) >= max_exports:
            break
    return selected

exports_list = exports if isinstance(exports, list) else []
suggested_exports = select_exports(exports_list)

dll_analysis = {
    "export_count": len(exports_list),
    "suggested_exports": suggested_exports,
    "recommended_invocations": [],
}

if pe_metadata.get("is_dll"):
    # Default to DllMain if no named exports are present
    targets = suggested_exports or ["DllMain"]
    for export_name in targets:
        dll_analysis["recommended_invocations"].append({
            "export": export_name,
            "command": "rundll32.exe",
            "arguments": [f'"{sample}"', export_name],
        })

analysis["dll_analysis"] = dll_analysis

out_path.write_text(json.dumps(analysis, indent=2))
PY
}

pesieve_status="not_run"
pesieve_stdout=""
pesieve_dir="${TMPDIR}/pesieve"
mkdir -p "${pesieve_dir}"
if [[ -f "${PESIEVE_BIN}" ]]; then
  log "Running PE-sieve on sample"
  if run_wine "${PESIEVE_BIN}" /log /o "${pesieve_dir}" /shellc /pid 0 /quiet /dir "$(dirname "${SAMPLE_ABS}")" /proc "${SAMPLE_NAME}" >/"${TMPDIR}/pesieve.log" 2>&1; then
    pesieve_status="completed"
    pesieve_stdout="$(cat "${TMPDIR}/pesieve.log" | tail -n 50)"
  else
    pesieve_status="error"
    pesieve_stdout="$(cat "${TMPDIR}/pesieve.log" | tail -n 50)"
  fi
else
  log "pe-sieve binary not found at ${PESIEVE_BIN}, skipping"
fi

static_metadata_file="${TMPDIR}/static-analysis.json"
static_metadata='{}'
heuristics_suspect="false"
heuristics_score="0"
if command -v "${RIZIN_CMD}" >/dev/null 2>&1; then
  if collect_static_metadata "${SAMPLE_ABS}" "${RIZIN_CMD}" "${static_metadata_file}" "${MAX_DLL_EXPORTS}" "${SUSPICION_THRESHOLD}" "${STATIC_STRINGS_LIMIT}" "$(dirname "${OUTPUT_JSON}")"; then
    static_metadata="$(<"${static_metadata_file}")"
    heuristics_suspect="$(jq -r '(.heuristics.suggested_suspect // false) | tostring' "${static_metadata_file}" 2>/dev/null || echo false)"
    heuristics_score="$(jq -r '(.heuristics.score // 0) | tostring' "${static_metadata_file}" 2>/dev/null || echo 0)"
  else
    log "Static metadata collection failed"
  fi
else
  log "Rizin not found in PATH"
fi

yara_matches=()
if command -v yara >/dev/null 2>&1 && [[ -d "${YARA_RULE_DIR}" ]]; then
  mapfile -t yara_matches < <(yara -w -g -m "${YARA_RULE_DIR}" "${SAMPLE_ABS}" 2>/dev/null | awk '{print $1}')
fi

yara_json='[]'
if [[ ${#yara_matches[@]} -gt 0 ]]; then
  yara_json=$(printf '%s\n' "${yara_matches[@]}" | jq -Rcs 'split("\n") | map(select(length>0))')
fi

av_results=()
load_av_config() {
  local config_json=""
  if [[ -n "${AV_SCANNERS_JSON:-}" ]]; then
    config_json="${AV_SCANNERS_JSON}"
  elif [[ -f "${LOCAL_AV_CONFIG}" ]]; then
    config_json="$(<"${LOCAL_AV_CONFIG}")"
  else
    return 1
  fi

  if ! jq empty <<<"${config_json}" >/dev/null 2>&1; then
    log "Invalid AV scanners JSON configuration"
    return 1
  fi

  while IFS= read -r scanner; do
    av_results+=("$(run_av_scanner "${scanner}")")
  done < <(jq -c '.[]' <<<"${config_json}")
}

run_av_scanner() {
  local scanner_json="$1"
  local name
  name="$(jq -r '.name // "unknown"' <<<"${scanner_json}")"

  mapfile -t cmd < <(jq -r '.cmd[]?' <<<"${scanner_json}")
  if [[ ${#cmd[@]} -eq 0 ]]; then
    printf '%s' "$(jq -n --arg name "${name}" --arg status "invalid_config" --arg output "Missing command" '{"name":$name,"status":$status,"return_code":null,"output":$output}')"
    return 0
  fi

  local resolved_cmd=()
  for arg in "${cmd[@]}"; do
    resolved_cmd+=("${arg//\{sample\}/${SAMPLE_ABS}}")
  done

  local executable="${resolved_cmd[0]}"
  if ! command -v "${executable}" >/dev/null 2>&1; then
    printf '%s' "$(jq -n --arg name "${name}" --arg status "not_available" --arg output "${executable} not found" '{"name":$name,"status":$status,"return_code":127,"output":$output}')"
    return 0
  fi

  local rc output
  set +e
  output="$("${resolved_cmd[@]}" 2>&1)"
  rc=$?
  set -e

  local status="unknown"
  case "${rc}" in
    0) status="clean" ;;
    1) status="malicious" ;;
    2) status="error" ;;
  esac

  printf '%s' "$(jq -n \
    --arg name "${name}" \
    --arg status "${status}" \
    --arg output "${output}" \
    --argjson return_code "${rc}" \
    '{"name":$name,"status":$status,"return_code":$return_code,"output":$output}')"
}

if command -v jq >/dev/null 2>&1; then
  load_av_config || true
fi

if [[ ${#av_results[@]} -gt 0 ]]; then
  av_results_json="$(printf '%s\n' "${av_results[@]}" | jq -s '.')"
else
  av_results_json='[]'
fi

av_flag="false"
if [[ "${av_results_json}" != '[]' ]]; then
  if jq -e 'map(select(.status == "malicious")) | length > 0' <<<"${av_results_json}" >/dev/null 2>&1; then
    av_flag="true"
  fi
fi

suspected=false
declare -a suspicion_reasons

if [[ "${heuristics_suspect}" == "true" ]]; then
  suspected=true
  if [[ -f "${static_metadata_file}" ]]; then
    suspicion_reasons+=("$(jq -c '{source:"heuristics", score:(.heuristics.score // 0), threshold:(.heuristics.threshold // 0), reasons:(.heuristics.reasons // []), flags:(.heuristics.flags // {})}' "${static_metadata_file}" 2>/dev/null || echo '{}')")
  fi
fi

if [[ ${#yara_matches[@]} -gt 0 ]]; then
  suspected=true
  suspicion_reasons+=("$(jq -n --argjson matches "${yara_json}" '{source:"yara", matches:$matches}')")
fi

if [[ "${pesieve_status}" == "error" ]]; then
  suspected=true
  suspicion_reasons+=("$(jq -n '{source:"pe-sieve", detail:"execution_error"}')")
fi

if [[ "${av_flag}" == "true" ]]; then
  suspected=true
  suspicion_reasons+=("$(jq -n --argjson scans "${av_results_json}" '{source:"av", detections:($scans | map(select(.status=="malicious")))}')")
fi

if [[ $(python3 - <<'PY' "$entropy"
import sys
try:
    print('true' if float(sys.argv[1]) > 7.3 else 'false')
except Exception:
    print('false')
PY
) == 'true' ]]; then
  suspected=true
  suspicion_reasons+=("$(jq -n --arg entropy "${entropy}" '{source:"entropy", global_entropy:($entropy|tonumber)}')")
fi

if [[ ${#suspicion_reasons[@]} -gt 0 ]]; then
  suspicion_breakdown_json="$(printf '%s\n' "${suspicion_reasons[@]}" | jq -s '.')"
else
  suspicion_breakdown_json='[]'
fi

static_analysis_json="$(jq -c '.' <<<"${static_metadata}" 2>/dev/null || echo '{}')"
pe_metadata_json="$(jq -c '.pe_metadata // {}' <<<"${static_analysis_json}" 2>/dev/null || echo '{}')"
dll_analysis_json="$(jq -c '.dll_analysis // {}' <<<"${static_analysis_json}" 2>/dev/null || echo '{}')"
indicators_json="$(jq -c '.indicators // {}' <<<"${static_analysis_json}" 2>/dev/null || echo '{}')"
heuristics_json="$(jq -c '.heuristics // {}' <<<"${static_analysis_json}" 2>/dev/null || echo '{}')"

debug_log=""
if [[ ${DEBUG} -eq 1 ]]; then
  debug_log="$(cat <<DBG
pesieve_stdout:
${pesieve_stdout}
---
static_analysis:
${static_metadata}
---
suspicion_breakdown:
${suspicion_breakdown_json}
DBG
)"
fi

cat <<JSON > "${OUTPUT_JSON}"
{
  "sample": "${SAMPLE_ABS}",
  "sha256": "${sha256}",
  "size": ${size},
  "filetype": "${filetype}",
  "entropy": ${entropy},
  "yara_matches": ${yara_json},
  "pesieve": {
    "status": "${pesieve_status}",
    "log_tail": $(jq -Rs '.' <<<"${pesieve_stdout}")
  },
  "static_analysis": ${static_analysis_json},
  "pe_metadata": ${pe_metadata_json},
  "dll_analysis": ${dll_analysis_json},
  "indicators": ${indicators_json},
  "heuristics": ${heuristics_json},
  "suspicion_breakdown": ${suspicion_breakdown_json},
  "av_scans": ${av_results_json},
  "suspected": ${suspected},
  "triage_timestamp": "$(date --iso-8601=seconds)",
  "tool_metadata": {
    "triage_version": "1.0.0",
    "timeout_seconds": ${TIMEOUT_SECONDS},
    "operator": "${USER:-unknown}",
    "suspicion_threshold": ${SUSPICION_THRESHOLD}
  },
  "debug": $(jq -Rs '.' <<<"${debug_log}")
}
JSON

log "Triage report written to ${OUTPUT_JSON}"
