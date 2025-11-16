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

print_usage() {
  cat <<'USAGE'
Usage: ./triage.sh --file <sample_path> [--json <output_json>] [--debug] \
                   [--yara-index <path>] [--yara-category <name>]

Runs static/rapid dynamic triage for the specified PE file.
Environment variables override defaults defined at the top of the script.

`--yara-index` may be repeated to point to custom rule indexes. Use
`--yara-category` to select built-in categories (e.g. `malware`, `lolbin`,
`internal`, `vendor/signature-base`).
USAGE
}

log() { echo "[triage] $*" >&2; }

abs_path() {
  python3 - "$1" <<'PY'
import os
import sys

path = sys.argv[1]
print(os.path.abspath(path))
PY
}

rel_path() {
  python3 - "$1" "$2" <<'PY'
import os
import sys

target = os.path.abspath(sys.argv[1])
base = os.path.abspath(sys.argv[2])
try:
    print(os.path.relpath(target, base))
except ValueError:
    print(target)
PY
}

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
declare -a CLI_YARA_INDEXES=()
declare -a CLI_YARA_CATEGORIES=()

while (("$#")); do
  case "$1" in
    -f|--file)
      SAMPLE="$2"; shift 2 ;;
    -o|--json)
      OUTPUT_JSON="$2"; shift 2 ;;
    --debug)
      DEBUG=1; shift ;;
    --yara-index)
      CLI_YARA_INDEXES+=("$2"); shift 2 ;;
    --yara-category)
      CLI_YARA_CATEGORIES+=("$2"); shift 2 ;;
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

YARA_RULE_DIR_ABS=""
if [[ -d "${YARA_RULE_DIR}" ]]; then
  YARA_RULE_DIR_ABS="$(abs_path "${YARA_RULE_DIR}")"
fi

declare -a SELECTED_YARA_INDEXES=()

if [[ ${#CLI_YARA_INDEXES[@]} -eq 0 && ${#CLI_YARA_CATEGORIES[@]} -eq 0 ]]; then
  if [[ -n "${YARA_RULE_DIR_ABS}" && -f "${YARA_RULE_DIR_ABS}/index.yar" ]]; then
    SELECTED_YARA_INDEXES+=("${YARA_RULE_DIR_ABS}/index.yar")
  fi
else
  for index_path in "${CLI_YARA_INDEXES[@]}"; do
    resolved_path="$(abs_path "${index_path}")"
    if [[ -f "${resolved_path}" ]]; then
      SELECTED_YARA_INDEXES+=("${resolved_path}")
    else
      log "YARA index ${index_path} not found"
    fi
  done

  for category in "${CLI_YARA_CATEGORIES[@]}"; do
    if [[ -z "${YARA_RULE_DIR_ABS}" ]]; then
      log "Cannot resolve category ${category} without YARA_RULE_DIR"
      continue
    fi
    category_index="${YARA_RULE_DIR_ABS}/${category}/index.yar"
    if [[ -f "${category_index}" ]]; then
      SELECTED_YARA_INDEXES+=("${category_index}")
    else
      log "Category index ${category_index} not found"
    fi
  done
fi

declare -a UNIQUE_YARA_INDEXES=()
declare -A _seen_indexes=()
for candidate in "${SELECTED_YARA_INDEXES[@]}"; do
  key="${candidate}"
  if [[ -n "${key}" && -z "${_seen_indexes[$key]+x}" ]]; then
    UNIQUE_YARA_INDEXES+=("${key}")
    _seen_indexes["${key}"]=1
  fi
done

if [[ ${#UNIQUE_YARA_INDEXES[@]} -eq 0 ]]; then
  log "No YARA indexes selected; skipping YARA scan stage"
fi

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

ssdeep_hash=""
if command -v ssdeep >/dev/null 2>&1; then
  if ssdeep_output=$(ssdeep -b "${SAMPLE_ABS}" 2>/dev/null); then
    ssdeep_hash=$(printf '%s\n' "${ssdeep_output}" | tail -n +2 | head -n 1 | cut -d',' -f2)
  fi
else
  log "ssdeep binary not found, skipping fuzzy hash"
fi

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
  python3 - "$sample_path" "$rizin_bin" "$out_file" "$max_exports" "$threshold" <<'PY'
import hashlib
import json
import math
import re
import struct
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import pefile  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    pefile = None

sample = Path(sys.argv[1])
rizin_bin = sys.argv[2]
out_path = Path(sys.argv[3])
max_exports = int(sys.argv[4])
threshold = float(sys.argv[5])

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
        "image_base": None,
        "address_of_entry_point": None,
        "data_directories": [],
    }
    characteristics_map = {
        0x0002: "executable_image",
        0x2000: "dll",
        0x0004: "line_nums_stripped",
        0x0008: "local_syms_stripped",
        0x0020: "large_address_aware",
        0x0100: "32bit_machine",
        0x1000: "system",
    }

    try:
        data = path.read_bytes()
    except Exception as exc:  # pragma: no cover - defensive
        analysis.setdefault("errors", []).append(f"read_error:{exc}")
        return result, data if 'data' in locals() else b"", {}

    if len(data) < 0x40 or data[:2] != b"MZ":
        return result, data, {}

    try:
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return result, data, {}

    if e_lfanew + 0x18 >= len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return result, data, {}

    result["is_pe"] = True

    try:
        machine, number_of_sections, timestamp, _, _, size_optional_header, characteristics = struct.unpack_from(
            "<HHIIIHH", data, e_lfanew + 4
        )
    except struct.error:
        return result, data, {}

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

    is_pe32_plus = magic == 0x20B
    pointer_size = 8 if is_pe32_plus else 4

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
    result["address_of_entry_point"] = entry_point_rva
    result["image_base"] = image_base
    result["size_of_image"] = size_of_image
    result["size_of_headers"] = size_of_headers
    result["optional_header_magic"] = magic

    # Data directories
    data_directories = []
    data_directory_names = [
        "export_table",
        "import_table",
        "resource_table",
        "exception_table",
        "certificate_table",
        "base_relocation_table",
        "debug_directory",
        "architecture",
        "global_ptr",
        "tls_table",
        "load_config_table",
        "bound_import",
        "iat",
        "delay_import_descriptor",
        "clr_runtime_header",
        "reserved",
    ]
    dd_offset = optional_offset + (96 if not is_pe32_plus else 112)
    number_of_rva_and_sizes = min(16, (size_optional_header - (dd_offset - optional_offset)) // 8)
    for idx in range(number_of_rva_and_sizes):
        entry_offset = dd_offset + idx * 8
        if entry_offset + 8 > len(data):
            break
        rva, size_entry = struct.unpack_from("<II", data, entry_offset)
        data_directories.append({
            "name": data_directory_names[idx],
            "rva": rva,
            "size": size_entry,
        })

    result["data_directories"] = data_directories

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

        section_hash = hashlib.sha256(section_data).hexdigest() if section_data else None
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
            "sha256": section_hash,
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

    return result, data, {
        "e_lfanew": e_lfanew,
        "is_pe32_plus": is_pe32_plus,
        "pointer_size": pointer_size,
    }

pe_metadata, file_bytes, pe_context = parse_pe_metadata(sample)
analysis["pe_metadata"] = pe_metadata

sections_for_rva = pe_metadata.get("sections", [])

def rva_to_offset(rva: int):
    for section in sections_for_rva:
        va = section.get("virtual_address") or 0
        raw = section.get("raw_offset") or 0
        size_virtual = section.get("virtual_size") or 0
        size_raw = section.get("raw_size") or 0
        size = max(size_virtual, size_raw)
        if size == 0:
            continue
        if va <= rva < va + size:
            return raw + (rva - va)
    headers_size = pe_metadata.get("size_of_headers") or 0
    if 0 <= rva < headers_size:
        return rva
    return None

def read_c_string(blob: bytes, offset: int) -> str:
    if offset is None or offset < 0 or offset >= len(blob):
        return ""
    end = blob.find(b"\x00", offset)
    if end == -1:
        end = len(blob)
    return blob[offset:end].decode("utf-8", errors="replace")

def parse_import_descriptors(blob: bytes):
    imports_dir = None
    for entry in pe_metadata.get("data_directories", []):
        if entry.get("name") == "import_table":
            imports_dir = entry
            break
    if not imports_dir or not imports_dir.get("rva"):
        return []
    descriptor_offset = rva_to_offset(imports_dir["rva"])
    if descriptor_offset is None:
        return []
    pointer_size = pe_context.get("pointer_size", 4)
    fmt = "<Q" if pointer_size == 8 else "<I"
    descriptors = []
    while descriptor_offset + 20 <= len(blob):
        fields = struct.unpack_from("<IIIII", blob, descriptor_offset)
        descriptor_offset += 20
        original_first_thunk, time_date_stamp, forwarder_chain, name_rva, first_thunk = fields
        if not any(fields):
            break
        dll_name = read_c_string(blob, rva_to_offset(name_rva))
        thunk_rva = original_first_thunk or first_thunk
        thunk_offset = rva_to_offset(thunk_rva)
        imports_local = []
        if thunk_offset is not None:
            while thunk_offset + pe_context.get("pointer_size", 4) <= len(blob):
                thunk_data = struct.unpack_from(fmt, blob, thunk_offset)[0]
                thunk_offset += pe_context.get("pointer_size", 4)
                if thunk_data == 0:
                    break
                if pe_context.get("pointer_size", 4) == 8:
                    ordinal_flag = 0x8000000000000000
                    ordinal_mask = 0xFFFF
                else:
                    ordinal_flag = 0x80000000
                    ordinal_mask = 0xFFFF
                import_by_ordinal = bool(thunk_data & ordinal_flag)
                ordinal = thunk_data & ordinal_mask if import_by_ordinal else None
                name = None
                if not import_by_ordinal:
                    hint_name_offset = rva_to_offset(thunk_data)
                    if hint_name_offset is not None and hint_name_offset + 2 < len(blob):
                        hint = struct.unpack_from("<H", blob, hint_name_offset)[0]
                        name = read_c_string(blob, hint_name_offset + 2)
                        ordinal = hint
                imports_local.append({
                    "name": name,
                    "ordinal": ordinal,
                    "import_by_ordinal": import_by_ordinal,
                })
        descriptors.append({
            "dll": dll_name,
            "imports": imports_local,
        })
    return descriptors

def compute_imphash(descriptors):
    if not descriptors:
        return None
    sequence = []
    for descriptor in descriptors:
        dll = (descriptor.get("dll") or "").lower()
        for imp in descriptor.get("imports", []):
            if imp.get("name"):
                sequence.append(f"{dll}.{imp['name'].lower()}")
            elif imp.get("ordinal") is not None:
                sequence.append(f"{dll}.ord{imp['ordinal']}")
    if not sequence:
        return None
    joined = ",".join(sequence)
    return hashlib.md5(joined.encode("utf-8", errors="ignore")).hexdigest()

def parse_tls_callbacks(blob: bytes):
    tls_dir = next((entry for entry in pe_metadata.get("data_directories", []) if entry.get("name") == "tls_table"), None)
    if not tls_dir or not tls_dir.get("rva"):
        return {}
    tls_offset = rva_to_offset(tls_dir["rva"])
    if tls_offset is None:
        return {}
    pointer_size = pe_context.get("pointer_size", 4)
    image_base = pe_metadata.get("image_base") or 0
    if pointer_size == 8:
        fmt = "<QQQQII"
    else:
        fmt = "<IIIIII"
    size_needed = struct.calcsize(fmt)
    if tls_offset + size_needed > len(blob):
        return {}
    fields = struct.unpack_from(fmt, blob, tls_offset)
    address_of_callbacks = fields[3]
    callbacks = []
    if address_of_callbacks:
        callbacks_rva = int(address_of_callbacks - image_base)
        cb_offset = rva_to_offset(callbacks_rva)
        if cb_offset is not None:
            fmt_ptr = "<Q" if pointer_size == 8 else "<I"
            size_ptr = struct.calcsize(fmt_ptr)
            while cb_offset + size_ptr <= len(blob):
                callback_va = struct.unpack_from(fmt_ptr, blob, cb_offset)[0]
                cb_offset += size_ptr
                if callback_va == 0:
                    break
                callbacks.append(hex(callback_va))
    return {
        "present": True,
        "callbacks": callbacks,
        "callback_count": len(callbacks),
    }

def extract_rich_header(blob: bytes):
    try:
        pe_offset = struct.unpack_from("<I", blob, 0x3C)[0]
    except struct.error:
        return {"present": False}
    rich_offset = blob.find(b"Rich", 0x80, pe_offset)
    if rich_offset == -1 or rich_offset + 8 > len(blob):
        return {"present": False}
    key = struct.unpack_from("<I", blob, rich_offset + 4)[0]
    cursor = rich_offset - 4
    start = None
    while cursor >= 0:
        value = struct.unpack_from("<I", blob, cursor)[0]
        if value ^ key == 0x536E6144:  # 'DanS'
            start = cursor
            break
        cursor -= 4
    if start is None:
        return {"present": False}
    decoded_entries = []
    decoded_bytes = bytearray()
    for entry_offset in range(start + 8, rich_offset, 4):
        raw_value = struct.unpack_from("<I", blob, entry_offset)[0]
        decoded = raw_value ^ key
        decoded_bytes.extend(struct.pack("<I", decoded))
        product_id = (decoded >> 16) & 0xFFFF
        build_id = decoded & 0xFFFF
        decoded_entries.append({
            "product_id": product_id,
            "build_id": build_id,
        })
    rich_hash = hashlib.sha256(decoded_bytes).hexdigest()
    return {
        "present": True,
        "hash": rich_hash,
        "entries": decoded_entries,
    }

import_descriptors = parse_import_descriptors(file_bytes)
imphash = compute_imphash(import_descriptors)
tls_info = parse_tls_callbacks(file_bytes)
rich_info = extract_rich_header(file_bytes)

version_info_strings = {}
fixed_file_info = {}
pdb_signatures = []

def guid_from_bytes(data: bytes) -> str:
    if len(data) != 16:
        return data.hex()
    d1, d2, d3 = struct.unpack("<IHH", data[:8])
    d4 = data[8:10]
    d5 = data[10:]
    return f"{d1:08x}-{d2:04x}-{d3:04x}-{d4.hex()}-{d5.hex()}"

if pefile is not None:
    try:
        pe = pefile.PE(data=file_bytes, fast_load=False)
        if getattr(pe, "FileInfo", None):
            for fileinfo in pe.FileInfo:
                key = getattr(fileinfo, "Key", b"")
                if isinstance(key, bytes):
                    key = key.decode("utf-8", errors="ignore")
                if key != "StringFileInfo":
                    continue
                for string_table in getattr(fileinfo, "StringTable", []):
                    for name, value in string_table.entries.items():
                        version_info_strings[name.decode("utf-8", errors="ignore")] = (
                            value.decode("utf-8", errors="ignore")
                        )
        vs_fixed = getattr(pe, "VS_FIXEDFILEINFO", None)
        if vs_fixed:
            fixed_file_info = {
                "file_version": f"{vs_fixed.FileVersionMS >> 16}.{vs_fixed.FileVersionMS & 0xFFFF}."
                f"{vs_fixed.FileVersionLS >> 16}.{vs_fixed.FileVersionLS & 0xFFFF}",
                "product_version": f"{vs_fixed.ProductVersionMS >> 16}.{vs_fixed.ProductVersionMS & 0xFFFF}."
                f"{vs_fixed.ProductVersionLS >> 16}.{vs_fixed.ProductVersionLS & 0xFFFF}",
                "file_flags": vs_fixed.FileFlags,
                "os": vs_fixed.FileOS,
                "file_type": vs_fixed.FileType,
            }
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            raw_data = pe.__data__
            for entry in pe.DIRECTORY_ENTRY_DEBUG:
                if entry.struct.Type != 2:  # IMAGE_DEBUG_TYPE_CODEVIEW
                    continue
                pointer = entry.struct.PointerToRawData
                size = entry.struct.SizeOfData
                if pointer == 0 or size == 0:
                    continue
                blob = raw_data[pointer : pointer + size]
                if len(blob) < 24 or blob[:4] not in (b"RSDS", b"NB10"):
                    continue
                if blob[:4] == b"RSDS":
                    guid = guid_from_bytes(blob[4:20])
                    age = struct.unpack_from("<I", blob, 20)[0]
                    path = blob[24:].split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
                else:  # NB10
                    timestamp, age = struct.unpack_from("<II", blob, 4)
                    guid = f"{timestamp:08x}"
                    path = blob[12:].split(b"\x00", 1)[0].decode("utf-8", errors="ignore")
                pdb_signatures.append({
                    "path": path,
                    "guid": guid,
                    "age": age,
                    "format": blob[:4].decode("ascii", errors="ignore"),
                })
    except Exception as exc:  # pragma: no cover - defensive
        analysis.setdefault("errors", []).append(f"pefile_parse_error:{exc}")
elif pefile is None:
    analysis.setdefault("warnings", []).append("pefile_not_installed")

analysis["advanced_imports"] = import_descriptors
hashes_section = analysis.setdefault("hashes", {})
if imphash:
    hashes_section["imphash"] = imphash
analysis["rich_header"] = rich_info
if tls_info:
    analysis["tls"] = tls_info
if rich_info.get("hash"):
    hashes_section["richhash"] = rich_info.get("hash")
if version_info_strings:
    analysis["version_info"] = version_info_strings
if fixed_file_info:
    analysis["version_fixed"] = fixed_file_info
if pdb_signatures:
    analysis["debug_directory"] = {"codeview": pdb_signatures}

imports = analysis["rizin"].get("imports") or []
exports = analysis["rizin"].get("exports") or []
strings = analysis["rizin"].get("strings") or []
sections_rizin = analysis["rizin"].get("sections") or []

if isinstance(imports, dict) and "imports" in imports:
    imports = imports.get("imports")
if isinstance(exports, dict) and "exports" in exports:
    exports = exports.get("exports")

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
if isinstance(strings, list):
    for entry in strings:
        if isinstance(entry, dict):
            value = entry.get("string")
        else:
            value = str(entry)
        if value:
            extracted_strings.append(value)

url_pattern = re.compile(r"https?://[\w\.-/:?=&%]+", re.IGNORECASE)
ipv4_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
registry_pattern = re.compile(r"HKEY_[A-Z_\\\\]+[\w\\\\/]+", re.IGNORECASE)
email_pattern = re.compile(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", re.IGNORECASE)

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

packed_sections = [
    section
    for section in pe_metadata.get("sections", [])
    if isinstance(section.get("entropy"), (int, float)) and section["entropy"] >= 7.2
]

rw_sections = [
    section.get("name")
    for section in pe_metadata.get("sections", [])
    if section.get("executable") and section.get("writable")
]

data_directory_anomalies = []
for entry in pe_metadata.get("data_directories", []) or []:
    rva = entry.get("rva") or 0
    size_entry = entry.get("size") or 0
    if (rva == 0 and size_entry != 0) or (rva != 0 and size_entry == 0):
        data_directory_anomalies.append({"name": entry.get("name"), "rva": rva, "size": size_entry})

if data_directory_anomalies:
    analysis.setdefault("anomalies", {})["data_directories"] = data_directory_anomalies

heuristics = {
    "score": 0,
    "threshold": threshold,
    "reasons": [],
    "flags": {
        "packed_sections": [section.get("name") for section in packed_sections],
        "data_directory_anomalies": [entry.get("name") for entry in data_directory_anomalies],
        "tls_callbacks": analysis.get("tls", {}).get("callbacks", []),
        "missing_import_table": not bool(import_descriptors),
        "rwx_sections": rw_sections,
        "version_info_present": bool(version_info_strings),
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

if analysis.get("tls", {}).get("callback_count", 0) > 0:
    add_reason("TLS callbacks present", 15)

if pe_metadata.get("is_pe") and not import_descriptors:
    add_reason("Import table missing or empty", 20)

if data_directory_anomalies:
    add_reason("Inconsistent PE data directory entries", 10)

if rw_sections:
    add_reason("Writable + executable sections detected", 15)

if pe_metadata.get("is_pe") and not version_info_strings:
    add_reason("Version info resource absent", 5)

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
  if collect_static_metadata "${SAMPLE_ABS}" "${RIZIN_CMD}" "${static_metadata_file}" "${MAX_DLL_EXPORTS}" "${SUSPICION_THRESHOLD}"; then
    static_metadata="$(<"${static_metadata_file}")"
    heuristics_suspect="$(jq -r '(.heuristics.suggested_suspect // false) | tostring' "${static_metadata_file}" 2>/dev/null || echo false)"
    heuristics_score="$(jq -r '(.heuristics.score // 0) | tostring' "${static_metadata_file}" 2>/dev/null || echo 0)"
  else
    log "Static metadata collection failed"
  fi
else
  log "Rizin not found in PATH"
fi

if [[ -n "${ssdeep_hash}" && -f "${static_metadata_file}" ]]; then
  if updated_metadata=$(jq --arg hash "${ssdeep_hash}" '.hashes = (.hashes // {}) | .hashes.ssdeep = $hash' "${static_metadata_file}" 2>/dev/null); then
    static_metadata="${updated_metadata}"
    printf '%s' "${static_metadata}" > "${static_metadata_file}"
  fi
fi

yara_matches=()
yara_json='[]'
yara_metrics_json='{}'
yara_family_breakdown_json='{"counts":{},"matches":{}}'
noisy_rules_json='[]'
yara_inventory_json='{}'

if [[ ${#UNIQUE_YARA_INDEXES[@]} -gt 0 ]]; then
  if yara_inventory_json=$(python3 - "${YARA_RULE_DIR_ABS}" "${UNIQUE_YARA_INDEXES[@]}" <<'PY'
import json
import re
import sys
from pathlib import Path

rule_dir_arg = sys.argv[1] if len(sys.argv) > 1 else ""
rule_dir = Path(rule_dir_arg).resolve() if rule_dir_arg else None
indexes = [Path(p).resolve() for p in sys.argv[2:]]

include_re = re.compile(r'^\s*include\s+"([^"]+)"')
rule_re = re.compile(r'^\s*(?:private\s+)?rule\s+([A-Za-z0-9_]+)')

seen = set()
files = set()
missing = set()
rule_count = 0
index_summaries = []

def resolve_include(base_path: Path, include_target: str) -> Path:
    candidate = Path(include_target)
    if not candidate.is_absolute():
        candidate = (base_path / candidate).resolve()
    else:
        candidate = candidate.resolve()
    return candidate

def walk(path: Path):
    global rule_count
    if path in seen:
        return
    seen.add(path)
    if not path.exists():
        missing.add(str(path))
        return
    files.add(str(path))
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        lines = []
    for line in lines:
        match = include_re.match(line)
        if match:
            target = resolve_include(path.parent, match.group(1))
            walk(target)
        elif rule_re.match(line):
            rule_count += 1

for index_path in indexes:
    before = rule_count
    walk(index_path)
    added = rule_count - before
    relative = None
    if rule_dir is not None:
        try:
            relative = str(index_path.relative_to(rule_dir))
        except ValueError:
            relative = None
    index_summaries.append({
        "path": str(index_path),
        "relative": relative,
        "rules": added
    })

print(json.dumps({
    "rule_files": sorted(files),
    "missing": sorted(missing),
    "rule_count": rule_count,
    "index_summaries": index_summaries
}))
PY
  ); then
    :
  else
    log "Failed to enumerate YARA inventory"
    yara_inventory_json='{}'
  fi
fi

yara_total_rules=$(jq -r '(.rule_count // 0)' <<<"${yara_inventory_json}" 2>/dev/null || echo 0)
yara_index_summaries=$(jq -c '(.index_summaries // [])' <<<"${yara_inventory_json}" 2>/dev/null || echo '[]')
yara_rule_files=$(jq -c '(.rule_files // [])' <<<"${yara_inventory_json}" 2>/dev/null || echo '[]')
yara_missing_files=$(jq -c '(.missing // [])' <<<"${yara_inventory_json}" 2>/dev/null || echo '[]')

noisy_rules_file=""
if [[ -n "${YARA_RULE_DIR_ABS}" ]]; then
  noisy_rules_file="${YARA_RULE_DIR_ABS}/internal/noisy_rules.txt"
fi
declare -A NOISY_RULE_SET=()
if [[ -n "${noisy_rules_file}" && -f "${noisy_rules_file}" ]]; then
  while IFS= read -r noisy_rule; do
    [[ -z "${noisy_rule}" ]] && continue
    NOISY_RULE_SET["${noisy_rule}"]=1
  done < <(python3 - "${noisy_rules_file}" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
    line = line.split('#', 1)[0].strip()
    if line:
        print(line)
PY
  )
fi

declare -A YARA_MATCH_SET=()
declare -A FAMILY_MATCH_COUNT=()
declare -A NOISY_MATCH_SEEN=()
declare -a noisy_hits=()
yara_matches_file="${TMPDIR}/yara-matches.txt"
>"${yara_matches_file}"

if command -v yara >/dev/null 2>&1 && [[ ${#UNIQUE_YARA_INDEXES[@]} -gt 0 ]]; then
  for index_path in "${UNIQUE_YARA_INDEXES[@]}"; do
    if [[ ! -f "${index_path}" ]]; then
      continue
    fi

    family_label="custom"
    if [[ -n "${YARA_RULE_DIR_ABS}" ]]; then
      rel="$(rel_path "${index_path}" "${YARA_RULE_DIR_ABS}")"
      rel_base="${rel%/index.yar}"
      if [[ -z "${rel_base}" || "${rel}" == "index.yar" ]]; then
        family_label="root"
      else
        family_label="${rel_base}"
      fi
    fi

    err_file="${TMPDIR}/yara-${RANDOM}.err"
    set +e
    yara_stdout="$(yara --fail-on-warnings -w -g -m "${index_path}" "${SAMPLE_ABS}" 2>"${err_file}")"
    yara_rc=$?
    set -e

    if [[ ${yara_rc} -gt 1 ]]; then
      log "YARA execution failed for ${index_path}"
      continue
    fi

    if [[ -s "${err_file}" ]]; then
      log "YARA warnings emitted for ${index_path}"
      while IFS= read -r warning_line; do
        log "  ${warning_line}"
      done <"${err_file}"
    fi

    while IFS= read -r rule_name; do
      [[ -z "${rule_name}" ]] && continue
      if [[ -z "${YARA_MATCH_SET[${rule_name}]+x}" ]]; then
        yara_matches+=("${rule_name}")
        YARA_MATCH_SET["${rule_name}"]=1
      fi
      current_count=${FAMILY_MATCH_COUNT["${family_label}"]:-0}
      FAMILY_MATCH_COUNT["${family_label}"]=$(( current_count + 1 ))
      printf '%s %s\n' "${family_label}" "${rule_name}" >>"${yara_matches_file}"
      if [[ -n "${NOISY_RULE_SET[${rule_name}]+x}" && -z "${NOISY_MATCH_SEEN[${rule_name}]+x}" ]]; then
        noisy_hits+=("${rule_name}")
        NOISY_MATCH_SEEN["${rule_name}"]=1
      fi
    done < <(printf '%s\n' "${yara_stdout}" | awk '{print $1}')
  done
fi

if [[ ${#yara_matches[@]} -gt 0 ]]; then
  yara_json=$(printf '%s\n' "${yara_matches[@]}" | jq -Rcs 'split("\n") | map(select(length>0))')
fi

if [[ -s "${yara_matches_file}" ]]; then
  yara_family_breakdown_json=$(python3 - "${yara_matches_file}" <<'PY'
import json
import sys
from collections import OrderedDict

counts = OrderedDict()
matches = {}
with open(sys.argv[1], 'r', encoding='utf-8') as handle:
    for line in handle:
        line = line.strip()
        if not line:
            continue
        try:
            family, rule = line.split(' ', 1)
        except ValueError:
            continue
        counts[family] = counts.get(family, 0) + 1
        matches.setdefault(family, []).append(rule)

print(json.dumps({"counts": counts, "matches": matches}))
PY
  )
fi

noisy_rules_json='[]'
if [[ ${#noisy_hits[@]} -gt 0 ]]; then
  noisy_rules_json=$(printf '%s\n' "${noisy_hits[@]}" | jq -Rcs 'split("\n") | map(select(length>0))')
  noisy_log_path="$(dirname "${OUTPUT_JSON}")/triage-noisy.log"
  while IFS= read -r noisy_entry; do
    [[ -z "${noisy_entry}" ]] && continue
    printf '%s %s %s\n' "$(date --iso-8601=seconds)" "${SAMPLE_NAME}" "${noisy_entry}" >>"${noisy_log_path}"
  done <<<"$(printf '%s\n' "${noisy_hits[@]}")"
fi

yara_metrics_json=$(jq -n \
  --argjson total_rules "${yara_total_rules}" \
  --argjson indexes "${yara_index_summaries}" \
  --argjson rule_files "${yara_rule_files}" \
  --argjson missing "${yara_missing_files}" \
  '{total_rules:$total_rules, indexes:$indexes, rule_files:$rule_files, missing:$missing}')

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
  "yara_metrics": ${yara_metrics_json},
  "yara_families": ${yara_family_breakdown_json},
  "yara_noisy_rules": ${noisy_rules_json},
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
