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

rizin_info=""
if command -v "${RIZIN_CMD}" >/dev/null 2>&1; then
  rizin_info="$(${RIZIN_CMD} -q -c 'iIj' "${SAMPLE_ABS}" 2>/dev/null || true)"
else
  log "Rizin not found in PATH"
fi

yara_matches=()
if command -v yara >/dev/null 2>&1 && [[ -d "${YARA_RULE_DIR}" ]]; then
  mapfile -t yara_matches < <(yara -w -g -m "${YARA_RULE_DIR}" "${SAMPLE_ABS}" 2>/dev/null | awk '{print $1}')
fi

suspected=false
if [[ ${#yara_matches[@]} -gt 0 ]]; then
  suspected=true
fi
if [[ "${pesieve_status}" == "error" ]]; then
  suspected=true
fi
if [[ $(python3 - <<'PY' "$entropy"
import sys
print('true' if float(sys.argv[1]) > 7.0 else 'false')
PY
) == 'true' ]]; then
  suspected=true
fi

if [[ ${#yara_matches[@]} -gt 0 ]]; then
  yara_json=$(printf '%s\n' "${yara_matches[@]}" | jq -Rcs 'split("\n") | map(select(length>0))')
else
  yara_json='[]'
fi

debug_log=""
if [[ ${DEBUG} -eq 1 ]]; then
  debug_log="$(cat <<DBG
pesieve_stdout:\n${pesieve_stdout}\n---\nrizin_info:\n${rizin_info}
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
  "rizin_info": $(jq -Rs '.' <<<"${rizin_info}"),
  "suspected": ${suspected},
  "triage_timestamp": "$(date --iso-8601=seconds)",
  "tool_metadata": {
    "triage_version": "1.0.0",
    "timeout_seconds": ${TIMEOUT_SECONDS},
    "operator": "${USER:-unknown}"
  },
  "debug": $(jq -Rs '.' <<<"${debug_log}")
}
JSON

log "Triage report written to ${OUTPUT_JSON}"
