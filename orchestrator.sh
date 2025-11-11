#!/usr/bin/env bash
set -euo pipefail

# ================= Configurable parameters =================
BASE_IMAGE_PATH="${BASE_IMAGE_PATH:-/var/lib/libvirt/images/windows10-base.qcow2}"
BRIDGE_NAME="${BRIDGE_NAME:-br-sandbox}"
SAMPLE_DIR="${SAMPLE_DIR:-./samples}"
OUTPUT_DIR="${OUTPUT_DIR:-./out}"
VM_MEM="${VM_MEM:-4096}"
VM_CPUS="${VM_CPUS:-2}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-120}"
INETSIM_IMAGE="${INETSIM_IMAGE:-opennic/inetsim}"
TRIAGE_IMAGE="${TRIAGE_IMAGE:-sandbox-triage}"
TCPDUMP_ROTATE_SIZE_MB="${TCPDUMP_ROTATE_SIZE_MB:-50}"
TCPDUMP_FILES="${TCPDUMP_FILES:-3}"
FORCE_NONROOT="${FORCE_NONROOT:-1}"
VM_USER="${VM_USER:-analyst}"
VM_PASSWORD="${VM_PASSWORD:-P@ssw0rd!}"
WINRM_PORT="${WINRM_PORT:-5985}"
SMB_SHARE="${SMB_SHARE:-C$}"
SMB_UPLOAD_DIR="${SMB_UPLOAD_DIR:-Sandbox\\Samples}"
RESULTS_DIR_GUEST="${RESULTS_DIR_GUEST:-C:\\results}"
AUTORUN_PATH="${AUTORUN_PATH:-C:\\autorun\\autorun.ps1}"
TCPDUMP_PRIV_CMD="${TCPDUMP_PRIV_CMD:-sudo -n}"
VIRT_DRIVER="${VIRT_DRIVER:-virsh}"
QEMU_URI="${QEMU_URI:-qemu:///system}"
CLONE_WORKDIR="${CLONE_WORKDIR:-$(dirname "${BASE_IMAGE_PATH}")}"
DRY_RUN=0
DEBUG=0
RUN_TRIAGE=1
COLLECT_MEMORY=0
KEEP_CLONE=0
PURGE_ARTIFACTS=0
ALLOW_ROOT=0
REPORT_SIGNING_KEY_FILE="${REPORT_SIGNING_KEY_FILE:-}"
REPORT_SIGNING_KEY_PASSPHRASE="${REPORT_SIGNING_KEY_PASSPHRASE:-}"

declare -a COMMAND_LOG_BUFFER=()
HOST_COMMAND_LOG=""

# ================= Utility functions =================
log() { echo "[orchestrator] $*" >&2; }
err() { echo "[orchestrator][error] $*" >&2; }
die() { err "$*"; exit 1; }

require_cmd() {
  local missing=()
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
    fi
  done
  if ((${#missing[@]})); then
    die "Missing required commands: ${missing[*]}"
  fi
}

command_to_string() {
  local -a parts=("$@")
  local formatted=""
  local arg
  for arg in "${parts[@]}"; do
    if [[ -z "${formatted}" ]]; then
      formatted="$(printf '%q' "${arg}")"
    else
      formatted+=" $(printf '%q' "${arg}")"
    fi
  done
  printf '%s' "${formatted}"
}

record_command() {
  local start_ts="$1"
  local end_ts="$2"
  local rc="$3"
  local cmd_str="$4"
  local note="${5:-}"
  local entry
  entry=$(jq -cn \
    --arg start "${start_ts}" \
    --arg end "${end_ts}" \
    --arg rc "${rc}" \
    --arg cmd "${cmd_str}" \
    --arg note "${note}" \
    '{start:$start,end:$end,return_code:($rc|tonumber),command:$cmd} + (if ($note|length) == 0 then {} else {note:$note} end)')
  if [[ -n "${HOST_COMMAND_LOG}" ]]; then
    printf '%s\n' "${entry}" >> "${HOST_COMMAND_LOG}"
  else
    COMMAND_LOG_BUFFER+=("${entry}")
  fi
}

flush_command_buffer() {
  if [[ -n "${HOST_COMMAND_LOG}" && ${#COMMAND_LOG_BUFFER[@]} -gt 0 ]]; then
    printf '%s\n' "${COMMAND_LOG_BUFFER[@]}" >> "${HOST_COMMAND_LOG}"
    COMMAND_LOG_BUFFER=()
  fi
}

run_cmd() {
  local -a cmd=("$@")
  if [[ ${#cmd[@]} -eq 0 ]]; then
    return 0
  fi
  local start_ts end_ts rc note=""
  start_ts="$(date --iso-8601=seconds)"
  local cmd_str
  cmd_str="$(command_to_string "${cmd[@]}")"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "[dry-run] ${cmd_str}"
    end_ts="${start_ts}"
    record_command "${start_ts}" "${end_ts}" 0 "${cmd_str}" "dry-run"
    return 0
  fi
  if [[ $DEBUG -eq 1 ]]; then
    log "[exec] ${cmd_str}"
  fi
  "${cmd[@]}"
  rc=$?
  end_ts="$(date --iso-8601=seconds)"
  record_command "${start_ts}" "${end_ts}" "${rc}" "${cmd_str}" "${note}"
  if [[ $rc -ne 0 ]]; then
    err "Command failed (rc=${rc}): ${cmd_str}"
  fi
  return $rc
}

cleanup() {
  local exit_code=$?
  if [[ -n "${TCPDUMP_PID:-}" ]]; then
    if kill -0 "${TCPDUMP_PID}" 2>/dev/null; then
      log "Stopping tcpdump (PID ${TCPDUMP_PID})"
      kill "${TCPDUMP_PID}" || true
      wait "${TCPDUMP_PID}" || true
    fi
  fi
  if [[ -n "${VM_NAME:-}" ]]; then
    if virsh --connect "${QEMU_URI}" dominfo "${VM_NAME}" >/dev/null 2>&1; then
      log "Forcing shutdown of ${VM_NAME}"
      virsh --connect "${QEMU_URI}" shutdown "${VM_NAME}" >/dev/null 2>&1 || true
      sleep 5
      virsh --connect "${QEMU_URI}" destroy "${VM_NAME}" >/dev/null 2>&1 || true
      virsh --connect "${QEMU_URI}" undefine "${VM_NAME}" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "${CLONE_PATH:-}" && $KEEP_CLONE -eq 0 ]]; then
    if [[ -f "${CLONE_PATH}" ]]; then
      log "Removing clone ${CLONE_PATH}"
      rm -f "${CLONE_PATH}"
    fi
  fi
  if [[ $exit_code -ne 0 && ${PURGE_ARTIFACTS} -eq 1 && -d "${RUN_DIR:-}" ]]; then
    log "Purging run directory ${RUN_DIR} due to failure"
    rm -rf "${RUN_DIR}"
  fi
  if [[ $exit_code -ne 0 ]]; then
    err "Exiting with code ${exit_code}"
  fi
  exit $exit_code
}

trap cleanup EXIT INT TERM

print_usage() {
  cat <<'USAGE'
Usage: ./orchestrator.sh --sample <path> [options]

Options:
  --no-triage           Skip triage prerequisite checks
  --collect-memory      Force memory dump collection (default off)
  --keep-clone          Keep QCOW2 clone after run (default remove)
  --purge               Remove generated artifacts on failure (dangerous)
  --dry-run             Show commands without executing
  --debug               Verbose logging
  --allow-root          Allow running as root (default refuse)
USAGE
}

# ================= Argument parsing =================
SAMPLE_PATH=""

while (("$#")); do
  case "$1" in
    --sample)
      SAMPLE_PATH="$2"; shift 2 ;;
    --no-triage)
      RUN_TRIAGE=0; shift ;;
    --collect-memory)
      COLLECT_MEMORY=1; shift ;;
    --keep-clone)
      KEEP_CLONE=1; shift ;;
    --purge)
      PURGE_ARTIFACTS=1; shift ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    --debug)
      DEBUG=1; shift ;;
    --allow-root)
      ALLOW_ROOT=1; shift ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      die "Unknown argument: $1" ;;
  esac
done

if [[ -z "${SAMPLE_PATH}" ]]; then
  die "Missing required --sample argument"
fi

if [[ ! -f "${SAMPLE_PATH}" ]]; then
  die "Sample ${SAMPLE_PATH} not found"
fi

if [[ ${FORCE_NONROOT} == "1" && ${ALLOW_ROOT} -eq 0 && $(id -u) -eq 0 ]]; then
  die "Refusing to run as root. Re-run with --allow-root if absolutely necessary."
fi

if [[ ! -f "${BASE_IMAGE_PATH}" ]]; then
  die "Base image ${BASE_IMAGE_PATH} not found"
fi

if command -v lsof >/dev/null 2>&1; then
  if lsof "${BASE_IMAGE_PATH}" >/dev/null 2>&1; then
    die "Base image appears to be in use. Refusing to continue."
  fi
else
  log "lsof not available; skipping in-use check"
fi

require_cmd qemu-img virsh virt-install virt-copy-in virt-copy-out sha256sum jq date tcpdump smbclient python3

TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RUN_ID="sandbox-${TIMESTAMP}"
VM_NAME="${RUN_ID}"
CLONE_PATH="${CLONE_WORKDIR}/${RUN_ID}.qcow2"
RUN_DIR="${OUTPUT_DIR}/${TIMESTAMP}"
mkdir -p "${RUN_DIR}"
HOST_COMMAND_LOG="${RUN_DIR}/host-commands.log"
: > "${HOST_COMMAND_LOG}"
flush_command_buffer

SAMPLE_ABS="$(realpath "${SAMPLE_PATH}")"
SAMPLE_NAME="$(basename "${SAMPLE_PATH}")"
TRIAGE_JSON="${SAMPLE_ABS}.triage.json"
FINAL_REPORT="${RUN_DIR}/final-report.json"
SAMPLE_SHA="$(sha256sum "${SAMPLE_ABS}" | awk '{print $1}')"
BASE_IMAGE_SHA="$(sha256sum "${BASE_IMAGE_PATH}" | awk '{print $1}')"
export RUN_DIR FINAL_REPORT SAMPLE_ABS SAMPLE_NAME TRIAGE_JSON BASE_IMAGE_PATH TIMEOUT_SECONDS COLLECT_MEMORY SAMPLE_SHA BASE_IMAGE_SHA
export REPORT_SIGNING_KEY_FILE REPORT_SIGNING_KEY_PASSPHRASE SAMPLE_KIND HEURISTICS_SCORE

if [[ $RUN_TRIAGE -eq 1 && ! -f "${TRIAGE_JSON}" ]]; then
  err "Triage JSON ${TRIAGE_JSON} not found. Run triage.sh first or use --no-triage."
  exit 1
fi

TRIAGE_STATIC_JSON='{}'
PE_METADATA_JSON='{}'
DLL_ANALYSIS_JSON='{}'
HEURISTICS_JSON='{}'
HEURISTICS_SCORE=0
SAMPLE_KIND="exe"
declare -a DLL_EXPORTS=()
if [[ -f "${TRIAGE_JSON}" ]]; then
  TRIAGE_STATIC_JSON="$(jq -c '.static_analysis // {}' "${TRIAGE_JSON}" 2>/dev/null || echo '{}')"
  PE_METADATA_JSON="$(jq -c '.pe_metadata // {}' "${TRIAGE_JSON}" 2>/dev/null || echo '{}')"
  DLL_ANALYSIS_JSON="$(jq -c '.dll_analysis // {}' "${TRIAGE_JSON}" 2>/dev/null || echo '{}')"
  HEURISTICS_JSON="$(jq -c '.heuristics // {}' "${TRIAGE_JSON}" 2>/dev/null || echo '{}')"
  if [[ "$(jq -r '(.is_dll // false) | tostring' <<<"${PE_METADATA_JSON}")" == "true" ]]; then
    SAMPLE_KIND="dll"
  fi
  mapfile -t DLL_EXPORTS < <(jq -r '.suggested_exports[]?' <<<"${DLL_ANALYSIS_JSON}" 2>/dev/null || true)
  if [[ ${COLLECT_MEMORY} -eq 0 ]]; then
    HEURISTICS_SCORE=$(jq -r '(.score // 0)' <<<"${HEURISTICS_JSON}" 2>/dev/null || echo 0)
    if [[ "${HEURISTICS_SCORE}" =~ ^[0-9]+$ ]] && (( HEURISTICS_SCORE >= 70 )); then
      log "Heuristic score ${HEURISTICS_SCORE} >= 70, enabling memory collection"
      COLLECT_MEMORY=1
    fi
  else
    HEURISTICS_SCORE=$(jq -r '(.score // 0)' <<<"${HEURISTICS_JSON}" 2>/dev/null || echo 0)
  fi
else
  HEURISTICS_SCORE=0
fi

log "Creating clone ${CLONE_PATH}"
run_cmd qemu-img create -f qcow2 -F qcow2 -b "${BASE_IMAGE_PATH}" "${CLONE_PATH}"

log "Injecting sample into offline image"
run_cmd virt-copy-in -a "${CLONE_PATH}" "${SAMPLE_ABS}" "C:\\sandbox"

log "Copying autorun script"
run_cmd virt-copy-in -a "${CLONE_PATH}" autorun.ps1 "C:\\autorun"

start_vm() {
  local -a cmd=(
    virt-install
    --name "${VM_NAME}"
    --memory "${VM_MEM}"
    --vcpus "${VM_CPUS}"
    --import
    --disk "path=${CLONE_PATH},format=qcow2"
    --network "bridge=${BRIDGE_NAME},model=virtio"
    --os-variant win10
    --graphics none
    --noautoconsole
    --check path_in_use=off
    --wait 0
  )
  run_cmd "${cmd[@]}"
}

wait_for_ip() {
  local attempts=0
  local max_attempts=60
  local addr=""
  while (( attempts < max_attempts )); do
    if [[ $DRY_RUN -eq 1 ]]; then
      echo "0.0.0.0"
      return 0
    fi
    addr=$(virsh --connect "${QEMU_URI}" domifaddr "${VM_NAME}" --source agent 2>/dev/null | awk '/ipv4/ {print $4}' | cut -d'/' -f1)
    if [[ -n "$addr" ]]; then
      echo "$addr"
      return 0
    fi
    sleep 5
    ((attempts++))
  done
  return 1
}

log "Starting VM ${VM_NAME}"
start_vm

log "Waiting for guest IP via qemu-guest-agent"
GUEST_IP="$(wait_for_ip)" || die "Failed to obtain guest IP via qemu-guest-agent. Ensure guest agent is running."
log "Guest IP: ${GUEST_IP}"

start_tcpdump() {
  local pcap_prefix="${RUN_DIR}/${RUN_ID}"
  local -a tcpdump_args=(-i "${BRIDGE_NAME}" -w "${pcap_prefix}-%Y%m%d%H%M%S.pcap" -C "${TCPDUMP_ROTATE_SIZE_MB}" -W "${TCPDUMP_FILES}" -n)
  local -a wrapper=()
  if [[ -n "${TCPDUMP_PRIV_CMD}" ]]; then
    # shellcheck disable=SC2206
    wrapper=( ${TCPDUMP_PRIV_CMD} )
  fi
  local cmd_str
  if [[ ${#wrapper[@]} -gt 0 ]]; then
    cmd_str="$(command_to_string "${wrapper[@]}" tcpdump "${tcpdump_args[@]}")"
  else
    cmd_str="$(command_to_string tcpdump "${tcpdump_args[@]}")"
  fi
  local start_ts="$(date --iso-8601=seconds)"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "[dry-run] ${cmd_str}"
    record_command "${start_ts}" "${start_ts}" 0 "${cmd_str}" "dry-run-background"
    return 0
  fi
  if [[ $DEBUG -eq 1 ]]; then
    log "Starting tcpdump: ${cmd_str}"
  fi
  if [[ ${#wrapper[@]} -gt 0 ]]; then
    "${wrapper[@]}" tcpdump "${tcpdump_args[@]}" &
  else
    tcpdump "${tcpdump_args[@]}" &
  fi
  TCPDUMP_PID=$!
  record_command "${start_ts}" "${start_ts}" 0 "${cmd_str}" "background-start"
  log "tcpdump PID ${TCPDUMP_PID}"
}

start_tcpdump

log "Uploading sample via SMB to ${SMB_UPLOAD_DIR}"
upload_share="//${GUEST_IP}/${SMB_SHARE}"
mkdir_cmd="mkdir ${SMB_UPLOAD_DIR}"
run_cmd smbclient "${upload_share}" "${VM_PASSWORD}" -U "${VM_USER}%${VM_PASSWORD}" -c "${mkdir_cmd}" || true
remote_sample_path="${SMB_UPLOAD_DIR}\\${SAMPLE_NAME}"
printf -v put_cmd 'put "%s" "%s"' "${SAMPLE_ABS}" "${remote_sample_path}"
run_cmd smbclient "${upload_share}" "${VM_PASSWORD}" -U "${VM_USER}%${VM_PASSWORD}" -c "${put_cmd}"

trigger_execution() {
  python3 - "$@" <<'PY'
import json
import os
import sys
import time
from datetime import datetime

sample_path = sys.argv[1]
autorun = sys.argv[2]
user = sys.argv[3]
password = sys.argv[4]
addr = sys.argv[5]
port = int(sys.argv[6])
timeout = int(sys.argv[7])
collect_flag = sys.argv[8].lower() in {'1', 'true', 'yes'}
sample_kind = sys.argv[9] if len(sys.argv) > 9 else 'exe'
exports_csv = sys.argv[10] if len(sys.argv) > 10 else ''
heuristic_score = sys.argv[11] if len(sys.argv) > 11 else ''
dll_exports = [item for item in exports_csv.split(',') if item]

try:
    import winrm
except ImportError:
    print("pywinrm not installed; cannot trigger execution", file=sys.stderr)
    sys.exit(1)

session = winrm.Session(f'http://{addr}:{port}/wsman', auth=(user, password))
args = ['-ExecutionPolicy', 'Bypass', '-File', autorun, '-SamplePath', sample_path, '-TimeoutSeconds', str(timeout)]
if collect_flag:
    args.extend(['-CollectMemory', 'True'])
if sample_kind.lower() == 'dll':
    args.extend(['-IsDll', 'True'])
    if dll_exports:
        args.extend(['-DllExports', ','.join(dll_exports)])
if heuristic_score:
    args.extend(['-HeuristicScore', heuristic_score])
print(f"[orchestrator] Triggering autorun with args: {args}", file=sys.stderr)
result = session.run_cmd('powershell', args)
print(json.dumps({
    'status_code': result.status_code,
    'std_out': result.std_out.decode(errors='ignore'),
    'std_err': result.std_err.decode(errors='ignore'),
    'timestamp': datetime.utcnow().isoformat() + 'Z'
}))
PY
}

dll_exports_arg=""
if [[ ${#DLL_EXPORTS[@]} -gt 0 ]]; then
  dll_exports_arg="$(printf '%s,' "${DLL_EXPORTS[@]}")"
  dll_exports_arg="${dll_exports_arg%,}"
fi

if [[ $DRY_RUN -eq 1 ]]; then
  log "[dry-run] Would trigger WinRM execution"
else
  trigger_execution "C:\\${SMB_UPLOAD_DIR}\\${SAMPLE_NAME}" "${AUTORUN_PATH}" "${VM_USER}" "${VM_PASSWORD}" "${GUEST_IP}" "${WINRM_PORT}" "${TIMEOUT_SECONDS}" "${COLLECT_MEMORY}" "${SAMPLE_KIND}" "${dll_exports_arg}" "${HEURISTICS_SCORE}" > "${RUN_DIR}/winrm-exec.json"
fi

log "Sleeping for ${TIMEOUT_SECONDS}s to allow execution"
if [[ $DRY_RUN -eq 0 ]]; then
  sleep "${TIMEOUT_SECONDS}"
fi

log "Initiating graceful shutdown"
run_cmd virsh --connect "${QEMU_URI}" shutdown "${VM_NAME}"
if [[ $DRY_RUN -eq 0 ]]; then
  for _ in {1..12}; do
    if virsh --connect "${QEMU_URI}" domstate "${VM_NAME}" 2>/dev/null | grep -q "shut"; then
      break
    fi
    sleep 5
  done
fi

if [[ $DRY_RUN -eq 0 ]]; then
  virsh --connect "${QEMU_URI}" destroy "${VM_NAME}" >/dev/null 2>&1 || true
  virsh --connect "${QEMU_URI}" undefine "${VM_NAME}" >/dev/null 2>&1 || true
fi
VM_NAME=""

if [[ -n "${TCPDUMP_PID:-}" && $DRY_RUN -eq 0 ]]; then
  log "Stopping tcpdump"
  kill "${TCPDUMP_PID}" >/dev/null 2>&1 || true
  wait "${TCPDUMP_PID}" 2>/dev/null || true
  record_command "$(date --iso-8601=seconds)" "$(date --iso-8601=seconds)" 0 "kill ${TCPDUMP_PID}" "background-stop"
  TCPDUMP_PID=""
fi

log "Collecting guest artifacts"
run_cmd virt-copy-out -a "${CLONE_PATH}" "${RESULTS_DIR_GUEST}" "${RUN_DIR}"

log "Hashing artifacts"
ARTIFACTS_JSON="${RUN_DIR}/artifacts.json"
export ARTIFACTS_JSON
python3 - <<'PY'
import hashlib
import json
import os
from pathlib import Path

run_dir = Path(os.environ['RUN_DIR'])
artifacts = {}
for path in run_dir.rglob('*'):
    if path.is_file():
        h = hashlib.sha256()
        h.update(path.read_bytes())
        artifacts[str(path.relative_to(run_dir))] = {
            'sha256': h.hexdigest(),
            'size': path.stat().st_size
        }
print(json.dumps(artifacts, indent=2))
PY > "${ARTIFACTS_JSON}"

log "Assembling final-report.json"
python3 - <<'PY'
import csv
import hashlib
import hmac
import json
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


def read_json(path: Path):
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


run_dir = Path(os.environ['RUN_DIR'])
report_path = Path(os.environ['FINAL_REPORT'])
artifacts_path = Path(os.environ['ARTIFACTS_JSON'])
sample_path = Path(os.environ['SAMPLE_ABS'])
sample_sha = os.environ['SAMPLE_SHA']
triage_path = Path(os.environ.get('TRIAGE_JSON', ''))
base_image = os.environ['BASE_IMAGE_PATH']
base_sha = os.environ['BASE_IMAGE_SHA']
collect_memory = os.environ['COLLECT_MEMORY'] == '1'
timeout = int(os.environ['TIMEOUT_SECONDS'])
sample_kind = os.environ.get('SAMPLE_KIND', 'exe')
heuristics_score = int(os.environ.get('HEURISTICS_SCORE', '0') or 0)

results_dir = None
for candidate in ('results', 'Results', 'RESULTS'):
    candidate_path = run_dir / candidate
    if candidate_path.exists() and candidate_path.is_dir():
        results_dir = candidate_path
        break
if results_dir is None:
    results_dir = run_dir

artifacts_map = json.loads(artifacts_path.read_text())
attachments = [
    {'path': rel_path, **meta}
    for rel_path, meta in sorted(artifacts_map.items())
]

triage = read_json(triage_path) if triage_path.is_file() else {}

winrm_file = run_dir / 'winrm-exec.json'
winrm_data = read_json(winrm_file) if winrm_file.exists() else {}

autorun_summary_file = results_dir / 'autorun-summary.json'
autorun_summary = read_json(autorun_summary_file) if autorun_summary_file.exists() else {}

baseline = autorun_summary.get('baseline', {})
for name, key in (('baseline-pre.json', 'pre'), ('baseline-post.json', 'post'), ('baseline-diff.json', 'diff')):
    path = results_dir / name
    if path.exists() and key not in baseline:
        baseline[key] = read_json(path)


def collect_text_logs(prefix: str):
    logs = []
    for path in sorted(results_dir.glob(f'{prefix}*.log')):
        try:
            data = path.read_text(errors='ignore')
        except Exception:
            continue
        truncated = False
        preview = data
        if len(data) > 4000:
            preview = data[:4000]
            truncated = True
        logs.append({
            'file': str(path.relative_to(run_dir)),
            'preview': preview,
            'truncated': truncated,
        })
    return logs


stdout_streams = collect_text_logs('stdout')
stderr_streams = collect_text_logs('stderr')

module_snapshots = []
for path in sorted(results_dir.glob('modules-*.json')):
    module_snapshots.append({
        'file': str(path.relative_to(run_dir)),
        'data': read_json(path),
    })

memory_dumps = autorun_summary.get('memoryDumps', [])
if not memory_dumps:
    for attachment in attachments:
        if attachment['path'].lower().endswith(('.dmp', '.mdmp')):
            memory_dumps.append({'path': attachment['path'], 'sha256': attachment['sha256']})


def summarize_procmon(csv_path: Path):
    summary = {
        'file_writes': [],
        'registry': [],
        'network': [],
        'dns_queries': [],
    }
    if not csv_path.exists():
        return summary
    rows = None
    for encoding in ('utf-16', 'utf-8-sig', 'utf-8'):
        try:
            with csv_path.open('r', encoding=encoding, errors='ignore') as fh:
                reader = csv.DictReader(fh)
                rows = list(reader)
            if rows:
                break
        except Exception:
            continue
    if not rows:
        return summary

    file_counter = Counter()
    reg_counter = Counter()
    net_counter = Counter()
    dns_counter = Counter()
    remote_pattern = re.compile(r'Remote Address:\s*([^;\s]+)', re.IGNORECASE)
    dns_pattern = re.compile(r'QueryName=([^;\s]+)', re.IGNORECASE)

    for row in rows:
        operation = (row.get('Operation') or '').lower()
        path = row.get('Path') or ''
        detail = row.get('Detail') or ''
        if 'writefile' in operation:
            file_counter[path] += 1
        if operation.startswith('regset') or operation.startswith('regcreate') or 'regdelete' in operation:
            reg_counter[path] += 1
        if 'tcp' in operation or 'udp' in operation or 'dns' in operation:
            match = remote_pattern.search(detail)
            if match:
                net_counter[match.group(1)] += 1
            elif path:
                net_counter[path] += 1
            dns_match = dns_pattern.search(detail)
            if dns_match:
                dns_counter[dns_match.group(1).lower()] += 1

    summary['file_writes'] = [{'path': p, 'count': c} for p, c in file_counter.most_common(10)]
    summary['registry'] = [{'path': p, 'count': c} for p, c in reg_counter.most_common(10)]
    summary['network'] = [{'remote': p, 'count': c} for p, c in net_counter.most_common(10)]
    summary['dns_queries'] = [{'domain': d, 'count': c} for d, c in dns_counter.most_common(10)]
    return summary


telemetry = autorun_summary.get('telemetry', {})
procmon_csv = results_dir / 'procmon.csv'
if 'procmon_summary' not in telemetry:
    telemetry['procmon_summary'] = summarize_procmon(procmon_csv)

etw_dir = results_dir / 'etw'
if etw_dir.exists():
    telemetry.setdefault('etw_traces', [])
    for path in sorted(etw_dir.glob('*.etl')):
        telemetry['etw_traces'].append(str(path.relative_to(run_dir)))

executions = autorun_summary.get('executions', [])
process_tree = autorun_summary.get('processTree', [])
autorun_brief = autorun_summary.get('summary', {})

dynamic_verdict = autorun_summary.get('verdict') or 'needs-review'
if dynamic_verdict == 'needs-review':
    if triage.get('suspected') is True:
        dynamic_verdict = 'suspicious'
    elif triage.get('suspected') is False:
        dynamic_verdict = 'benign'

dynamic = {
    'timeout_seconds': timeout,
    'collect_memory': collect_memory,
    'verdict': dynamic_verdict,
    'winrm': winrm_data,
    'autorun': autorun_brief,
    'executions': executions,
    'process_tree': process_tree,
    'baseline': baseline,
    'telemetry': telemetry,
    'stdout_streams': stdout_streams,
    'stderr_streams': stderr_streams,
    'memory_dumps': memory_dumps,
    'module_snapshots': module_snapshots,
}


def extract_remote_hosts(entries):
    hosts = set()
    for entry in entries:
        if isinstance(entry, dict):
            host = entry.get('remote') or entry.get('path') or entry.get('domain')
            if host:
                hosts.add(host.lower())
    return hosts


correlations = {}
indicators = triage.get('indicators', {})
observed_hosts = extract_remote_hosts(telemetry.get('procmon_summary', {}).get('network', []))

if indicators.get('urls'):
    matches = []
    for url in indicators['urls']:
        host = urlparse(url).hostname
        if host and host.lower() in observed_hosts:
            matches.append({'url': url, 'matched_host': host.lower()})
    if matches:
        correlations['static_urls_seen_in_network'] = matches

if indicators.get('ipv4'):
    matching_ips = [ip for ip in indicators['ipv4'] if ip.lower() in observed_hosts]
    if matching_ips:
        correlations['static_ips_seen_in_network'] = matching_ips

if sample_kind.lower() == 'dll':
    suggested = triage.get('dll_analysis', {}).get('suggested_exports', [])
    executed = sorted({entry.get('export') for entry in executions if isinstance(entry, dict) and entry.get('type') == 'dllExport' and entry.get('export')})
    correlations['dll_exports'] = {
        'suggested': suggested,
        'executed': executed,
        'pending': [exp for exp in suggested if exp not in executed],
    }

baseline_diff = baseline.get('diff') if isinstance(baseline.get('diff'), dict) else {}
if indicators.get('registry') and baseline_diff:
    registry_added = set(baseline_diff.get('registryAdded', [])) | set(baseline_diff.get('registryModified', []))
    matched_registry = sorted({reg for reg in indicators['registry'] if reg in registry_added})
    if matched_registry:
        correlations['registry_indicators_touched'] = matched_registry


host_commands_log = run_dir / 'host-commands.log'
host_commands = []
if host_commands_log.exists():
    for line in host_commands_log.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            host_commands.append(json.loads(line))
        except json.JSONDecodeError:
            continue

analysis_summary = {
    'static': {
        'heuristics_score': heuristics_score,
        'heuristics_reasons': triage.get('heuristics', {}).get('reasons', []),
        'suspected': triage.get('suspected'),
        'suspicion_breakdown': triage.get('suspicion_breakdown', []),
    },
    'dynamic': {
        'execution_count': len(executions),
        'memory_dump_count': len(memory_dumps),
        'observed_network_hosts': len(observed_hosts),
    },
}

final = {
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'operator': os.environ.get('USER', 'unknown'),
    'sample': {
        'path': str(sample_path),
        'name': sample_path.name,
        'sha256': sample_sha,
        'size': sample_path.stat().st_size,
        'kind': sample_kind,
    },
    'vm_image': {
        'path': base_image,
        'sha256': base_sha,
    },
    'triage': triage,
    'dynamic': dynamic,
    'attachments': attachments,
    'correlations': correlations,
    'analysis_summary': analysis_summary,
}

if host_commands:
    final['host_commands'] = {
        'log_path': str(host_commands_log.relative_to(run_dir)),
        'total': len(host_commands),
        'recent': host_commands[-25:],
    }

payload = json.dumps(final, sort_keys=True).encode()
integrity = {
    'algorithm': 'sha256',
    'value': hashlib.sha256(payload).hexdigest(),
    'generated_at': datetime.utcnow().isoformat() + 'Z',
}

key_path = os.environ.get('REPORT_SIGNING_KEY_FILE')
if key_path:
    key_file = Path(key_path)
    if key_file.is_file():
        key_material = key_file.read_bytes()
        passphrase = os.environ.get('REPORT_SIGNING_KEY_PASSPHRASE')
        if passphrase:
            key_material += passphrase.encode()
        integrity['hmac_sha256'] = hmac.new(key_material, payload, hashlib.sha256).hexdigest()

final['report_integrity'] = integrity

report_path.write_text(json.dumps(final, indent=2))
PY

if [[ $KEEP_CLONE -eq 0 ]]; then
  log "Removing clone ${CLONE_PATH}"
  run_cmd rm -f "${CLONE_PATH}"
  CLONE_PATH=""
fi

log "Analysis complete. Final report: ${FINAL_REPORT}"
