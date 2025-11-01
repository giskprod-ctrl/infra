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

run_cmd() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log "[dry-run] $*"
  else
    if [[ $DEBUG -eq 1 ]]; then
      log "[exec] $*"
    fi
    eval "$@"
  fi
}

run_cmd_capture() {
  if [[ $DRY_RUN -eq 1 ]]; then
    log "[dry-run] $*"
    return 0
  fi
  if [[ $DEBUG -eq 1 ]]; then
    log "[exec] $*"
  fi
  eval "$@"
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

SAMPLE_ABS="$(realpath "${SAMPLE_PATH}")"
SAMPLE_NAME="$(basename "${SAMPLE_PATH}")"
TRIAGE_JSON="${SAMPLE_ABS}.triage.json"
FINAL_REPORT="${RUN_DIR}/final-report.json"
SAMPLE_SHA="$(sha256sum "${SAMPLE_ABS}" | awk '{print $1}')"
BASE_IMAGE_SHA="$(sha256sum "${BASE_IMAGE_PATH}" | awk '{print $1}')"
export RUN_DIR FINAL_REPORT SAMPLE_ABS SAMPLE_NAME TRIAGE_JSON BASE_IMAGE_PATH TIMEOUT_SECONDS COLLECT_MEMORY SAMPLE_SHA BASE_IMAGE_SHA

if [[ $RUN_TRIAGE -eq 1 && ! -f "${TRIAGE_JSON}" ]]; then
  err "Triage JSON ${TRIAGE_JSON} not found. Run triage.sh first or use --no-triage."
  exit 1
fi

log "Creating clone ${CLONE_PATH}"
run_cmd "qemu-img create -f qcow2 -F qcow2 -b '${BASE_IMAGE_PATH}' '${CLONE_PATH}'"

log "Injecting sample into offline image"
run_cmd "virt-copy-in -a '${CLONE_PATH}' '${SAMPLE_ABS}' 'C:\\sandbox'"

log "Copying autorun script"
run_cmd "virt-copy-in -a '${CLONE_PATH}' autorun.ps1 'C:\\autorun'"

start_vm() {
  local cmd="virt-install --name ${VM_NAME} --memory ${VM_MEM} --vcpus ${VM_CPUS} --import --disk path=${CLONE_PATH},format=qcow2 --network bridge=${BRIDGE_NAME},model=virtio --os-variant win10 --graphics none --noautoconsole --check path_in_use=off --wait 0"
  run_cmd "$cmd"
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
  local cmd="${TCPDUMP_PRIV_CMD} tcpdump -i ${BRIDGE_NAME} -w ${pcap_prefix}-%Y%m%d%H%M%S.pcap -C ${TCPDUMP_ROTATE_SIZE_MB} -W ${TCPDUMP_FILES} -n"
  if [[ $DRY_RUN -eq 1 ]]; then
    log "[dry-run] ${cmd}"
    return 0
  fi
  if [[ $DEBUG -eq 1 ]]; then
    log "Starting tcpdump: ${cmd}"
  fi
  eval "${cmd} &"
  TCPDUMP_PID=$!
  log "tcpdump PID ${TCPDUMP_PID}"
}

start_tcpdump

log "Uploading sample via SMB to ${SMB_UPLOAD_DIR}"
run_cmd "smbclient //${GUEST_IP}/${SMB_SHARE} '${VM_PASSWORD}' -U ${VM_USER}%${VM_PASSWORD} -c 'mkdir ${SMB_UPLOAD_DIR}' || true"
run_cmd "smbclient //${GUEST_IP}/${SMB_SHARE} '${VM_PASSWORD}' -U ${VM_USER}%${VM_PASSWORD} -c 'put \"${SAMPLE_ABS}\" ${SMB_UPLOAD_DIR}\\${SAMPLE_NAME}'"

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
collect_memory = sys.argv[8] == '1'

try:
    import winrm
except ImportError:
    print("pywinrm not installed; cannot trigger execution", file=sys.stderr)
    sys.exit(1)

session = winrm.Session(f'http://{addr}:{port}/wsman', auth=(user, password))
args = ['-ExecutionPolicy', 'Bypass', '-File', autorun, '-SamplePath', sample_path, '-TimeoutSeconds', str(timeout)]
if collect_memory:
    args.extend(['-CollectMemory', 'True'])
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

if [[ $DRY_RUN -eq 1 ]]; then
  log "[dry-run] Would trigger WinRM execution"
else
  trigger_execution "C:\\${SMB_UPLOAD_DIR}\\${SAMPLE_NAME}" "${AUTORUN_PATH}" "${VM_USER}" "${VM_PASSWORD}" "${GUEST_IP}" "${WINRM_PORT}" "${TIMEOUT_SECONDS}" > "${RUN_DIR}/winrm-exec.json"
fi

log "Sleeping for ${TIMEOUT_SECONDS}s to allow execution"
if [[ $DRY_RUN -eq 0 ]]; then
  sleep "${TIMEOUT_SECONDS}"
fi

log "Initiating graceful shutdown"
run_cmd "virsh --connect '${QEMU_URI}' shutdown '${VM_NAME}'"
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
  TCPDUMP_PID=""
fi

log "Collecting guest artifacts"
run_cmd "virt-copy-out -a '${CLONE_PATH}' '${RESULTS_DIR_GUEST}' '${RUN_DIR}'"

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
import hashlib
import json
import os
from pathlib import Path
from datetime import datetime

run_dir = Path(os.environ['RUN_DIR'])
report_path = Path(os.environ['FINAL_REPORT'])
artifacts_path = Path(os.environ['ARTIFACTS_JSON'])
sample_path = Path(os.environ['SAMPLE_ABS'])
sample_sha = os.environ['SAMPLE_SHA']
triage_path = os.environ.get('TRIAGE_JSON', '')
base_image = os.environ['BASE_IMAGE_PATH']
base_sha = os.environ['BASE_IMAGE_SHA']
collect_memory = os.environ['COLLECT_MEMORY'] == '1'
timeout = int(os.environ['TIMEOUT_SECONDS'])

artifacts_map = json.loads(artifacts_path.read_text())
attachments = []
for rel_path, meta in artifacts_map.items():
    attachments.append({
        'path': rel_path,
        **meta
    })

triage = {}
if triage_path and Path(triage_path).is_file():
    triage = json.loads(Path(triage_path).read_text())

dynamic_verdict = 'needs-review'
if triage.get('suspected') is True:
    dynamic_verdict = 'suspicious'
elif triage.get('suspected') is False:
    dynamic_verdict = 'benign'

winrm_data = {}
winrm_file = run_dir / 'winrm-exec.json'
if winrm_file.exists():
    winrm_data = json.loads(winrm_file.read_text())

final = {
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'operator': os.environ.get('USER', 'unknown'),
    'sample': {
        'path': str(sample_path),
        'name': sample_path.name,
        'sha256': sample_sha,
        'size': sample_path.stat().st_size,
    },
    'vm_image': {
        'path': base_image,
        'sha256': base_sha,
    },
    'triage': triage,
    'dynamic': {
        'timeout_seconds': timeout,
        'collect_memory': collect_memory,
        'verdict': dynamic_verdict,
        'winrm': winrm_data,
    },
    'attachments': attachments,
}

payload = json.dumps(final, sort_keys=True).encode()
signature = hashlib.sha256(payload).hexdigest()
final['report_integrity'] = {
    'algorithm': 'sha256',
    'value': signature,
}

report_path.write_text(json.dumps(final, indent=2))
PY

if [[ $KEEP_CLONE -eq 0 ]]; then
  log "Removing clone ${CLONE_PATH}"
  run_cmd "rm -f '${CLONE_PATH}'"
  CLONE_PATH=""
fi

log "Analysis complete. Final report: ${FINAL_REPORT}"
