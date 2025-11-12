#!/usr/bin/env bash
set -euo pipefail

BRIDGE_NAME="${BRIDGE_NAME:-br-sandbox}"
FORCE_NONROOT="${FORCE_NONROOT:-1}"
DRY_RUN=0
ALLOW_ROOT=0
TCPDUMP_USER="${TCPDUMP_USER:-$USER}"

log() { echo "[deploy] $*" >&2; }
die() { echo "[deploy][error] $*" >&2; exit 1; }

print_usage() {
  cat <<'USAGE'
Usage: ./deploy_test_env.sh [--bridge <name>] [--dry-run] [--allow-root]

Prepares the host machine for the sandbox environment:
  * validates dependencies (qemu, libvirt, virt-* tools, docker, tcpdump)
  * checks KVM acceleration availability
  * creates the isolated bridge if missing
  * reminds you of security guardrails before launching analyses.

Run ./scripts/bootstrap_env.sh first to install prerequisites and provision local directories automatically.
USAGE
}

while (("$#")); do
  case "$1" in
    --bridge)
      BRIDGE_NAME="$2"; shift 2 ;;
    --dry-run)
      DRY_RUN=1; shift ;;
    --allow-root)
      ALLOW_ROOT=1; shift ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      die "Unknown argument: $1" ;;
  esac
done

if [[ ${FORCE_NONROOT} == "1" && ${ALLOW_ROOT} -eq 0 && $(id -u) -eq 0 ]]; then
  die "Refusing to run as root. Re-run with --allow-root if you really need root privileges."
fi

run_cmd() {
  local -a cmd=("$@")
  if [[ ${#cmd[@]} -eq 0 ]]; then
    return 0
  fi
  local formatted
  formatted=$(printf '%q ' "${cmd[@]}")
  formatted=${formatted%% }
  if [[ $DRY_RUN -eq 1 ]]; then
    log "[dry-run] ${formatted}"
    return 0
  fi
  log "${formatted}"
  "${cmd[@]}"
}

missing=()
for cmd in qemu-img qemu-system-x86_64 virt-copy-in virt-copy-out virt-install virsh tcpdump docker docker-compose; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    missing+=("$cmd")
  fi
done

if ((${#missing[@]})); then
  log "Missing tools detected: ${missing[*]}"
  log "Install them using your distribution package manager. Example (Debian/Ubuntu):"
  log "  sudo apt install qemu-utils libguestfs-tools virtinst libvirt-clients tcpdump docker.io docker-compose"
  log "Or run ./scripts/bootstrap_env.sh to handle installation automatically."
else
  log "All required binaries found."
fi

log "Checking KVM acceleration"
if [[ -r /proc/cpuinfo ]] && grep -Eiq 'vmx|svm' /proc/cpuinfo; then
  log "CPU virtualization extensions detected."
else
  log "WARNING: CPU virtualization extensions (VT-x/AMD-V) not detected."
fi

if lsmod | grep -q kvm; then
  log "kvm kernel module loaded."
else
  log "WARNING: kvm kernel module not loaded. Run: sudo modprobe kvm"
fi

if [[ -n "${BRIDGE_NAME}" ]]; then
  if ip link show "${BRIDGE_NAME}" >/dev/null 2>&1; then
    log "Bridge ${BRIDGE_NAME} already exists."
  else
    log "Creating bridge ${BRIDGE_NAME}"
    run_cmd sudo ip link add name "${BRIDGE_NAME}" type bridge
    run_cmd sudo ip link set "${BRIDGE_NAME}" up
    run_cmd sudo ip addr flush dev "${BRIDGE_NAME}"
  fi
fi

log "Ensuring tcpdump capture permissions follow host hardening guidance"
if command -v setcap >/dev/null 2>&1; then
  run_cmd sudo setcap "CAP_NET_RAW+eip CAP_NET_ADMIN+eip" "$(command -v tcpdump)"
  if getent group pcap >/dev/null 2>&1; then
    log "Adding ${TCPDUMP_USER} to pcap group for tcpdump access"
    run_cmd sudo usermod -a -G pcap "${TCPDUMP_USER}"
  else
    log "Group 'pcap' not present; consider creating it and granting tcpdump group ownership."
  fi
else
  log "setcap not available; tcpdump may require sudo."
fi

cat <<CHECKLIST

Next steps checklist:
  [ ] Place your prepared windows10-base.qcow2 at ${BASE_IMAGE_PATH:-/var/lib/libvirt/images/windows10-base.qcow2}
  [ ] Ensure qemu-guest-agent and WinRM are configured in the guest.
  [ ] Copy autorun.ps1 into C:\\autorun on the gold image and set execution policy.
  [ ] Configure INetSim docker image (${INETSIM_IMAGE:-opennic/inetsim}) and Suricata profile if required.
  [ ] Test docker-compose up to confirm INetSim responds within the isolated bridge.
  [ ] Run ./triage.sh on a benign sample to validate hashing/yara workflow.
  [ ] Use ./orchestrator.sh --dry-run to confirm actions before executing malware.
  [ ] Never attach ${BRIDGE_NAME} to the Internet; keep it air-gapped.
CHECKLIST

log "Host preparation script completed."
