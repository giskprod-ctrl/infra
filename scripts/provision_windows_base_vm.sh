#!/usr/bin/env bash
set -euo pipefail

log() { printf '[provision-winvm] %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

usage() {
  cat <<'USAGE'
Usage: ./scripts/provision_windows_base_vm.sh [options]

Provision a Windows base VM from an ISO (downloaded from the Internet if needed)
so it can be used by orchestrator.sh as BASE_IMAGE_PATH.

Options:
  --iso-url URL          Windows ISO URL to download when ISO is missing.
  --iso-path PATH        Local path for the ISO (default: ./isos/windows.iso).
  --vm-name NAME         Libvirt VM name (default: windows10-base-installer).
  --disk-path PATH       Output qcow2 path (default: /var/lib/libvirt/images/windows10-base.qcow2).
  --disk-size SIZE       Qcow2 size in GiB (default: 80).
  --memory MB            VM RAM in MiB (default: 8192).
  --vcpus N              Number of vCPUs (default: 4).
  --allow-emulation     Allow TCG emulation when /dev/kvm is unavailable.
  --bridge NAME          Bridge/network name (default: br-sandbox).
  --network-mode MODE    auto|bridge|default (default: auto).
  --os-variant NAME      Libosinfo variant (default: win10).
  --virtio-iso PATH      Optional virtio driver ISO path.
  --start                Start VM after creation (default behavior).
  --no-start             Define VM but do not start.
  --force                Overwrite existing qcow2 and undefine existing VM.
  -h, --help             Show this help.

Notes:
  - This script creates the VM and installation media wiring only.
  - You still need to complete Windows installation and hardening inside the guest
    (qemu-guest-agent, WinRM, autorun.ps1 placement) as documented in README.md.
USAGE
}

ISO_URL="${ISO_URL:-}"
ISO_PATH="${ISO_PATH:-./isos/windows.iso}"
VM_NAME="${VM_NAME:-windows10-base-installer}"
DISK_PATH="${DISK_PATH:-/var/lib/libvirt/images/windows10-base.qcow2}"
DISK_SIZE_GB="${DISK_SIZE_GB:-80}"
MEMORY_MB="${MEMORY_MB:-8192}"
VCPUS="${VCPUS:-4}"
BRIDGE_NAME="${BRIDGE_NAME:-br-sandbox}"
NETWORK_MODE="${NETWORK_MODE:-auto}"
ALLOW_EMULATION=0
OS_VARIANT="${OS_VARIANT:-win10}"
VIRTIO_ISO="${VIRTIO_ISO:-}"
AUTO_START=1
FORCE=0

while (($#)); do
  case "$1" in
    --iso-url) ISO_URL="$2"; shift 2 ;;
    --iso-path) ISO_PATH="$2"; shift 2 ;;
    --vm-name) VM_NAME="$2"; shift 2 ;;
    --disk-path) DISK_PATH="$2"; shift 2 ;;
    --disk-size) DISK_SIZE_GB="$2"; shift 2 ;;
    --memory) MEMORY_MB="$2"; shift 2 ;;
    --vcpus) VCPUS="$2"; shift 2 ;;
    --bridge) BRIDGE_NAME="$2"; shift 2 ;;
    --network-mode) NETWORK_MODE="$2"; shift 2 ;;
    --allow-emulation) ALLOW_EMULATION=1; shift ;;
    --os-variant) OS_VARIANT="$2"; shift 2 ;;
    --virtio-iso) VIRTIO_ISO="$2"; shift 2 ;;
    --start) AUTO_START=1; shift ;;
    --no-start) AUTO_START=0; shift ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

case "$NETWORK_MODE" in auto|bridge|default) ;; *) die "--network-mode must be auto|bridge|default" ;; esac

for cmd in qemu-img virt-install virsh curl; do
  command -v "$cmd" >/dev/null 2>&1 || die "Missing required command: $cmd"
done

mkdir -p "$(dirname "$ISO_PATH")"
mkdir -p "$(dirname "$DISK_PATH")"

if [[ ! -f "$ISO_PATH" ]]; then
  [[ -n "$ISO_URL" ]] || die "ISO file not found at $ISO_PATH. Provide --iso-url to download it."
  log "Downloading Windows ISO from $ISO_URL"
  curl -fL --output "$ISO_PATH" "$ISO_URL"
fi

if virsh dominfo "$VM_NAME" >/dev/null 2>&1; then
  if [[ "$FORCE" == "1" ]]; then
    log "Existing VM $VM_NAME detected; removing due to --force"
    virsh destroy "$VM_NAME" >/dev/null 2>&1 || true
    virsh undefine "$VM_NAME" --nvram >/dev/null 2>&1 || virsh undefine "$VM_NAME" >/dev/null 2>&1 || true
  else
    die "VM $VM_NAME already exists. Use --force to recreate it."
  fi
fi

if [[ -f "$DISK_PATH" ]]; then
  if [[ "$FORCE" == "1" ]]; then
    log "Removing existing disk $DISK_PATH due to --force"
    rm -f "$DISK_PATH"
  else
    die "Disk already exists at $DISK_PATH. Use --force to recreate it."
  fi
fi

log "Creating qcow2 disk at $DISK_PATH (${DISK_SIZE_GB}G)"
qemu-img create -f qcow2 "$DISK_PATH" "${DISK_SIZE_GB}G" >/dev/null

resolve_network_arg() {
  if [[ "$NETWORK_MODE" == "bridge" ]]; then
    echo "bridge=${BRIDGE_NAME},model=virtio"
    return
  fi
  if [[ "$NETWORK_MODE" == "default" ]]; then
    echo "network=default,model=virtio"
    return
  fi
  if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
    echo "bridge=${BRIDGE_NAME},model=virtio"
  else
    echo "network=default,model=virtio"
  fi
}

net_arg="$(resolve_network_arg)"

virt_cmd=(
  virt-install
  --name "$VM_NAME"
  --memory "$MEMORY_MB"
  --vcpus "$VCPUS"
  --machine q35
  --boot uefi
  --os-variant "$OS_VARIANT"
  --network "$net_arg"
  --graphics spice
  --video qxl
  --disk "path=${DISK_PATH},format=qcow2,bus=virtio"
  --cdrom "$ISO_PATH"
  --noautoconsole
)

if [[ -n "$VIRTIO_ISO" ]]; then
  [[ -f "$VIRTIO_ISO" ]] || die "--virtio-iso file not found: $VIRTIO_ISO"
  virt_cmd+=(--disk "path=${VIRTIO_ISO},device=cdrom")
fi

if [[ "$ALLOW_EMULATION" == "1" ]]; then
  virt_cmd+=(--virt-type qemu --cpu max)
fi

if [[ "$AUTO_START" == "0" ]]; then
  virt_cmd+=(--print-xml)
  xml_file="$(mktemp)"
  "${virt_cmd[@]}" >"$xml_file"
  virsh define "$xml_file" >/dev/null
  rm -f "$xml_file"
  log "VM defined but not started (--no-start)."
else
  "${virt_cmd[@]}"
  log "VM created and started. Connect with virt-viewer/virt-manager to finish Windows setup."
fi

cat <<NEXT_STEPS

Next steps inside the Windows guest:
1) Complete Windows install and updates.
2) Install virtio drivers (if needed), qemu-guest-agent, and enable WinRM (HTTP on sandbox network only).
3) Copy autorun.ps1 to C:\\autorun\\autorun.ps1 and create C:\\Sandbox\\Samples.
4) Ensure image path matches orchestrator expectation:
   BASE_IMAGE_PATH=$DISK_PATH
5) Test with:
   ./orchestrator.sh --sample samples/<your-sample>.exe --debug
NEXT_STEPS
