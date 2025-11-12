#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RESET=0
INSTALL=0
FORCE=0

log() { echo "[bootstrap] $*" >&2; }
die() { echo "[bootstrap][error] $*" >&2; exit 1; }

print_usage() {
  cat <<'USAGE'
Usage: scripts/bootstrap_env.sh [options]

Bootstraps the sandbox host by provisioning directories/configuration templates
and optionally installing required host packages.

Options:
  --install      Install required host dependencies for the detected package manager.
  --reset        Purge generated artefacts (out/, diagnostics/, logs/, sandbox clones) before provisioning.
  --force        Do not prompt before destructive reset actions triggered by --reset.
  -h, --help     Show this message.
USAGE
}

while (("$#")); do
  case "$1" in
    --install)
      INSTALL=1; shift ;;
    --reset)
      RESET=1; shift ;;
    --force)
      FORCE=1; shift ;;
    -h|--help)
      print_usage; exit 0 ;;
    *)
      die "Unknown argument: $1" ;;
  esac
done

detect_package_manager() {
  if command -v apt-get >/dev/null 2>&1; then
    echo apt
  elif command -v dnf >/dev/null 2>&1; then
    echo dnf
  elif command -v pacman >/dev/null 2>&1; then
    echo pacman
  else
    echo none
  fi
}

install_dependencies() {
  local manager
  local -a packages update_cmd install_cmd
  manager=$(detect_package_manager)

  case "$manager" in
    apt)
      packages=(
        bridge-utils
        docker.io
        docker-compose
        libguestfs-tools
        libvirt-clients
        libvirt-daemon-system
        qemu-kvm
        qemu-utils
        tcpdump
        virtinst
      )
      update_cmd=(sudo apt-get update)
      install_cmd=(sudo apt-get install -y "${packages[@]}")
      ;;
    dnf)
      packages=(
        '@virtualization'
        bridge-utils
        docker
        docker-compose
        libguestfs-tools-c
        libvirt
        qemu-kvm
        tcpdump
        virt-install
      )
      update_cmd=(sudo dnf makecache)
      install_cmd=(sudo dnf install -y "${packages[@]}")
      ;;
    pacman)
      packages=(
        bridge-utils
        docker
        docker-compose
        libguestfs
        libvirt
        qemu-full
        tcpdump
        virt-install
      )
      update_cmd=(sudo pacman -Sy)
      install_cmd=(sudo pacman -S --needed --noconfirm "${packages[@]}")
      ;;
    none)
      log "Unable to determine the system package manager. Skipping dependency installation."
      return
      ;;
  esac

  log "Detected package manager: $manager"
  log "Refreshing package metadata"
  "${update_cmd[@]}"
  log "Installing dependencies: ${packages[*]}"
  "${install_cmd[@]}"

  if command -v systemctl >/dev/null 2>&1; then
    log "Ensuring libvirtd and docker services are enabled"
    sudo systemctl enable --now libvirtd docker || log "Failed to enable libvirtd/docker services; adjust manually."
  fi
}

confirm_reset() {
  if [[ $FORCE -eq 1 ]]; then
    return
  fi
  read -r -p "This will remove generated artefacts (out/, logs/, sandbox clones). Continue? [y/N] " response
  case "$response" in
    [yY][eE][sS]|[yY]) ;;
    *)
      log "Reset aborted by user."
      exit 0
      ;;
  esac
}

reset_artifacts() {
  confirm_reset
  local -a paths=(
    "$REPO_ROOT/out"
    "$REPO_ROOT/diagnostics"
    "$REPO_ROOT/inetsim/logs"
    "$REPO_ROOT/suricata/logs"
  )

  for path in "${paths[@]}"; do
    if [[ -d "$path" ]]; then
      log "Removing contents of ${path}"
      find "${path}" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
    fi
  done

  local clone_dir="${CLONE_WORKDIR:-/var/lib/libvirt/images}"
  if [[ -d "$clone_dir" ]]; then
    mapfile -t clones < <(find "$clone_dir" -maxdepth 1 -type f -name 'sandbox-*.qcow2' 2>/dev/null)
    if (( ${#clones[@]} )); then
      for clone in "${clones[@]}"; do
        if rm -f "$clone" 2>/dev/null; then
          log "Removed leftover clone $clone"
        else
          log "Could not remove $clone (insufficient permissions). Remove manually if required."
        fi
      done
    else
      log "No sandbox VM clones found in ${clone_dir}."
    fi
  fi
}

ensure_directory() {
  local dir="$1"
  if [[ ! -d "$dir" ]]; then
    log "Creating directory $dir"
    mkdir -p "$dir"
  fi
}

provision_templates() {
  ensure_directory "$REPO_ROOT/samples"
  ensure_directory "$REPO_ROOT/out"
  ensure_directory "$REPO_ROOT/inetsim/etc"
  ensure_directory "$REPO_ROOT/inetsim/logs"
  ensure_directory "$REPO_ROOT/suricata/etc"
  ensure_directory "$REPO_ROOT/suricata/logs"
  ensure_directory "$REPO_ROOT/diagnostics"

  if [[ ! -f "$REPO_ROOT/samples/README.txt" ]]; then
    cat >"$REPO_ROOT/samples/README.txt" <<'EOF'
Place binaries to analyse in this directory.
Generated artefacts from triage runs are stored alongside the original sample
using the `<filename>.triage.json` convention.
EOF
  fi

  if [[ ! -f "$REPO_ROOT/out/README.txt" ]]; then
    cat >"$REPO_ROOT/out/README.txt" <<'EOF'
Dynamic analysis outputs are written here by orchestrator.sh.
Each execution uses a timestamped directory containing the final report and
collected evidence (pcaps, logs, dumps).
EOF
  fi

  if [[ ! -f "$REPO_ROOT/diagnostics/README.txt" ]]; then
    cat >"$REPO_ROOT/diagnostics/README.txt" <<'EOF'
Support bundles and troubleshooting logs generated by orchestrator.sh are
written here when diagnostics collection is enabled.
EOF
  fi

  local inetsim_conf="$REPO_ROOT/inetsim/etc/inetsim.conf"
  if [[ ! -f "$inetsim_conf" ]]; then
    cat >"$inetsim_conf" <<'EOF'
# INetSim default configuration generated by scripts/bootstrap_env.sh
# Adjust service listeners and response profiles as needed.

service_bind_address 0.0.0.0
service_bind_port_default 80

dns_default_ip 198.51.100.1
http_default_content_file /opt/inetsim/share/inetsim/html/default.html

log_dir /logs
pid_file /tmp/inetsim.pid
EOF
  fi

  local suricata_conf="$REPO_ROOT/suricata/etc/suricata.yaml"
  if [[ ! -f "$suricata_conf" ]]; then
    cat >"$suricata_conf" <<'EOF'
# Minimal Suricata configuration generated by scripts/bootstrap_env.sh
# Replace with your production configuration or mount an existing file.

default-log-dir: /logs

vars:
  address-groups:
    HOME_NET: "[192.0.2.0/24]"

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
EOF
  fi

  local autorun_target="$REPO_ROOT/samples/autorun.ps1"
  if [[ ! -f "$autorun_target" ]]; then
    log "Copying autorun.ps1 into samples/ for convenience"
    cp "$REPO_ROOT/autorun.ps1" "$autorun_target"
  fi

  local av_target="$REPO_ROOT/local_av_scanners.json"
  if [[ ! -f "$av_target" && -f "$REPO_ROOT/local_av_scanners.example.json" ]]; then
    log "Seeding local_av_scanners.json from template"
    cp "$REPO_ROOT/local_av_scanners.example.json" "$av_target"
  fi
}

main() {
  if [[ $RESET -eq 1 ]]; then
    reset_artifacts
  fi

  if [[ $INSTALL -eq 1 ]]; then
    install_dependencies
  else
    log "Dependency installation skipped (use --install to install packages)"
  fi

  provision_templates

  log "Bootstrap completed. Run ./deploy_test_env.sh to validate the host configuration."
}

main "$@"
