#!/usr/bin/env bash
set -euo pipefail

log() { printf '[qualification] %s\n' "$*"; }
die() { log "ERROR: $*"; exit 1; }

usage() {
  cat <<'USAGE'
Usage: ./scripts/run_software_qualification.sh --sample <path> [options]

Run a complete software qualification workflow with static triage and optional
full Windows dynamic analysis, then build a decision-oriented report.

Options:
  --sample PATH           Path to .exe/.dll/.msi sample (required)
  --operator NAME         Analyst/operator name (default: $USER or unknown)
  --dynamic MODE          auto|on|off (default: auto)
  --triage MODE           local|docker|auto (default: auto)
  --report-dir PATH       Output folder for qualification report package
                          (default: ./out/qualification-<timestamp>)
  --orchestrator-args STR Extra args appended to orchestrator.sh
  --bridge NAME          Sandbox bridge/network expected for infra checks (default: br-sandbox)
  --auto-fix             Attempt lightweight remediation (bootstrap/install + env validation)
  --self-check-only      Only run infrastructure checks and emit readiness report
  --allow-root            Sets FORCE_NONROOT=0 for triage.sh
  --allow-emulation       Allow QEMU software emulation (no /dev/kvm requirement)
  --net-mode MODE         bridge|default|auto for orchestrator networking (default: auto)
  -h, --help              Show this message

Examples:
  ./scripts/run_software_qualification.sh --sample samples/tool.exe
  ./scripts/run_software_qualification.sh --sample samples/tool.exe --dynamic on --triage docker
USAGE
}

SAMPLE=""
OPERATOR="${USER:-unknown}"
DYNAMIC_MODE="auto"
TRIAGE_MODE="auto"
REPORT_DIR=""
ORCH_ARGS=""
FORCE_NONROOT_VALUE="1"
BRIDGE_NAME="${BRIDGE_NAME:-br-sandbox}"
AUTO_FIX="false"
SELF_CHECK_ONLY="false"
ALLOW_EMULATION="false"
NET_MODE="${SANDBOX_NET_MODE:-auto}"

while (($#)); do
  case "$1" in
    --sample) SAMPLE="$2"; shift 2 ;;
    --operator) OPERATOR="$2"; shift 2 ;;
    --dynamic) DYNAMIC_MODE="$2"; shift 2 ;;
    --triage) TRIAGE_MODE="$2"; shift 2 ;;
    --report-dir) REPORT_DIR="$2"; shift 2 ;;
    --orchestrator-args) ORCH_ARGS="$2"; shift 2 ;;
    --bridge) BRIDGE_NAME="$2"; shift 2 ;;
    --auto-fix) AUTO_FIX="true"; shift ;;
    --self-check-only) SELF_CHECK_ONLY="true"; shift ;;
    --allow-root) FORCE_NONROOT_VALUE="0"; shift ;;
    --allow-emulation) ALLOW_EMULATION="true"; shift ;;
    --net-mode) NET_MODE="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown argument: $1" ;;
  esac
done

if [[ "$SELF_CHECK_ONLY" != "true" ]]; then
  [[ -n "$SAMPLE" ]] || die "--sample is required"
  [[ -f "$SAMPLE" ]] || die "Sample not found: $SAMPLE"
fi

case "$DYNAMIC_MODE" in auto|on|off) ;; *) die "--dynamic must be auto|on|off" ;; esac
case "$TRIAGE_MODE" in auto|local|docker) ;; *) die "--triage must be auto|local|docker" ;; esac
case "$NET_MODE" in auto|bridge|default) ;; *) die "--net-mode must be auto|bridge|default" ;; esac

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SAMPLE_ABS=""
SAMPLE_NAME=""
TRIAGE_JSON=""
if [[ -n "$SAMPLE" ]]; then
  SAMPLE_ABS="$(realpath "$SAMPLE")"
  SAMPLE_NAME="$(basename "$SAMPLE")"
  TRIAGE_JSON="${SAMPLE_ABS}.triage.json"
fi
REPORT_DIR="${REPORT_DIR:-./out/qualification-${STAMP}}"
mkdir -p "$REPORT_DIR"

command_state() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    printf 'present'
  else
    printf 'missing'
  fi
}

kvm_state() {
  if [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]]; then
    printf 'present'
  elif [[ -e /dev/kvm ]]; then
    printf 'permission_denied'
  else
    printf 'missing'
  fi
}

virsh_system_state() {
  if ! command -v virsh >/dev/null 2>&1; then
    printf 'missing'
    return
  fi
  if virsh -c qemu:///system uri >/dev/null 2>&1; then
    printf 'present'
  else
    printf 'error'
  fi
}

libvirt_default_network_state() {
  if ! command -v virsh >/dev/null 2>&1; then
    printf 'missing'
    return
  fi
  local state
  state="$(virsh -c qemu:///system net-info default 2>/dev/null | awk -F': *' '/^Active:/ {print $2}' | tr '[:upper:]' '[:lower:]')"
  if [[ "$state" == "yes" ]]; then
    printf 'present'
  elif [[ -n "$state" ]]; then
    printf 'inactive'
  else
    printf 'missing'
  fi
}

compute_readiness_json() {
  local out_path="$1"
  local docker_state virsh_state virsh_system default_network qemu_img_state smb_state bridge_state base_image_state kvm
  local base_image_path

  base_image_path="${BASE_IMAGE_PATH:-/var/lib/libvirt/images/windows10-base.qcow2}"
  docker_state="$(command_state docker)"
  virsh_state="$(command_state virsh)"
  virsh_system="$(virsh_system_state)"
  default_network="$(libvirt_default_network_state)"
  qemu_img_state="$(command_state qemu-img)"
  smb_state="$(command_state smbclient)"
  kvm="$(kvm_state)"

  if command -v ip >/dev/null 2>&1; then
    if ip link show "$BRIDGE_NAME" >/dev/null 2>&1; then
      bridge_state="present"
    else
      bridge_state="missing"
    fi
  else
    bridge_state="unknown"
  fi

  if [[ -f "$base_image_path" ]]; then
    base_image_state="present"
  else
    base_image_state="missing"
  fi

  python3 - "$out_path" "$docker_state" "$virsh_state" "$virsh_system" "$default_network" "$qemu_img_state" "$smb_state" "$bridge_state" "$base_image_state" "$base_image_path" "$kvm" "$ALLOW_EMULATION" "$NET_MODE" <<'PY'
import json, sys
out = sys.argv[1]
states = {
    "docker": sys.argv[2],
    "virsh": sys.argv[3],
    "virsh_system": sys.argv[4],
    "default_network": sys.argv[5],
    "qemu_img": sys.argv[6],
    "smbclient": sys.argv[7],
    "bridge": sys.argv[8],
    "base_image": sys.argv[9],
    "kvm": sys.argv[11],
}
base_image_path = sys.argv[10]
allow_emulation = sys.argv[12].lower() == "true"
net_mode = sys.argv[13]
bridge_required = net_mode == "bridge" or (net_mode == "auto" and states["bridge"] == "present")
bridge_ok = (states["bridge"] == "present") if bridge_required else True
default_net_required = not bridge_required
default_net_ok = (states["default_network"] == "present") if default_net_required else True
kvm_ok = (states["kvm"] == "present") or allow_emulation
dynamic_ready = all(states[k] == "present" for k in ["virsh", "virsh_system", "qemu_img", "smbclient"]) and bridge_ok and default_net_ok and kvm_ok and states["base_image"] == "present"
container_ready = states["docker"] == "present"
overall_ready = dynamic_ready and container_ready
payload = {
    "states": states,
    "base_image_path": base_image_path,
    "dynamic_ready": dynamic_ready,
    "container_ready": container_ready,
    "overall_ready": overall_ready,
}
with open(out, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
PY
}

preflight_check() {
  local preflight_json="$REPORT_DIR/infra-readiness.json"
  compute_readiness_json "$preflight_json"

  if [[ "$AUTO_FIX" == "true" ]]; then
    log "Auto-fix enabled: attempting environment bootstrap"
    if [[ -x ./scripts/bootstrap_env.sh ]]; then
      ./scripts/bootstrap_env.sh --install || true
    fi
    if [[ -x ./deploy_test_env.sh ]]; then
      USER="${USER:-analyst}" ./deploy_test_env.sh --bridge "$BRIDGE_NAME" --dry-run --allow-root || true
    fi

    compute_readiness_json "$preflight_json"
  fi

  log "Infrastructure readiness written to $preflight_json"
}

preflight_check

if [[ "$SELF_CHECK_ONLY" == "true" ]]; then
  log "Self-check completed (--self-check-only), exiting without sample execution."
  exit 0
fi

run_triage_local() {
  log "Running local triage.sh"
  FORCE_NONROOT="$FORCE_NONROOT_VALUE" ./triage.sh \
    --debug \
    --file "$SAMPLE_ABS" \
    --json "$TRIAGE_JSON" \
    --yara-category malware \
    --yara-category lolbin \
    --yara-category internal \
    --yara-category vendor/signature-base \
    --yara-category vendor/yara-forensics \
    --yara-category vendor/elastic
}

run_triage_docker() {
  local docker_sample_path

  command -v docker >/dev/null 2>&1 || return 1
  if ! docker compose ps triage >/dev/null 2>&1; then
    docker compose up -d triage >/dev/null
  fi

  docker_sample_path="${SAMPLE_ABS}"
  if [[ "$SAMPLE_ABS" != "$PWD"/* ]]; then
    log "Sample outside repository; copying into ./samples for docker triage"
    mkdir -p "$SAMPLE_DIR"
    cp -f "$SAMPLE_ABS" "$SAMPLE_DIR/$SAMPLE_NAME"
    docker_sample_path="$(realpath "$SAMPLE_DIR/$SAMPLE_NAME")"
  fi

  log "Running triage via docker compose"
  docker compose exec -T triage ./triage.sh \
    --debug \
    --file "$docker_sample_path" \
    --json "$TRIAGE_JSON" \
    --yara-category malware \
    --yara-category lolbin \
    --yara-category internal \
    --yara-category vendor/signature-base \
    --yara-category vendor/yara-forensics \
    --yara-category vendor/elastic
}

if [[ "$TRIAGE_MODE" == "docker" ]]; then
  run_triage_docker || die "Docker triage failed"
elif [[ "$TRIAGE_MODE" == "local" ]]; then
  run_triage_local
else
  if command -v docker >/dev/null 2>&1; then
    run_triage_docker || run_triage_local
  else
    run_triage_local
  fi
fi

[[ -f "$TRIAGE_JSON" ]] || die "Expected triage JSON missing: $TRIAGE_JSON"
cp "$TRIAGE_JSON" "$REPORT_DIR/triage.json"

DYNAMIC_RAN="false"
FINAL_REPORT=""
if [[ "$DYNAMIC_MODE" != "off" ]]; then
  can_dynamic=1
  for cmd in virsh qemu-img smbclient; do
    command -v "$cmd" >/dev/null 2>&1 || can_dynamic=0
  done
  BASE_IMAGE_PATH="${BASE_IMAGE_PATH:-/var/lib/libvirt/images/windows10-base.qcow2}"
  [[ -f "$BASE_IMAGE_PATH" ]] || can_dynamic=0
  if [[ "$ALLOW_EMULATION" != "true" ]]; then
    [[ -e /dev/kvm && -r /dev/kvm && -w /dev/kvm ]] || can_dynamic=0
  fi
  if [[ "$NET_MODE" == "bridge" ]]; then
    ip link show "$BRIDGE_NAME" >/dev/null 2>&1 || can_dynamic=0
  else
    virsh -c qemu:///system net-info default 2>/dev/null | awk -F': *' '/^Active:/ {print $2}' | grep -qi yes || can_dynamic=0
  fi
  virsh -c qemu:///system uri >/dev/null 2>&1 || can_dynamic=0

  if [[ "$DYNAMIC_MODE" == "on" && $can_dynamic -eq 0 ]]; then
    die "Dynamic mode forced on but prerequisites are missing (virsh/qemu-img/smbclient, working qemu:///system libvirt, required network mode, base image, and /dev/kvm unless --allow-emulation)."
  fi

  if [[ $can_dynamic -eq 1 ]]; then
    log "Running orchestrator dynamic analysis"
    # shellcheck disable=SC2086
    orch_allow_root=""
    if [[ "$FORCE_NONROOT_VALUE" == "0" ]]; then
      orch_allow_root="--allow-root"
    fi
    SANDBOX_NET_MODE="$NET_MODE" ./orchestrator.sh --sample "$SAMPLE_ABS" --debug ${orch_allow_root} $ORCH_ARGS
    latest_out="$(ls -1dt out/* 2>/dev/null | head -n1 || true)"
    if [[ -n "$latest_out" && -f "$latest_out/final-report.json" ]]; then
      FINAL_REPORT="$latest_out/final-report.json"
      cp "$FINAL_REPORT" "$REPORT_DIR/final-report.json"
      DYNAMIC_RAN="true"
    fi
  else
    log "Dynamic analysis skipped (missing VM/libvirt prerequisites in this environment)."
  fi
fi

python3 - "$REPORT_DIR" "$OPERATOR" "$SAMPLE_ABS" "$DYNAMIC_RAN" "$DYNAMIC_MODE" "$TRIAGE_MODE" <<'PY'
import json
import pathlib
import sys
from datetime import datetime, timezone

report_dir = pathlib.Path(sys.argv[1])
operator = sys.argv[2]
sample = sys.argv[3]
dynamic_ran = sys.argv[4].lower() == "true"
dynamic_mode = sys.argv[5]
triage_mode = sys.argv[6]
triage_path = report_dir / "triage.json"
final_path = report_dir / "final-report.json"

triage = json.loads(triage_path.read_text()) if triage_path.exists() else {}
final = json.loads(final_path.read_text()) if final_path.exists() else {}
readiness_path = report_dir / "infra-readiness.json"
readiness = json.loads(readiness_path.read_text()) if readiness_path.exists() else {}

def g(obj, path, default=None):
    cur = obj
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur

def has_data(value):
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    if isinstance(value, str):
        return value.strip() != ""
    return True

minimum_dynamic_coverage = {
    "phase1_install_prerequisites": {
        "supported": has_data(g(final, ["dynamic", "execution_context"], {})),
        "source": "dynamic.execution_context"
    },
    "phase1_install_network": {
        "supported": has_data(g(final, ["dynamic", "telemetry", "network"], {})),
        "source": "dynamic.telemetry.network"
    },
    "phase1_install_files_registry": {
        "supported": has_data(g(final, ["dynamic", "baseline", "diff"], {})),
        "source": "dynamic.baseline.diff"
    },
    "phase1_install_process_services": {
        "supported": has_data(g(final, ["dynamic", "process_tree"], [])) or has_data(g(final, ["dynamic", "telemetry", "services"], [])),
        "source": "dynamic.process_tree + dynamic.telemetry.services"
    },
    "phase2_behavioral_use_cases": {
        "supported": has_data(g(final, ["dynamic", "executions"], [])),
        "source": "dynamic.executions"
    },
    "phase2_runtime_network": {
        "supported": has_data(g(final, ["dynamic", "telemetry", "network"], {})),
        "source": "dynamic.telemetry.network"
    },
    "phase2_runtime_files_registry": {
        "supported": has_data(g(final, ["dynamic", "baseline", "diff"], {})),
        "source": "dynamic.baseline.diff"
    },
    "phase2_runtime_process_services_dlls": {
        "supported": has_data(g(final, ["dynamic", "process_tree"], [])) or has_data(g(final, ["dynamic", "module_snapshots"], [])),
        "source": "dynamic.process_tree + dynamic.module_snapshots"
    }
}

coverage_supported_count = sum(1 for item in minimum_dynamic_coverage.values() if item["supported"])
coverage_total = len(minimum_dynamic_coverage)

summary = {
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "operator": operator,
    "sample": {
        "path": sample,
        "sha256": g(triage, ["sha256"]),
        "size": g(triage, ["size"]),
        "filetype": g(triage, ["filetype"]),
    },
    "static": {
        "entropy": g(triage, ["entropy"]),
        "yara_matches": g(triage, ["yara_matches"], []),
        "suspected": g(triage, ["suspected"]),
        "pe_metadata": g(triage, ["pe_metadata"], {}),
        "dll_analysis": g(triage, ["dll_analysis"], {}),
        "indicators": g(triage, ["indicators"], {}),
        "heuristics": g(triage, ["heuristics"], {}),
    },
    "dynamic": {
        "executed": dynamic_ran,
        "verdict": g(final, ["dynamic", "verdict"]),
        "winrm": g(final, ["dynamic", "winrm"], {}),
        "baseline_diff": g(final, ["dynamic", "baseline", "diff"], {}),
        "process_tree": g(final, ["dynamic", "process_tree"], []),
        "module_snapshots": g(final, ["dynamic", "module_snapshots"], []),
        "memory_dumps": g(final, ["dynamic", "memory_dumps"], []),
        "telemetry": g(final, ["dynamic", "telemetry"], {}),
        "executions": g(final, ["dynamic", "executions"], []),
    },
    "correlations": g(final, ["correlations"], {}),
    "attachments": g(final, ["attachments"], []),
    "analysis_summary": g(final, ["analysis_summary"], {}),
    "infrastructure": {
        "readiness": readiness,
        "blockers": [
            key for key, state in readiness.get("states", {}).items()
            if key in {"virsh", "virsh_system", "default_network", "qemu_img", "smbclient", "bridge", "base_image", "kvm"} and state != "present"
        ],
        "overall_operational": bool(readiness.get("overall_ready", False) and (dynamic_ran if dynamic_mode != "off" else True) and (
            readiness.get("container_ready", False) if triage_mode == "docker" else True
        ))
    },
    "dynamic_minimum_coverage": {
        "items": minimum_dynamic_coverage,
        "supported_count": coverage_supported_count,
        "total_count": coverage_total,
        "coverage_ratio": (coverage_supported_count / coverage_total) if coverage_total else 0.0
    },
    "decision_aid": {
        "key_findings": [
            f"YARA matches: {', '.join(g(triage, ['yara_matches'], []) or ['none'])}",
            f"Entropy: {g(triage, ['entropy'])}",
            f"Static suspected: {g(triage, ['suspected'])}",
            f"Dynamic executed: {dynamic_ran}",
            f"Dynamic verdict: {g(final, ['dynamic', 'verdict'], 'n/a')}",
        ],
        "recommended_next_step": "Review dynamic baseline diff + telemetry before allowlisting in internal network."
    }
}

(report_dir / "qualification-summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False))

md = []
md.append("# Software Qualification Report")
md.append("")
md.append(f"- Generated: {summary['generated_at']}")
md.append(f"- Operator: {operator}")
md.append(f"- Sample: {sample}")
md.append("")
md.append("## Static analysis")
md.append(f"- SHA256: {summary['sample']['sha256']}")
md.append(f"- File type: {summary['sample']['filetype']}")
md.append(f"- Entropy: {summary['static']['entropy']}")
md.append(f"- YARA matches: {', '.join(summary['static']['yara_matches']) if summary['static']['yara_matches'] else 'none'}")
md.append(f"- Suspected: {summary['static']['suspected']}")
md.append("")
md.append("## Dynamic analysis")
md.append(f"- Executed: {summary['dynamic']['executed']}")
md.append(f"- Verdict: {summary['dynamic']['verdict']}")
md.append(f"- WinRM status: {summary['dynamic']['winrm'].get('status_code', 'n/a') if isinstance(summary['dynamic']['winrm'], dict) else 'n/a'}")
md.append("")
md.append("## Windows changes and behavior (from dynamic telemetry)")
md.append("- Baseline diff (process/services/tasks/registry):")
md.append("```json")
md.append(json.dumps(summary['dynamic']['baseline_diff'], indent=2, ensure_ascii=False))
md.append("```")
md.append("- Process tree:")
md.append("```json")
md.append(json.dumps(summary['dynamic']['process_tree'], indent=2, ensure_ascii=False))
md.append("```")
md.append("")
md.append("## Infrastructure operational status")
md.append(f"- Overall ready: {readiness.get('overall_ready', False)}")
md.append(f"- Dynamic capable now: {readiness.get('dynamic_ready', False)}")
md.append(f"- Container capable now: {readiness.get('container_ready', False)}")
md.append(f"- Operational with end-to-end evidence: {summary['infrastructure']['overall_operational']}")
md.append(f"- Dynamic blockers: {', '.join(summary['infrastructure']['blockers']) if summary['infrastructure']['blockers'] else "none"}")
md.append("")
md.append("## Dynamic minimum coverage (requested checklist)")
for key, item in summary["dynamic_minimum_coverage"]["items"].items():
    status = "OK" if item.get("supported") else "MISSING"
    md.append(f"- {key}: {status} (source: {item.get('source', 'n/a')})")
md.append(f"- Coverage: {summary['dynamic_minimum_coverage']['supported_count']}/{summary['dynamic_minimum_coverage']['total_count']} ({summary['dynamic_minimum_coverage']['coverage_ratio']:.2%})")
md.append("")
md.append("## Decision aid")
for finding in summary["decision_aid"]["key_findings"]:
    md.append(f"- {finding}")
md.append("")
md.append(f"Next step: {summary['decision_aid']['recommended_next_step']}")

(report_dir / "qualification-report.md").write_text("\n".join(md), encoding="utf-8")
PY

if command -v python3 >/dev/null 2>&1 && [[ -x ./scripts/render_dynamic_questionnaire.py ]]; then
  python3 ./scripts/render_dynamic_questionnaire.py     --summary "$REPORT_DIR/qualification-summary.json"     --out "$REPORT_DIR/dynamic-questionnaire.md" || true
fi

log "Qualification package generated in: $REPORT_DIR"
log " - $REPORT_DIR/triage.json"
log " - $REPORT_DIR/infra-readiness.json"
if [[ -f "$REPORT_DIR/final-report.json" ]]; then
  log " - $REPORT_DIR/final-report.json"
fi
log " - $REPORT_DIR/qualification-summary.json"
log " - $REPORT_DIR/qualification-report.md"
if [[ -f "$REPORT_DIR/dynamic-questionnaire.md" ]]; then
  log " - $REPORT_DIR/dynamic-questionnaire.md"
fi
