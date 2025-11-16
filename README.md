# Windows Binary Analysis Sandbox

This repository contains an end-to-end infrastructure to triage, execute, and
report on Windows binaries (`.exe`/`.msi`) in an isolated environment. The
stack is designed for analysts who want a reproducible and tweakable setup that
runs locally without jeopardising the host system.

## Components

| Component | Purpose |
|-----------|---------|
| `docker-compose.yml` | Starts the triage container (Wine + pe-sieve + rizin), an INetSim service for fake Internet responses, and an optional Suricata sensor.
| `triage.sh` | Performs rapid static/dynamic triage inside the triage container and emits JSON reports.
| `analyse_adapter/` | Python wrapper for integrating `analysisSimba.py` outputs into a standard JSON structure.
| `orchestrator.sh` | Manages virtual machine cloning, execution, evidence collection, and final report generation.
| `autorun.ps1` | PowerShell automation dropped inside the Windows gold image to execute samples (EXEs or DLL exports), capture baselines/telemetry, and ship memory/network artefacts back to the host.
| `deploy_test_env.sh` | Host bootstrap script that validates prerequisites and prepares the isolated bridge network.
| `local_av_scanners.example.json` | Sample configuration for chaining local antivirus engines during triage.
| `yara_rules/` | Structured YARA catalogue (malware, LOLBIN, internal overrides, curated vendor mirrors).
| `final-report.template.json` | Template describing the expected report schema.
| `final-report.example.json` | Minimal example output.

## Prerequisites

* Linux host with KVM support and libvirt (tested on Ubuntu 22.04).
* Windows 10/11 gold image (`windows10-base.qcow2`) with:
  * `qemu-guest-agent` installed and running.
  * WinRM enabled (HTTP within the isolated bridge only).
  * `autorun.ps1` placed in `C:\autorun\autorun.ps1`.
  * Sysinternals Procmon and ProcDump installed (paths configurable in the script).
  * `C:\Sandbox\Samples` directory created (or adjust `SMB_UPLOAD_DIR`).
  * Optional: Sysmon installed and logging to `Microsoft-Windows-Sysmon/Operational`.
* Docker Engine and Docker Compose v2.
* Ability to create an isolated Linux bridge (no uplinks!) for the sandbox.

> **Never expose the analysis network to the Internet.** Keep the bridge
> air-gapped; only INetSim, optional Suricata, and the Windows VM should attach
> to it.

## Environment Bootstrap

Run `./scripts/bootstrap_env.sh` to prepare a fresh host. The helper:

* detects whether `apt`, `dnf`, or `pacman` is available and installs the required packages (QEMU/libvirt tooling, docker, tcpdump, bridge utilities) when `--install` is provided.
* creates local folders (`samples/`, `out/`, `inetsim/`, `suricata/`, `diagnostics/`) and seeds default configuration templates.
* copies `autorun.ps1` into `samples/` and seeds `local_av_scanners.json` from `local_av_scanners.example.json` when missing.
* optionally purges captured artefacts, diagnostics, logs, and any `sandbox-*.qcow2` clones when `--reset` is requested.

Options:

* `--install` – install distribution packages providing QEMU/libvirt utilities, Docker Engine/Compose, and tcpdump.
* `--reset` – remove generated artefacts (`out/`, `diagnostics/`, INetSim/Suricata logs) and leftover sandbox clones before recreating templates.
* `--force` – suppress the confirmation prompt normally shown by `--reset`.

You can run the bootstrap script directly or invoke it through `./deploy_test_env.sh` with `--bootstrap-install`/`--bootstrap-reset` when combining host validation with provisioning.

## Quick Start

1. **Bootstrap or reset the host**
   ```bash
   # Fresh installation with package provisioning
   ./deploy_test_env.sh --bootstrap-install --bridge br-sandbox

   # Reset artefacts/logs and recreate templates
   ./deploy_test_env.sh --bootstrap-reset --bootstrap-force --bridge br-sandbox
   ```
   `deploy_test_env.sh` can invoke `scripts/bootstrap_env.sh` for you. Use
   `--bootstrap-install` on a new host to install dependencies, provision
   directories (`samples/`, `out/`, `inetsim/`, `suricata/`, `diagnostics/`), and
   copy template configs. Add `--bootstrap-reset` (optionally with
   `--bootstrap-force`) between analysis campaigns to wipe artefacts and remove
   stale VM clones. The script then validates KVM availability, creates the
   `br-sandbox` bridge if required, and prints a hardening checklist. Append
   `--dry-run` to review actions without executing them.

2. **Bring up supportive services**
   ```bash
   docker-compose up -d
   ```
   This starts INetSim (`sandbox-inetsim`) and the triage container
   (`sandbox-triage`). The triage container runs as a non-root user and mounts
   `./samples` as its working directory.

3. **Run triage on a sample**
   ```bash
   docker compose exec sandbox-triage ./triage.sh --file samples/test-safe.exe
   ```
   Output is saved as `samples/test-safe.exe.triage.json`. Review the JSON to
   confirm hashes, entropy, YARA matches, and heuristics (`suspected`).

### Static inspection depth

`triage.sh` bakes in the heuristics normally provided by Manalyze and extends
them further:

* **Import table reconstruction + imphash** – the parser walks the PE import
  descriptors directly, preserves descriptor order, and emits both a structured
  view (`static_analysis.advanced_imports`) and the derived imphash for rapid
  clustering.
* **Rich header decoding** – the DOS stub is decoded, the `Rich` signature is
  hashed (SHA-256), and product/build tuples are preserved to help attribute the
  originating toolchain.
* **TLS callback detection** – TLS directory parsing highlights callback VAs and
  raises a heuristic flag because malware frequently abuses TLS callbacks to run
  before `main`/`DllMain`.
* **Data-directory sanity checks** – inconsistent RVA/size entries are recorded
  and wired into the suspicion score to catch malformed PE headers.
* **ssdeep / fuzzy hashes** – if the `ssdeep` binary is present, the fuzzy hash
  is injected into `static_analysis.hashes`. Install it via `apt install ssdeep`
  (or the equivalent package on your distribution) to unlock this signal.

These additions make the static JSON richer than the default Manalyze output
while keeping the tooling self-contained inside the triage container.

4. **Execute full dynamic analysis**
   ```bash
   ./orchestrator.sh --sample samples/test-safe.exe
   ```
   The orchestrator clones the base QCOW2, uploads the sample via SMB, triggers
   `autorun.ps1` through WinRM, captures traffic (`tcpdump`) and artefacts, and
   writes `/out/<timestamp>/final-report.json` plus all evidence. Use
   `--dry-run`, `--debug`, or `--keep-clone` while testing.

### YARA rule management and tuning

The `yara_rules/` tree is now split into dedicated catalogues:

* `malware/` – in-house rules for packers, droppers, and injection tradecraft.
* `lolbin/` – detections for living-off-the-land binaries and scripts.
* `internal/` – overrides (`overrides.yar`) and noise tracking (`noisy_rules.txt`).
* `vendor/` – curated mirrors of trusted open-source projects (signature-base, yara-forensics, Elastic).

**Update policy**

* **Cadence:** Refresh vendor mirrors and internal rules during the first week of every month, or immediately after major intelligence drops.
* **Owner:** Detection Engineering (contact: `detections@infra.local`). Submit PRs for structural changes or emergency fixes outside the regular window.
* **Process:**
  1. Pull upstream mirrors (or run the sync helper once created) and review upstream changelogs for impactful signatures.
  2. De-duplicate rules by name across `vendor/` and internal categories. Prefer the vendor implementation when semantics overlap.
  3. Adjust conditions (e.g. PE header gates, stricter string combinations) to minimise false positives before promoting updates to `malware/` or `lolbin/`.
  4. Update `internal/noisy_rules.txt` if a vendor rule is known to be noisy but still valuable. Add targeted suppressions in `internal/overrides.yar` when outright disabling is necessary.

**Validation workflow**

Run the following checks before pushing updates:

```bash
# Ensure the combined catalogue is syntactically correct
yara --fail-on-warnings -w -g -m yara_rules/index.yar samples/benign/

# Exercise curated malicious samples to confirm expected hits
yara --fail-on-warnings -w -g -r yara_rules/index.yar samples/malware/

# Compile once to catch issues missed by the CLI run
yarac yara_rules/index.yar /tmp/ruleset.yarac
```

The `samples/benign/` and `samples/malware/` folders should contain your local validation corpus (hash-locked and documented separately). Capture resulting metrics via `triage.sh --file ... --debug` to archive coverage numbers alongside the PR.

**Tuning noisy rules**

* List noisy rule identifiers in `yara_rules/internal/noisy_rules.txt` – matching rules are appended to `triage-noisy.log` during runs.
* Use `yara_rules/internal/overrides.yar` to suppress, alias, or wrap upstream detections without forking the vendor files.
* `triage.sh` accepts `--yara-category <name>` and `--yara-index <path>` to scope scans per family. The generated report surfaces `yara_metrics`, per-family match counts, and noisy-rule telemetry to help analysts decide whether to tune or disable signatures.

## Configurable Variables

Each script exposes configuration variables at the top. Override via environment
variables or inline edits.

| Variable | Default | Description |
|----------|---------|-------------|
| `BASE_IMAGE_PATH` | `/var/lib/libvirt/images/windows10-base.qcow2` | Path to the Windows gold image. |
| `BRIDGE_NAME` | `br-sandbox` | Isolated Linux bridge shared by VM and INetSim. |
| `SAMPLE_DIR` | `./samples` | Local directory containing binaries to analyse. |
| `OUTPUT_DIR` | `./out` | Directory where orchestrator stores evidence. |
| `VM_MEM` / `VM_CPUS` | `4096` / `2` | Resources allocated to the analysis VM. |
| `TIMEOUT_SECONDS` | `120` | Default runtime for dynamic execution. |
| `INETSIM_IMAGE` | `opennic/inetsim` | Container image for INetSim. |
| `TRIAGE_IMAGE` | `sandbox-triage` | Name of the triage container image. |
| `TCPDUMP_ROTATE_SIZE_MB` / `TCPDUMP_FILES` | `50` / `3` | Packet capture rotation policy. |
| `FORCE_NONROOT` | `1` | Refuse to run scripts as UID 0 unless `--allow-root`. |
| `LOCAL_AV_CONFIG` | `./local_av_scanners.json` | JSON file listing local AV scanners executed during triage. |
| `WINRM_PORT` | `5985` | WinRM endpoint inside the guest. |
| `SMB_UPLOAD_DIR` | `Sandbox\Samples` | Destination directory inside the guest for samples. |
| `RESULTS_DIR_GUEST` | `C:\results` | Location collected by `virt-copy-out`. |
| `TIMEOUT_SECONDS` | `120` | Execution timeout passed to `autorun.ps1`. |
| `SUSPICION_THRESHOLD` | `50` | Minimum heuristic score before `triage.sh` marks a sample as suspected. |
| `MAX_DLL_EXPORTS` | `5` | Maximum number of DLL exports suggested/executed automatically. |
| `REPORT_SIGNING_KEY_FILE` | _(unset)_ | Path to a secret key used to compute an HMAC over `final-report.json`. |
| `REPORT_SIGNING_KEY_PASSPHRASE` | _(unset)_ | Optional passphrase concatenated with the key material for signing. |
| `ENABLE_DEBUG_CHANNEL` | `0` | Create a per-run `diagnostics/debug-console.fifo` for live notes and mirror logs to `diagnostics/infrastructure.log`. |
| `CREATE_SUPPORT_BUNDLE` | `0` | Force generation of the support bundle even on successful runs (failures always produce one). |

Additional toggles:

* `./orchestrator.sh --no-triage` – skip the triage JSON requirement.
* `./orchestrator.sh --collect-memory` – force ProcDump collection (off by default for safety).
* `./orchestrator.sh --keep-clone` – retain the cloned QCOW2 for debugging.
* `./orchestrator.sh --support-bundle` – always collect the diagnostics bundle even when the run succeeds.
* `./orchestrator.sh --debug-channel` – expose `diagnostics/debug-console.fifo` to append analyst notes in real time.
* `./orchestrator.sh --dry-run` – print planned actions without executing.
* `./orchestrator.sh --debug` – verbose logging for each command.
* `triage.sh --debug` – embed diagnostic logs in the JSON output.

### Offline “VirusTotal-style” scanning

`triage.sh` can orchestrate several local antivirus or rule-based scanners to
approximate the verdict aggregation provided by VirusTotal, while remaining
fully offline. Provide a JSON configuration either via the
`LOCAL_AV_CONFIG` path (default `./local_av_scanners.json`) or directly through
the `AV_SCANNERS_JSON` environment variable. Each entry must define a `name`
and a command array; occurrences of `{sample}` are replaced with the absolute
path of the binary under analysis.

Example configuration (`local_av_scanners.example.json`):

```json
[
  { "name": "clamav", "cmd": ["clamscan", "--no-summary", "{sample}"] },
  { "name": "loki", "cmd": ["loki", "--quiet", "--intense", "--file", "{sample}"] }
]
```

Place your preferred scanners in the triage container, copy the example to
`local_av_scanners.json`, and the triage report will contain an `av_scans`
array with per-engine return codes and raw output.

### pe-sieve release management

The triage container bundles the upstream [pe-sieve](https://github.com/hasherezade/pe-sieve)
release so that analysts can run memory scans without a live download step.
`triage.Dockerfile` currently pins version **v0.3.5** and verifies the archive
against the expected SHA-256 hash `ddb1292ad410895696b3606d76f0d8b968d88c78c42170c406e73484de5514e0`
before extraction. The Docker build will fail automatically if the checksum does
not match.

When upgrading pe-sieve:

1. Download the desired release asset and compute `sha256sum pe-sieve64.zip` on
   a trusted workstation.
2. Update `PESIEVE_VERSION` and `PESIEVE_SHA256` in `triage.Dockerfile` to match
   the new release.
3. Rebuild the triage image. If the checksum is incorrect the build stops,
   protecting against tampering or CDN corruption.

### Static triage enhancements

The triage pipeline now emits a structured `static_analysis` section populated
via Rizin JSON commands. In addition to global entropy, the report contains
per-section entropy, import/export tables, Authenticode metadata (when
available), and strings/section overviews suitable for offline automation. A
new heuristic scorer synthesises these signals (including suspicious API
imports, timestamp anomalies, overlays, and packer-like entropy) into a
weighted `heuristics.score` and lists the reasons that contributed to the
`suspected` verdict. The script also extracts contextual indicators—URLs,
IPv4s, registry paths—from the combined string set and records recommended
`rundll32` invocations when the sample is a DLL.

`SUSPICION_THRESHOLD` and `MAX_DLL_EXPORTS` can be tuned to adjust the
threshold for heuristic escalation and the number of DLL exports considered.

### DLL-aware execution workflow

`orchestrator.sh` consumes the new triage metadata to decide whether a sample
behaves like a DLL. When it does, the orchestrator passes the suggested export
list to `autorun.ps1`, which in turn executes each export via `rundll32.exe`
with dedicated stdout/stderr logs, module snapshots, and memory dumps. The
final report links static exports to the runtime executions so analysts can see
which entry points ran successfully and which remain pending.

### Dynamic instrumentation and evidence capture

The in-guest automation now performs a comprehensive before/after baseline:

* Captures running processes, services, scheduled tasks, TCP listeners, and key
  autorun registry entries before launching the sample.
* Starts dedicated ETW sessions for process, image, and network providers and
  stops them after execution, saving `*.etl` traces under `results/etw/`.
* Keeps Procmon running in quiet mode and exports both the `.pml` and a CSV
  summary, enabling quick correlations from the host.
* Produces adaptive memory dumps—mid-run, final, and for any detected child
  processes—using ProcDump when available and falling back to the
  `comsvcs.dll` MiniDump entry point.
* Records module inventories for each execution and aggregates child-process
  trees in `autorun-summary.json`.

On the host side, `final-report.json` incorporates these artefacts into a richer
`dynamic` section containing baseline diffs, telemetry summaries, stdout/stderr
previews, and per-execution metadata. The `correlations` block automatically
cross-references static indicators (URLs/IPs/registry paths) with dynamic
observations from Procmon/ETW, highlighting overlaps.

### Chain-of-custody and report signing

Every orchestrated command is logged in `host-commands.log` and summarised in
the final report to strengthen auditability. The canonical report payload is
hashed (`report_integrity.value`) and, if you provide a secret via
`REPORT_SIGNING_KEY_FILE` (and optional `REPORT_SIGNING_KEY_PASSPHRASE`), an
HMAC-SHA256 signature is added as `report_integrity.hmac_sha256`. This allows
teams to notarise reports offline and verify that no artefacts were tampered
with after generation.

### Diagnostics and support bundles

Each run persists a rich diagnostics trail under `<run>/diagnostics/` to help
debug infrastructure issues without re-running the sample:

* `infrastructure.log` captures every `log`/`err` message emitted by the
  orchestrator, while `debug-events.jsonl` stores structured milestones (clone,
  VM start, uploads, report generation).
* `runtime-state.json` records the latest orchestration state (guest IP,
  tcpdump PID, heuristic score) so you can check progression at a glance.
* `support-summary.json` and the optional `support-bundle.tar.gz` contain host
  health snapshots (`virsh`, `docker ps`, bridge info, disk usage). The bundle
  is always produced on failure and can be forced on success with
  `--support-bundle` or `CREATE_SUPPORT_BUNDLE=1`.
* When `--debug-channel` (or `ENABLE_DEBUG_CHANNEL=1`) is set, the orchestrator
  exposes `diagnostics/debug-console.fifo`; writing text to this FIFO (e.g.
  `echo 'note' > diagnostics/debug-console.fifo`) appends analyst notes to the
  log without altering the automation flow.

The final `final-report.json` includes a `diagnostics` section referencing
these artefacts, making it easy to cross-check host telemetry alongside the
static and dynamic evidence.

## Workflow Summary

1. Place a binary in `./samples`.
2. Run triage via the container (`triage.sh`), examine the JSON verdict.
3. If suspicious (or forced), execute `orchestrator.sh --sample <file>`.
4. Inspect `/out/<timestamp>/` for:
   * `final-report.json` – consolidated metadata, static heuristics, dynamic instrumentation summary, correlations, attachments list, and integrity/HMAC details.
   * `artifacts.json` – per-file hashes and sizes (pcaps, Procmon logs, memory dumps).
   * `host-commands.log` – JSONL audit log of commands executed on the host orchestrator.
   * `winrm-exec.json` – raw WinRM execution transcript.
   * Collected guest artefacts (`autorun-summary.json`, `stdout.log`, `procmon.pml`, etc.) and rotated PCAPs.
5. Use `analyse_adapter/adapter.py` to integrate additional tooling outputs as
   required:
   ```bash
   ./analyse_adapter/adapter.py samples/test-safe.exe --output-dir out/analysis --json out/analysis/simba.json
   ```

## Preparing the Gold Image

1. Install Windows updates, Sysinternals Suite (Procmon + ProcDump), and Sysmon if desired.
2. Enable WinRM over HTTP for the sandbox network (`winrm quickconfig`).
3. Install and verify `qemu-guest-agent` so `virsh domifaddr` works.
4. Copy `autorun.ps1` to `C:\autorun\autorun.ps1` and allow script execution (`Set-ExecutionPolicy RemoteSigned`).
5. Create `C:\Sandbox\Samples` and `C:\results` directories with write permissions.
6. Configure Procmon to accept the EULA once manually.
7. Create a Windows scheduled task or startup script if you want autorun to fire automatically; otherwise the orchestrator triggers it through WinRM.

## Security Checklist

- [ ] Always operate on an isolated bridge with no uplinks or NAT.
- [ ] Run scripts as a non-root user unless a flag explicitly allows root.
- [ ] Confirm `qemu-img create -b` clones are deleted after each run (default behaviour).
- [ ] Review `artifacts.json` and `final-report.json` for SHA-256 values before moving artefacts.
- [ ] Configure `REPORT_SIGNING_KEY_FILE` if you require authenticated reports for external sharing.
- [ ] Keep the gold image offline and patch it using a separate workflow.
- [ ] Never mount the base QCOW2 read-write while analyses are running.
- [ ] Validate INetSim logs before trusting dynamic verdicts.

## Load and Stress Testing

1. Launch multiple triage containers to parallelise static analysis (`docker compose up --scale sandbox-triage=3`).
2. Stress-test VM orchestration with short benign samples and reduced timeout (e.g., `TIMEOUT_SECONDS=30`).
3. Use synthetic binaries that trigger YARA rules to verify detection paths.
4. Exercise network capture rotation by increasing `TCPDUMP_FILES` and running long-lived samples.
5. Monitor host CPU/RAM while running sequential analyses to plan capacity.

## Rollback Procedure

1. Stop all containers:
   ```bash
   docker compose down
   ```
2. Destroy leftover VM clones:
   ```bash
   ls ${CLONE_WORKDIR:-/var/lib/libvirt/images} | grep sandbox-
   ```
   Remove manually if any remain.
3. Flush captures and evidence by removing dated directories under `./out/` (verify hashes before deletion).
4. Delete and recreate the Linux bridge if it was misconfigured:
   ```bash
   sudo ip link set br-sandbox down
   sudo ip link del br-sandbox
   ./deploy_test_env.sh --bridge br-sandbox
   ```
5. Restore the gold image from your offline backup if contamination is suspected.

## Troubleshooting

* **WinRM errors** – ensure the guest firewall allows WinRM on the sandbox subnet and that credentials in `orchestrator.sh` match the guest user.
* **`virt-copy-in` fails** – the destination path must exist inside the guest filesystem. Create `C:\sandbox` in the gold image or update `SMB_UPLOAD_DIR`.
* **tcpdump requires sudo** – run `sudo setcap ... tcpdump` as suggested by `deploy_test_env.sh`, or update `TCPDUMP_PRIV_CMD`.
* **pywinrm missing** – install with `pip install pywinrm` on the host running `orchestrator.sh`.
* **High entropy false-positives** – adjust the entropy threshold inside `triage.sh` or override `TRIAGE_TIMEOUT_SECONDS`.

## File Layout

```
├── analyse_adapter/
│   ├── __init__.py
│   └── adapter.py
├── autorun.ps1
├── deploy_test_env.sh
├── docker-compose.yml
├── final-report.example.json
├── final-report.template.json
├── orchestrator.sh
├── triage.Dockerfile
├── triage.sh
├── yara_rules/
│   ├── droppers.yar
│   ├── index.yar
│   ├── injection.yar
│   └── packers.yar
└── ...
```

Test everything with safe samples first and iterate gradually. When in doubt,
run scripts with `--dry-run` and inspect the commands before proceeding.
