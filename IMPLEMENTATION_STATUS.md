# Feature Implementation Status

This checklist tracks the high-level enhancements discussed for the sandbox and where they are implemented.

## Chain-of-custody and Host Hygiene
- Evidence integrity (host command logging, report hashing/HMAC, diagnostics bundle) — see `orchestrator.sh` and final report schema updates.
- Tcpdump capability handling without ownership changes — handled in `deploy_test_env.sh`.

## Static Triage Improvements
- Structured Rizin exports (imports/exports/sections/strings/resources/certificates) — collected in `triage.sh`.
- Suspicion heuristics and packer detection — `triage.sh` heuristic scorer.
- Indicator extraction (URLs/IPs/registry/emails) — `triage.sh` indicator builder.
- DLL-specific insights (dependency modules, recommended exports) — `triage.sh` `dll_analysis`.

## Dynamic Analysis Enhancements
- Pre/post host baselines with diffs — `autorun.ps1` snapshots and diff routine.
- ETW + Procmon telemetry capture — `autorun.ps1` session orchestration.
- Adaptive memory dumps (primary, mid-run, children) — `autorun.ps1` memory routines.
- DLL export execution plans with stdout/stderr capture — `autorun.ps1` execution planner.
- Module inventories and process tree tracking — `autorun.ps1` module/child collectors.

## Correlation and Reporting
- Final report includes dynamic telemetry, correlations (network vs static indicators, DLL coverage), and diagnostics references — assembled in `orchestrator.sh` and captured in `final-report.template.json`.
- Artifacts hashed and indexed for evidence tracking — generated in `orchestrator.sh`.

Consult the README for narrative documentation of these capabilities.
