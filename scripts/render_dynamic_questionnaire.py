#!/usr/bin/env python3
import argparse
import json
from pathlib import Path


def load_json(path: Path):
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def get(obj, path, default=None):
    cur = obj
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def yes_no(b):
    return "Oui" if b else "Non"


def main():
    ap = argparse.ArgumentParser(description="Render dynamic-analysis questionnaire markdown from qualification artifacts")
    ap.add_argument("--summary", required=True, help="Path to qualification-summary.json")
    ap.add_argument("--out", required=True, help="Output markdown path")
    args = ap.parse_args()

    summary = load_json(Path(args.summary))
    cov = get(summary, ["dynamic_minimum_coverage", "items"], {}) or {}
    dyn = get(summary, ["dynamic"], {}) or {}
    infra = get(summary, ["infrastructure"], {}) or {}

    lines = []
    lines.append("# Questionnaire d'analyse dynamique (auto-généré)")
    lines.append("")
    lines.append(f"- Sample: {get(summary, ['sample', 'path'], 'n/a')}")
    lines.append(f"- Dynamic exécuté: {yes_no(get(dyn, ['executed'], False))}")
    lines.append(f"- Verdict dynamique: {get(dyn, ['verdict'], 'n/a')}")
    lines.append(f"- Infra opérationnelle: {yes_no(get(infra, ['overall_operational'], False))}")
    blockers = get(infra, ["blockers"], []) or []
    lines.append(f"- Bloquants: {', '.join(blockers) if blockers else 'aucun'}")
    lines.append("")

    lines.append("## Couverture minimale")
    for key in [
        "phase1_install_prerequisites",
        "phase1_install_network",
        "phase1_install_files_registry",
        "phase1_install_process_services",
        "phase2_behavioral_use_cases",
        "phase2_runtime_network",
        "phase2_runtime_files_registry",
        "phase2_runtime_process_services_dlls",
    ]:
        item = cov.get(key, {})
        supported = bool(item.get("supported", False))
        src = item.get("source", "n/a")
        lines.append(f"- {key}: {'OK' if supported else 'NON COUVERT'} (source: {src})")

    lines.append("")
    lines.append("## Détails utiles déjà disponibles")
    lines.append(f"- Baseline diff présent: {yes_no(bool(get(dyn, ['baseline_diff'], {})))}")
    lines.append(f"- Process tree présent: {yes_no(bool(get(dyn, ['process_tree'], [])))}")
    lines.append(f"- Module snapshots présents: {yes_no(bool(get(dyn, ['module_snapshots'], [])))}")
    lines.append(f"- Télémetrie réseau présente: {yes_no(bool(get(dyn, ['telemetry', 'network'], {})))}")
    lines.append(f"- Exécutions/cas d'usage présents: {yes_no(bool(get(dyn, ['executions'], [])))}")

    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
