#!/usr/bin/env python3
"""Wrapper utilities for normalising analysisSimba.py output.

The goal is to ensure every run emits a JSON payload that can be
consumed by the orchestrator or other automation tooling.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

DEFAULT_SCRIPT = Path(os.environ.get("ANALYSIS_SIMBA_PATH", "./analysisSimba.py"))


@dataclass
class AnalysisResult:
    tool: str
    script_path: str
    sample: str
    output_dir: str
    return_code: int
    stdout: str
    stderr: str
    generated_at: str
    attachments: List[str]
    extra: Dict[str, str]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


class AnalysisSimbaAdapter:
    """Executes analysisSimba.py and returns a structured payload."""

    def __init__(self, script_path: Path = DEFAULT_SCRIPT):
        self.script_path = Path(script_path)
        if not self.script_path.exists():
            raise FileNotFoundError(f"analysisSimba.py not found at {self.script_path}")

    def run(self, sample: Path, output_dir: Path, extra_args: Optional[List[str]] = None) -> AnalysisResult:
        sample = Path(sample)
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        cmd = [sys.executable, str(self.script_path), str(sample)]
        if extra_args:
            cmd.extend(extra_args)

        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            cwd=output_dir,
        )

        attachments: List[str] = []
        for path in output_dir.rglob("*"):
            if path.is_file():
                attachments.append(str(path.relative_to(output_dir)))

        extra: Dict[str, str] = {}
        # Attempt to parse stdout as JSON if possible
        try:
            parsed = json.loads(proc.stdout)
            if isinstance(parsed, dict):
                extra["stdout_json"] = json.dumps(parsed)
        except json.JSONDecodeError:
            pass

        result = AnalysisResult(
            tool="analysisSimba",
            script_path=str(self.script_path.resolve()),
            sample=str(sample.resolve()),
            output_dir=str(output_dir.resolve()),
            return_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            generated_at=datetime.utcnow().isoformat() + "Z",
            attachments=sorted(attachments),
            extra=extra,
        )
        return result


def run_cli(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="analysisSimba adapter")
    parser.add_argument("sample", type=Path, help="Path to the sample to analyse")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("./analysis-output"),
        help="Directory where analysis artefacts will be stored",
    )
    parser.add_argument(
        "--script",
        type=Path,
        default=DEFAULT_SCRIPT,
        help="Path to analysisSimba.py",
    )
    parser.add_argument(
        "--extra-arg",
        action="append",
        dest="extra_args",
        default=None,
        help="Additional arguments forwarded to analysisSimba.py",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Optional path to write the JSON payload (stdout used if omitted)",
    )

    args = parser.parse_args(argv)

    adapter = AnalysisSimbaAdapter(args.script)
    result = adapter.run(args.sample, args.output_dir, args.extra_args)

    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(result.to_json(), encoding="utf-8")
    else:
        print(result.to_json())

    return 0 if result.return_code == 0 else result.return_code


if __name__ == "__main__":
    sys.exit(run_cli())
