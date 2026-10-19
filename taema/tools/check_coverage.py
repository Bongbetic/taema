#!/usr/bin/env python3
"""Enforce per-module coverage floors from pyproject.toml."""

from __future__ import annotations

import argparse
import json
import sys
import tomllib
from pathlib import Path
from typing import Any


def coverage_violations(
    report: dict[str, Any],
    baseline: dict[str, float],
    minimum_new_percent: float,
) -> list[str]:
    """Return coverage policy violations for a Coverage.py JSON report."""
    files = report.get("files", {})
    violations: list[str] = []

    for path, floor in sorted(baseline.items()):
        entry = files.get(path)
        if entry is None:
            violations.append(
                f"{path}: recorded baseline is missing from coverage report"
            )
            continue
        actual = entry.get("summary", {}).get("percent_covered")
        if actual is None:
            violations.append(f"{path}: coverage report has no percentage")
        elif round(actual) < floor:
            violations.append(
                f"{path}: {actual:.2f}% reports below recorded {floor}% baseline"
            )

    for path, entry in sorted(files.items()):
        if path in baseline:
            continue
        actual = entry.get("summary", {}).get("percent_covered")
        if actual is None:
            violations.append(f"{path}: coverage report has no percentage")
        elif actual + 1e-9 < minimum_new_percent:
            violations.append(
                f"{path}: new module has {actual:.2f}% coverage; "
                f"minimum is {minimum_new_percent:.2f}%"
            )
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("coverage_json", type=Path, help="Coverage.py JSON report")
    parser.add_argument(
        "--config", type=Path, default=Path("pyproject.toml"), help="quality config"
    )
    args = parser.parse_args()

    with args.config.open("rb") as stream:
        config = tomllib.load(stream)
    policy = config["tool"]["taema"]["coverage"]
    with args.coverage_json.open(encoding="utf-8") as stream:
        report = json.load(stream)

    violations = coverage_violations(
        report,
        policy["existing_baseline"],
        policy["minimum_new_percent"],
    )
    if violations:
        print("Coverage policy failed:", file=sys.stderr)
        for violation in violations:
            print(f"- {violation}", file=sys.stderr)
        return 1

    print(
        "Coverage policy passed: existing modules meet baseline; "
        f"new modules meet {policy['minimum_new_percent']:.2f}%"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
