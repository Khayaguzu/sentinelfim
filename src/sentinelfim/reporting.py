"""Human-readable and JSON integrity alert reporting."""

import json
from pathlib import Path

from .models import IntegrityAlert


def print_summary(alerts: list[IntegrityAlert]) -> None:
    """Print a compact terminal summary for a security analyst."""

    if not alerts:
        print("Integrity check passed: no changes detected.")
        return

    print(f"Detected {len(alerts)} integrity change(s)\n")
    print(f"{'SEVERITY':<10} {'RISK':<6} {'CHANGE':<10} PATH")
    print("-" * 75)
    for alert in alerts:
        print(f"{alert.severity:<10} {alert.risk_score:<6} {alert.change_type:<10} {alert.path}")


def write_report(alerts: list[IntegrityAlert], path: Path) -> None:
    """Export structured findings for automation or SIEM ingestion."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps([alert.to_dict() for alert in alerts], indent=2), encoding="utf-8")
