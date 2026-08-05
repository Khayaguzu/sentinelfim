"""Command-line interface for baseline and integrity-check workflows."""

import argparse
from pathlib import Path

from .baseline import build_baseline, load_baseline, save_baseline, signing_key_from_environment
from .monitor import compare_baseline
from .reporting import print_summary, write_report


def build_parser() -> argparse.ArgumentParser:
    """Define explicit baseline and check subcommands."""

    parser = argparse.ArgumentParser(description="Detect unauthorized file changes with SHA-256 baselines.")
    subcommands = parser.add_subparsers(dest="command", required=True)

    baseline = subcommands.add_parser("baseline", help="Create or replace a trusted baseline.")
    baseline.add_argument("root", type=Path, help="Directory to monitor.")
    baseline.add_argument("--output", type=Path, default=Path("baseline.json"))
    baseline.add_argument("--exclude", action="append", default=[], help="Additional glob exclusion.")

    check = subcommands.add_parser("check", help="Compare files with a trusted baseline.")
    check.add_argument("root", type=Path, help="Directory to monitor.")
    check.add_argument("--baseline", type=Path, default=Path("baseline.json"))
    check.add_argument("--report", type=Path, default=Path("reports/integrity-alerts.json"))
    check.add_argument("--exclude", action="append", default=[], help="Additional glob exclusion.")
    return parser


def main() -> int:
    """Create baselines or check monitored files for unauthorized changes."""

    args = build_parser().parse_args()
    key = signing_key_from_environment()

    try:
        if args.command == "baseline":
            records = build_baseline(args.root, args.exclude)
            save_baseline(records, args.output, key)
            print(f"Baseline created for {len(records)} file(s): {args.output}")
            return 0

        trusted = load_baseline(args.baseline, key)
        current = build_baseline(args.root, args.exclude)
        alerts = compare_baseline(trusted, current)
        print_summary(alerts)
        write_report(alerts, args.report)
        return 2 if alerts else 0
    except (OSError, ValueError) as error:
        print(f"SentinelFIM failed: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
