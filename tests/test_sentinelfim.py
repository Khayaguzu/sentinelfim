"""Automated tests for baselines, signatures, and integrity alerts."""

import tempfile
import unittest
from pathlib import Path

from sentinelfim.baseline import build_baseline, load_baseline, save_baseline
from sentinelfim.monitor import compare_baseline


class SentinelFIMTests(unittest.TestCase):
    """Verify the security-relevant monitoring behaviours."""

    def test_detects_added_modified_and_deleted_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "modified.txt").write_text("trusted", encoding="utf-8")
            (root / "deleted.txt").write_text("trusted", encoding="utf-8")
            baseline = build_baseline(root)

            (root / "modified.txt").write_text("tampered", encoding="utf-8")
            (root / "deleted.txt").unlink()
            (root / "added.txt").write_text("unexpected", encoding="utf-8")
            alerts = compare_baseline(baseline, build_baseline(root))

        self.assertEqual({"ADDED", "MODIFIED", "DELETED"}, {alert.change_type for alert in alerts})

    def test_unchanged_files_produce_no_alerts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.txt").write_text("unchanged", encoding="utf-8")
            baseline = build_baseline(root)
            self.assertEqual([], compare_baseline(baseline, build_baseline(root)))

    def test_high_value_file_receives_higher_risk(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "startup.ps1").write_text("safe", encoding="utf-8")
            baseline = build_baseline(root)
            (root / "startup.ps1").write_text("changed", encoding="utf-8")
            alert = compare_baseline(baseline, build_baseline(root))[0]
        self.assertEqual("CRITICAL", alert.severity)

    def test_signed_baseline_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            monitored = root / "monitored"
            monitored.mkdir()
            (monitored / "safe.txt").write_text("safe", encoding="utf-8")
            baseline_path = root / "baseline.json"
            save_baseline(build_baseline(monitored), baseline_path, "test-secret")
            content = baseline_path.read_text(encoding="utf-8").replace("safe.txt", "evil.txt")
            baseline_path.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "signature"):
                load_baseline(baseline_path, "test-secret")

    def test_exclusions_are_not_monitored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "ignored.log").write_text("temporary", encoding="utf-8")
            self.assertEqual({}, build_baseline(root, ["*.log"]))


if __name__ == "__main__":
    unittest.main()
