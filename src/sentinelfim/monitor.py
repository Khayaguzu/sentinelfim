"""File-integrity comparison and risk classification."""

from .models import FileRecord, IntegrityAlert

HIGH_VALUE_NAMES = {".env", "authorized_keys", "passwd", "shadow", "web.config"}
HIGH_VALUE_SUFFIXES = {".exe", ".dll", ".ps1", ".sh", ".service", ".conf", ".ini"}


def compare_baseline(
    trusted: dict[str, FileRecord],
    current: dict[str, FileRecord],
) -> list[IntegrityAlert]:
    """Identify added, modified, and deleted files, ordered by risk."""

    alerts: list[IntegrityAlert] = []
    trusted_paths = set(trusted)
    current_paths = set(current)

    for path in sorted(current_paths - trusted_paths):
        alerts.append(_alert("ADDED", path, None, current[path].sha256))

    for path in sorted(trusted_paths - current_paths):
        alerts.append(_alert("DELETED", path, trusted[path].sha256, None))

    for path in sorted(trusted_paths & current_paths):
        if trusted[path].sha256 != current[path].sha256:
            alerts.append(_alert("MODIFIED", path, trusted[path].sha256, current[path].sha256))

    return sorted(alerts, key=lambda alert: (-alert.risk_score, alert.path))


def _alert(change_type: str, path: str, old_hash: str | None, new_hash: str | None) -> IntegrityAlert:
    """Create a contextual alert using the file type and change category."""

    sensitive = _is_high_value(path)
    scores = {
        "ADDED": 85 if sensitive else 55,
        "MODIFIED": 90 if sensitive else 70,
        "DELETED": 88 if sensitive else 65,
    }
    score = scores[change_type]
    severity = "CRITICAL" if score >= 90 else "HIGH" if score >= 80 else "MEDIUM"
    actions = {
        "ADDED": "Validate the file origin, scan it, and isolate the host if unauthorized.",
        "MODIFIED": "Compare with the approved version, investigate the responsible process, and restore if unauthorized.",
        "DELETED": "Confirm the deletion, review audit logs, and restore the trusted file when required.",
    }

    return IntegrityAlert(
        change_type,
        path,
        severity,
        score,
        old_hash,
        new_hash,
        "T1565.001 Stored Data Manipulation",
        actions[change_type],
    )


def _is_high_value(path: str) -> bool:
    """Identify configuration, credential, script, and executable files."""

    lowered = path.lower()
    name = lowered.rsplit("/", 1)[-1]
    return name in HIGH_VALUE_NAMES or any(lowered.endswith(suffix) for suffix in HIGH_VALUE_SUFFIXES)
