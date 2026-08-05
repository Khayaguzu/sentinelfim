"""Trusted baseline creation, hashing, storage, and validation."""

import fnmatch
import hashlib
import hmac
import json
import os
from pathlib import Path

from .models import FileRecord

DEFAULT_EXCLUSIONS = [".git/*", "__pycache__/*", "*.pyc", ".venv/*", "venv/*"]


def build_baseline(root: Path, exclusions: list[str] | None = None) -> dict[str, FileRecord]:
    """Hash every eligible file below a root directory with SHA-256."""

    root = root.resolve()
    patterns = DEFAULT_EXCLUSIONS + (exclusions or [])
    records: dict[str, FileRecord] = {}

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue

        relative = path.relative_to(root).as_posix()
        if any(fnmatch.fnmatch(relative, pattern) for pattern in patterns):
            continue

        stat = path.stat()
        records[relative] = FileRecord(_sha256(path), stat.st_size, stat.st_mtime_ns)

    return records


def save_baseline(records: dict[str, FileRecord], path: Path, signing_key: str | None = None) -> None:
    """Store a versioned baseline and optionally protect it with an HMAC signature."""

    payload = {
        "version": 1,
        "algorithm": "sha256",
        "files": {name: record.to_dict() for name, record in sorted(records.items())},
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    document = {"payload": payload, "signature": _sign(canonical, signing_key)}
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")


def load_baseline(path: Path, signing_key: str | None = None) -> dict[str, FileRecord]:
    """Load a baseline and reject invalid versions or signatures."""

    document = json.loads(path.read_text(encoding="utf-8"))
    payload = document.get("payload", {})

    if payload.get("version") != 1 or payload.get("algorithm") != "sha256":
        raise ValueError("Unsupported or invalid baseline format.")

    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    expected = _sign(canonical, signing_key)
    actual = document.get("signature")

    if signing_key and not hmac.compare_digest(actual or "", expected or ""):
        raise ValueError("Baseline signature verification failed.")

    return {name: FileRecord(**record) for name, record in payload["files"].items()}


def _sha256(path: Path) -> str:
    """Calculate a file hash in bounded chunks to support large files safely."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sign(canonical_payload: str, signing_key: str | None) -> str | None:
    """Return an HMAC-SHA256 signature when a key is configured."""

    if not signing_key:
        return None
    return hmac.new(signing_key.encode(), canonical_payload.encode(), hashlib.sha256).hexdigest()


def signing_key_from_environment() -> str | None:
    """Read the optional baseline-signing key without exposing it on the command line."""

    return os.getenv("SENTINELFIM_SIGNING_KEY")
