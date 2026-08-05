"""Data models for file baselines and integrity alerts."""

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class FileRecord:
    """Stores the security-relevant metadata for one monitored file."""

    sha256: str
    size: int
    modified_ns: int

    def to_dict(self) -> dict[str, Any]:
        """Convert this record to a serializable dictionary."""

        return asdict(self)


@dataclass(frozen=True)
class IntegrityAlert:
    """Describes a difference between a trusted baseline and a current scan."""

    change_type: str
    path: str
    severity: str
    risk_score: int
    old_sha256: str | None
    new_sha256: str | None
    mitre_technique: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        """Convert this alert to a serializable dictionary."""

        return asdict(self)
