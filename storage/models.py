from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid


def _now_iso() -> str:
    """Consistent ISO-8601 timestamp (UTC, seconds precision)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class FileMetadata:
    """
    Describes a file stored in the local vault.

    The `stored_name` is the opaque filename on disk (e.g. ciphertext blob), while
    `filename` is what the user sees and enters in the UI.
    """

    file_id: str
    owner: str
    filename: str
    stored_name: str
    size: int
    created_at: str
    nonce: Optional[str] = None
    tag: Optional[str] = None

    @staticmethod
    def new(
        owner: str,
        filename: str,
        stored_name: str,
        size: int,
        *,
        nonce: Optional[str] = None,
        tag: Optional[str] = None,
    ) -> "FileMetadata":
        return FileMetadata(
            file_id=str(uuid.uuid4()),
            owner=owner,
            filename=filename,
            stored_name=stored_name,
            size=size,
            created_at=_now_iso(),
            nonce=nonce,
            tag=tag,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileMetadata":
        return cls(**data)
