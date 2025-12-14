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
    wrapped_key: Optional[str] = None
    wrap_algo: Optional[str] = None
    nonce: Optional[str] = None
    tag: Optional[str] = None
    # Digital signature fields
    signature: Optional[str] = None  # base64-encoded signature of file content
    signature_algo: Optional[str] = None  # e.g., "RSA-PSS-SHA256"
    signer_cert: Optional[str] = None  # base64-encoded signer's certificate

    @staticmethod
    def new(
        owner: str,
        filename: str,
        stored_name: str,
        size: int,
        *,
        wrapped_key: Optional[str] = None,
        wrap_algo: Optional[str] = None,
        nonce: Optional[str] = None,
        tag: Optional[str] = None,
        signature: Optional[str] = None,
        signature_algo: Optional[str] = None,
        signer_cert: Optional[str] = None,
    ) -> "FileMetadata":
        return FileMetadata(
            file_id=str(uuid.uuid4()),
            owner=owner,
            filename=filename,
            stored_name=stored_name,
            size=size,
            created_at=_now_iso(),
            #crypto stuff
            wrapped_key=wrapped_key,
            wrap_algo=wrap_algo,
            nonce=nonce,
            tag=tag,
            # digital signature stuff
            signature=signature,
            signature_algo=signature_algo,
            signer_cert=signer_cert,
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileMetadata":
        return cls(
            file_id=data["file_id"],
            owner=data["owner"],
            filename=data["filename"],
            stored_name=data["stored_name"],
            size=data["size"],
            created_at=data["created_at"],
            wrapped_key=data.get("wrapped_key"),
            wrap_algo=data.get("wrap_algo"),
            nonce=data.get("nonce"),
            tag=data.get("tag"),
            signature=data.get("signature"),
            signature_algo=data.get("signature_algo"),
            signer_cert=data.get("signer_cert"),
        )
