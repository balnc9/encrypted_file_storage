from __future__ import annotations

from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import uuid


def _now_iso() -> str:
    """Consistent ISO-8601 timestamp (UTC, seconds precision)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class RecipientKey:
    """
    Wrapped encryption key for a specific recipient.
    Allows multi-recipient encryption where each authorized user
    can decrypt the file using their own private key.
    """
    username: str
    wrapped_key: str  # base64-encoded RSA-OAEP wrapped AES key
    
    def to_dict(self) -> Dict[str, str]:
        return {"username": self.username, "wrapped_key": self.wrapped_key}
    
    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "RecipientKey":
        return cls(username=data["username"], wrapped_key=data["wrapped_key"])


@dataclass
class FileMetadata:
    """
    Describes a file stored in the local vault.

    The `stored_name` is the opaque filename on disk (e.g. ciphertext blob), while
    `filename` is what the user sees and enters in the UI.
    
    Digital Signatures:
    - `signature`: RSA-PSS signature of the original plaintext (base64)
    - `signer`: username of who signed the file
    - `file_hash`: SHA-256 hash of original plaintext (base64)
    
    Multi-recipient encryption:
    - `recipient_keys`: List of wrapped keys for each authorized recipient
    """

    file_id: str
    owner: str
    filename: str
    stored_name: str
    size: int
    created_at: str
    
    # Encryption metadata (legacy single-recipient)
    wrapped_key: Optional[str] = None
    wrap_algo: Optional[str] = None
    nonce: Optional[str] = None
    tag: Optional[str] = None
    
    # Digital signature
    signature: Optional[str] = None
    signer: Optional[str] = None
    file_hash: Optional[str] = None
    
    # Multi-recipient encryption
    recipient_keys: List[RecipientKey] = field(default_factory=list)
    
    # File sharing
    shared_with: List[str] = field(default_factory=list)

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
        signer: Optional[str] = None,
        file_hash: Optional[str] = None,
        recipient_keys: Optional[List[RecipientKey]] = None,
        shared_with: Optional[List[str]] = None,
    ) -> "FileMetadata":
        return FileMetadata(
            file_id=str(uuid.uuid4()),
            owner=owner,
            filename=filename,
            stored_name=stored_name,
            size=size,
            created_at=_now_iso(),
            # crypto stuff
            wrapped_key=wrapped_key,
            wrap_algo=wrap_algo,
            nonce=nonce,
            tag=tag,
            # digital signature
            signature=signature,
            signer=signer,
            file_hash=file_hash,
            # multi-recipient
            recipient_keys=recipient_keys or [],
            shared_with=shared_with or [],
        )

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # Convert RecipientKey objects to dicts
        d["recipient_keys"] = [rk if isinstance(rk, dict) else rk for rk in d["recipient_keys"]]
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FileMetadata":
        recipient_keys = [
            RecipientKey.from_dict(rk) if isinstance(rk, dict) else rk
            for rk in data.get("recipient_keys", [])
        ]
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
            signer=data.get("signer"),
            file_hash=data.get("file_hash"),
            recipient_keys=recipient_keys,
            shared_with=data.get("shared_with", []),
        )
    
    def get_wrapped_key_for_user(self, username: str) -> Optional[str]:
        """Get the wrapped key for a specific user from recipient_keys."""
        username_lower = username.lower()
        for rk in self.recipient_keys:
            if rk.username.lower() == username_lower:
                return rk.wrapped_key
        # Fallback to legacy wrapped_key if owner matches
        if self.owner.lower() == username_lower and self.wrapped_key:
            return self.wrapped_key
        return None
    
    def can_access(self, username: str) -> bool:
        """Check if a user can access this file."""
        username_lower = username.lower()
        if self.owner.lower() == username_lower:
            return True
        if username_lower in [u.lower() for u in self.shared_with]:
            return True
        if any(rk.username.lower() == username_lower for rk in self.recipient_keys):
            return True
        return False
