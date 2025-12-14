from dataclasses import dataclass
from datetime import datetime, timezone
import uuid

@dataclass(frozen=True)
class User:
    # basic account information
    user_id: str
    username: str   # canonical (e.g., lowercased)
    pwd_hash: str
    created_at: str   # ISO8601 "YYYY-MM-DDTHH:MM:SSZ"

    # encryption stuff
    public_key: str
    enc_private_key: str
    enc_private_key_nonce: str
    enc_private_key_salt: str
    key_wrap_version: str = "v1"
    
    # PKI - digital signatures and certificates
    certificate: str = ""  # base64-encoded X.509 certificate (PEM)
    ca_certificate: str = ""  # base64-encoded CA certificate if using PKI

    # constructor
    @staticmethod
    def new(
        username: str,
        pwd_hash: str,
        public_key: str,
        enc_private_key: str,
        enc_private_key_nonce: str,
        enc_private_key_salt: str,
        key_wrap_version: str = "v1",
        certificate: str = "",
        ca_certificate: str = "",
    ) -> "User":
        now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

        return User(
            user_id=str(uuid.uuid4()),
            username=username.lower(),
            pwd_hash=pwd_hash,
            created_at=now,
            public_key=public_key,
            enc_private_key=enc_private_key,
            enc_private_key_nonce=enc_private_key_nonce,
            enc_private_key_salt=enc_private_key_salt,
            key_wrap_version=key_wrap_version,
            certificate=certificate,
            ca_certificate=ca_certificate,
        )
