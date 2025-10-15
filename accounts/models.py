from dataclasses import dataclass
from datetime import datetime, timezone
import uuid

@dataclass(frozen=True)
class User:
    user_id: str
    username: str   # canonical (e.g., lowercased)
    pwd_hash: str
    created_at: str   # ISO8601 "YYYY-MM-DDTHH:MM:SSZ"

    @staticmethod
    def new(username: str, pwd_hash: str) -> "User":
        now = now = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")

        return User(
            user_id=str(uuid.uuid4()),
            username=username,
            pwd_hash=pwd_hash,
            created_at=now,
        )