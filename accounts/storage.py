from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from dataclasses import fields
from .models import User
import json, os, tempfile

# Get valid field names from User dataclass
_USER_FIELDS = {f.name for f in fields(User)}

def _make_user(data: Dict[str, Any]) -> User:
    """Create a User from dict, filtering out unknown fields for backwards compatibility."""
    filtered = {k: v for k, v in data.items() if k in _USER_FIELDS}
    return User(**filtered)

class IStorage(ABC):
    @abstractmethod
    def get_user_by_username(self, username: str) -> Optional[User]: ...
    @abstractmethod
    def save_user(self, user: User) -> None: ...
    @abstractmethod
    def get_all_users(self) -> List[User]: ...

class JSONStorage(IStorage):
    def __init__(self, path: str = "users.json"):
        self.path = path
        if not os.path.exists(self.path):
            with open(self.path, "w") as f:
                json.dump({"users": []}, f)

    def _load(self) -> Dict[str, Any]:
        with open(self.path, "r") as f:
            return json.load(f)

    def _save(self, data: Dict[str, Any]) -> None:
        # atomic-ish write to avoid corruption
        fd, tmp = tempfile.mkstemp(prefix="users.", suffix=".tmp", dir=os.path.dirname(self.path) or ".")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self.path)
        finally:
            if os.path.exists(tmp):
                try: os.remove(tmp)
                except OSError: pass

    def get_user_by_username(self, username: str) -> Optional[User]:
        data = self._load()
        for u in data["users"]:
            if u["username"] == username:
                return _make_user(u)
        return None

    def save_user(self, user: User) -> None:
        data = self._load()
        if any(u["username"] == user.username for u in data["users"]):
            raise ValueError("username already exists")
        data["users"].append(user.__dict__)
        self._save(data)

    def get_all_users(self) -> List[User]:
        data = self._load()
        return [_make_user(u) for u in data["users"]]