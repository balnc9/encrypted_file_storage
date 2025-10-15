from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
from .models import User
import json, os, tempfile

class IStorage(ABC):
    @abstractmethod
    def get_user_by_username(self, username: str) -> Optional[User]: ...
    @abstractmethod
    def save_user(self, user: User) -> None: ...

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
                return User(**u)
        return None

    def save_user(self, user: User) -> None:
        data = self._load()
        if any(u["username"] == user.username for u in data["users"]):
            raise ValueError("username already exists")
        data["users"].append(user.__dict__)
        self._save(data)