from typing import Optional
from .models import User
from .storage import IStorage
from .hashing import SimpleHasher

class AccountManager:
    def __init__(self, storage: IStorage, hasher: SimpleHasher):
        self.storage = storage
        self.hasher = hasher

    @staticmethod
    def _canon(username: str) -> str:
        return username.strip().lower()

    def register(self, username: str, password: str) -> User:
        username_c = self._canon(username)
        if self.storage.get_user_by_username(username_c):
            raise ValueError("Username already taken.")
        pwd_hash = self.hasher.hash(password)
        user = User.new(username=username_c, pwd_hash=pwd_hash)
        self.storage.save_user(user)
        return user

    def authenticate(self, username: str, password: str) -> Optional[User]:
        username_c = self._canon(username)
        user = self.storage.get_user_by_username(username_c)
        if not user:
            return None
        if not self.hasher.verify(user.pwd_hash, password):
            return None
        return user
