from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

class SimpleHasher:
    def __init__(self):
        self._ph = PasswordHasher()

    def hash(self, password: str) -> str:
        """Create a secure hash for a new password."""
        return self._ph.hash(password)

    def verify(self, stored_hash: str, password: str) -> bool:
        """Check a password attempt against the stored hash."""
        try:
            return self._ph.verify(stored_hash, password)
        except VerifyMismatchError:
            return False
