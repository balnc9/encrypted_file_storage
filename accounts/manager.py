import base64
import os
from typing import Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .hashing import SimpleHasher
from .models import User
from .storage import IStorage

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
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=200_000,
        )
        aes_key = kdf.derive(password.encode("utf-8"))

        nonce = os.urandom(12)
        aesgcm = AESGCM(aes_key)
        enc_private_key = aesgcm.encrypt(nonce, private_bytes, None)

        user = User.new(
            username=username_c,
            pwd_hash=pwd_hash,
            public_key=base64.b64encode(public_pem).decode("ascii"),
            enc_private_key=base64.b64encode(enc_private_key).decode("ascii"),
            enc_private_key_nonce=base64.b64encode(nonce).decode("ascii"),
            enc_private_key_salt=base64.b64encode(salt).decode("ascii"),
        )
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
