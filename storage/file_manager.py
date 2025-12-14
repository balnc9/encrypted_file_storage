from pathlib import Path
import base64
import json
import os
import shutil
import sys
import tempfile
from typing import Iterable, Optional, Tuple
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Import signature and PKI functionality
sys.path.insert(0, str(Path(__file__).parent.parent))
from crypto.signatures import sign_data, verify_signature, signature_to_base64, signature_from_base64
from crypto.pki import load_certificate, verify_certificate_signature, extract_public_key_from_cert

from .models import FileMetadata

VAULT_ROOT = Path("vault")

# crypto helpers

def encrypt_bytes_aes_gcm(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypt plaintext with AES-GCM. Returns (ciphertext, nonce, tag).
    AESGCM.encrypt returns ciphertext||tag, so we split the tag for storage.
    """
    if len(key) not in (16, 24, 32):
        raise ValueError("AES-GCM key must be 128/192/256 bits")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext, tag = ct_with_tag[:-16], ct_with_tag[-16:]
    return ciphertext, nonce, tag


def decrypt_bytes_aes_gcm(ciphertext: bytes, nonce: bytes, tag: bytes, key: bytes) -> bytes:
    """
    Decrypt AES-GCM ciphertext given nonce and tag. Raises if authentication fails.
    """
    if len(tag) != 16:
        raise ValueError("GCM tag must be 16 bytes")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


def wrap_key_rsa_oaep(file_key: bytes, public_key_pem: bytes) -> bytes:
    """
    Wrap (encrypt) a symmetric file key with RSA-OAEP using the given PEM public key.
    """
    public_key = serialization.load_pem_public_key(public_key_pem)
    return public_key.encrypt(
        file_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_key_rsa_oaep(wrapped_key: bytes, private_key_pem: bytes) -> bytes:
    """
    Unwrap (decrypt) a symmetric file key with RSA-OAEP using the given PEM private key.
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    return private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# helper methods

def _canon_username(username: str) -> str:
    username = username.strip()
    if not username:
        raise ValueError("username cannot be empty")
    return username.lower()

def _ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path

def _user_dir(username: str, root: Path = VAULT_ROOT) -> Path:
    return _ensure_dir(root / _canon_username(username))

def _index_path(user_dir: Path) -> Path:
    return user_dir / "index.json"

def _load_index(user_dir: Path) -> list[FileMetadata]:
    path = _index_path(user_dir)
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [FileMetadata.from_dict(item) for item in data.get("files", [])]

def _save_index(user_dir: Path, entries: Iterable[FileMetadata]) -> None:
    path = _index_path(user_dir)
    payload = {"files": [entry.to_dict() for entry in entries]}
    fd, tmp = tempfile.mkstemp(prefix="vault.", suffix=".json", dir=str(user_dir))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
        Path(tmp).replace(path)
    finally:
        tmp_path = Path(tmp)
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

def _select_entry(entries: Iterable[FileMetadata], identifier: str) -> Optional[FileMetadata]:
    for entry in entries:
        if entry.file_id == identifier or entry.filename == identifier:
            return entry
    return None

def _default_download_dir(username: str) -> Path:
    base = Path.home() / "Downloads"
    return base / _canon_username(username)

# public operations

def list_files(username: str, *, vault_root: Path = VAULT_ROOT) -> list[FileMetadata]:
    user_dir = _user_dir(username, vault_root)
    entries = _load_index(user_dir)
    return sorted(entries, key=lambda entry: entry.created_at, reverse=True)

def upload_file(
    username: str,
    filepath: str,
    *,
    vault_root: Path = VAULT_ROOT,
    user_public_key_pem: Optional[bytes] = None,
    private_key_pem: Optional[bytes] = None,
    certificate_pem: Optional[bytes] = None,
) -> FileMetadata:
    """
    Upload a file to the vault with encryption and digital signature.
    
    Args:
        username: Username of the file owner
        filepath: Path to the file to upload
        vault_root: Root directory for vault storage
        user_public_key_pem: User's public key for encryption
        private_key_pem: User's private key for signing
        certificate_pem: User's certificate (for signature verification)
    
    Returns:
        FileMetadata entry for the uploaded file
    """
    src = Path(filepath).expanduser()
    if not src.is_file():
        raise FileNotFoundError(f"{filepath} is not a file")

    user_dir = _user_dir(username, vault_root)

    stored_name = f"{uuid.uuid4().hex}{src.suffix or ''}.bin"
    owner = _canon_username(username)
    
    # Read the original file content for signing
    plaintext = src.read_bytes()
    
    # Sign the file if private key is provided
    signature_b64 = None
    signature_algo = None
    signer_cert_b64 = None
    
    if private_key_pem:
        # Sign the original plaintext (before encryption)
        signature = sign_data(plaintext, private_key_pem)
        signature_b64 = signature_to_base64(signature)
        signature_algo = "RSA-PSS-SHA256"
        
        # Include the signer's certificate
        if certificate_pem:
            signer_cert_b64 = base64.b64encode(certificate_pem).decode("ascii")

    if user_public_key_pem:
        # Encrypt file with random key, wrap it, and store ciphertext blob.
        file_key = os.urandom(32)  # AES-256
        ciphertext, nonce, tag = encrypt_bytes_aes_gcm(plaintext, file_key)
        wrapped_key = wrap_key_rsa_oaep(file_key, user_public_key_pem)

        (user_dir / stored_name).write_bytes(ciphertext)
        entry = FileMetadata.new(
            owner=owner,
            filename=src.name,
            stored_name=stored_name,
            size=src.stat().st_size,
            wrapped_key=base64.b64encode(wrapped_key).decode("ascii"),
            wrap_algo="rsa-oaep-sha256",
            nonce=base64.b64encode(nonce).decode("ascii"),
            tag=base64.b64encode(tag).decode("ascii"),
            signature=signature_b64,
            signature_algo=signature_algo,
            signer_cert=signer_cert_b64,
        )
    else:
        # Legacy plaintext storage.
        shutil.copy2(src, user_dir / stored_name)
        entry = FileMetadata.new(
            owner=owner,
            filename=src.name,
            stored_name=stored_name,
            size=src.stat().st_size,
            signature=signature_b64,
            signature_algo=signature_algo,
            signer_cert=signer_cert_b64,
        )

    entries = _load_index(user_dir)
    entries.append(entry)
    _save_index(user_dir, entries)
    return entry

def download_file(
    username: str,
    filename: str,
    dest_dir: Optional[str] = None,
    *,
    vault_root: Path = VAULT_ROOT,
    private_key_pem: Optional[bytes] = None,
    verify_signature: bool = True,
) -> Path:
    """
    Download and decrypt a file from the vault, verifying its digital signature.
    
    Args:
        username: Username of the file owner
        filename: Name or ID of the file to download
        dest_dir: Destination directory (defaults to ~/Downloads/username)
        vault_root: Root directory for vault storage
        private_key_pem: User's private key for decryption
        verify_signature: Whether to verify the file's digital signature
    
    Returns:
        Path to the downloaded file
    
    Raises:
        ValueError: If signature verification fails
    """
    if not filename:
        raise ValueError("filename cannot be empty")

    user_dir = _user_dir(username, vault_root)
    entries = _load_index(user_dir)
    entry = _select_entry(entries, filename)
    
    if not entry:
        raise FileNotFoundError(f"No stored file named '{filename}' for {username}")

    if dest_dir:
        target_dir = _ensure_dir(Path(dest_dir).expanduser())
    else:
        target_dir = _ensure_dir(_default_download_dir(username))

    _ensure_dir(target_dir)
    target_path = target_dir / entry.filename

    source_path = user_dir / entry.stored_name
    if not source_path.exists():
        raise FileNotFoundError(f"Stored blob missing: {source_path}")

    # Decrypt the file if encrypted
    if entry.wrapped_key:
        if not private_key_pem:
            raise ValueError("Private key required to decrypt this file")
        if not entry.nonce or not entry.tag:
            raise ValueError("Missing nonce/tag for encrypted file")
        ciphertext = source_path.read_bytes()
        file_key = unwrap_key_rsa_oaep(
            base64.b64decode(entry.wrapped_key),
            private_key_pem,
        )
        plaintext = decrypt_bytes_aes_gcm(
            ciphertext,
            base64.b64decode(entry.nonce or ""),
            base64.b64decode(entry.tag or ""),
            file_key,
        )
    else:
        plaintext = source_path.read_bytes()

    # Verify digital signature if present and requested
    if verify_signature and entry.signature:
        if not entry.signer_cert:
            raise ValueError("File has signature but no certificate for verification")
        
        # Load the signer's certificate
        cert_pem = base64.b64decode(entry.signer_cert)
        cert = load_certificate(cert_pem)
        
        # Extract public key from certificate
        public_key_pem = extract_public_key_from_cert(cert)
        
        # Verify the certificate is self-signed (or verify with CA if available)
        if not verify_certificate_signature(cert, public_key_pem):
            raise ValueError("Certificate verification failed - certificate is not valid")
        
        # Verify the file signature
        signature = signature_from_base64(entry.signature)
        if not verify_signature(plaintext, signature, public_key_pem):
            raise ValueError(
                "Digital signature verification FAILED! "
                "The file may have been tampered with."
            )
        
        print(f"✓ Digital signature verified successfully for {entry.filename}")
    
    # Write the plaintext to the target location
    target_path.write_bytes(plaintext)
    return target_path
