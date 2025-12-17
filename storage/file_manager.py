from pathlib import Path
import base64
import json
import os
import shutil
import tempfile
from typing import Iterable, List, Optional, Tuple, Dict
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .models import FileMetadata, RecipientKey
from crypto.signatures import sign_data_b64, verify_signature_b64, compute_file_hash_b64

VAULT_ROOT = Path("vault")


# ============================================================================
# Crypto helpers
# ============================================================================

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


# ============================================================================
# Helper methods
# ============================================================================

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


def _load_index(user_dir: Path) -> List[FileMetadata]:
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


# ============================================================================
# Public operations
# ============================================================================

def list_files(username: str, *, vault_root: Path = VAULT_ROOT) -> List[FileMetadata]:
    """List all files accessible to a user (owned or shared)."""
    user_dir = _user_dir(username, vault_root)
    entries = _load_index(user_dir)
    return sorted(entries, key=lambda entry: entry.created_at, reverse=True)


def list_shared_files(username: str, *, vault_root: Path = VAULT_ROOT) -> List[FileMetadata]:
    """
    List files that have been shared with this user by others.
    Scans all user vaults for files shared with this username.
    """
    username_c = _canon_username(username)
    shared_files = []
    
    if not vault_root.exists():
        return shared_files
    
    for user_folder in vault_root.iterdir():
        if not user_folder.is_dir():
            continue
        if user_folder.name == username_c:
            continue  # Skip own files
        
        entries = _load_index(user_folder)
        for entry in entries:
            if entry.can_access(username_c):
                shared_files.append(entry)
    
    return sorted(shared_files, key=lambda e: e.created_at, reverse=True)


def upload_file(
    username: str,
    filepath: str,
    *,
    vault_root: Path = VAULT_ROOT,
    user_public_key_pem: Optional[bytes] = None,
    user_private_key_pem: Optional[bytes] = None,
    share_with_public_keys: Optional[Dict[str, bytes]] = None,
) -> FileMetadata:
    """
    Upload and encrypt a file.
    
    Args:
        username: The uploading user's username
        filepath: Path to the file to upload
        vault_root: Root directory for the vault
        user_public_key_pem: User's public key for encryption
        user_private_key_pem: User's private key for signing (optional)
        share_with_public_keys: Dict of {username: public_key_pem} for sharing
        
    Returns:
        FileMetadata for the uploaded file
    """
    src = Path(filepath).expanduser()
    if not src.is_file():
        raise FileNotFoundError(f"{filepath} is not a file")

    user_dir = _user_dir(username, vault_root)
    stored_name = f"{uuid.uuid4().hex}{src.suffix or ''}.bin"
    owner = _canon_username(username)
    plaintext = src.read_bytes()

    # Initialize metadata fields
    signature = None
    file_hash = None
    signer = None
    recipient_keys: List[RecipientKey] = []
    wrapped_key = None
    nonce_b64 = None
    tag_b64 = None

    if user_public_key_pem:
        # Generate random AES-256 file key
        file_key = os.urandom(32)
        
        # Encrypt file with AES-GCM
        ciphertext, nonce, tag = encrypt_bytes_aes_gcm(plaintext, file_key)
        
        # Compute file hash for integrity verification
        file_hash = compute_file_hash_b64(plaintext)
        
        # Sign the file if private key provided
        if user_private_key_pem:
            signature = sign_data_b64(plaintext, user_private_key_pem)
            signer = owner
        
        # Wrap key for owner
        wrapped_owner_key = wrap_key_rsa_oaep(file_key, user_public_key_pem)
        recipient_keys.append(RecipientKey(
            username=owner,
            wrapped_key=base64.b64encode(wrapped_owner_key).decode("ascii")
        ))
        
        # Wrap key for each additional recipient
        shared_with = []
        if share_with_public_keys:
            for share_username, share_pub_key in share_with_public_keys.items():
                share_username_c = _canon_username(share_username)
                if share_username_c == owner:
                    continue  # Already added owner
                wrapped_share_key = wrap_key_rsa_oaep(file_key, share_pub_key)
                recipient_keys.append(RecipientKey(
                    username=share_username_c,
                    wrapped_key=base64.b64encode(wrapped_share_key).decode("ascii")
                ))
                shared_with.append(share_username_c)
        
        # Store ciphertext
        (user_dir / stored_name).write_bytes(ciphertext)
        
        # For backwards compatibility, also store owner's wrapped key in legacy field
        wrapped_key = base64.b64encode(wrapped_owner_key).decode("ascii")
        nonce_b64 = base64.b64encode(nonce).decode("ascii")
        tag_b64 = base64.b64encode(tag).decode("ascii")
        
        entry = FileMetadata.new(
            owner=owner,
            filename=src.name,
            stored_name=stored_name,
            size=src.stat().st_size,
            wrapped_key=wrapped_key,
            wrap_algo="rsa-oaep-sha256",
            nonce=nonce_b64,
            tag=tag_b64,
            signature=signature,
            signer=signer,
            file_hash=file_hash,
            recipient_keys=recipient_keys,
            shared_with=shared_with,
        )
    else:
        # Legacy plaintext storage (not recommended)
        shutil.copy2(src, user_dir / stored_name)
        entry = FileMetadata.new(
            owner=owner,
            filename=src.name,
            stored_name=stored_name,
            size=src.stat().st_size,
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
    verify_signature_with_public_key: Optional[bytes] = None,
) -> Tuple[Path, bool, Optional[str]]:
    """
    Download and decrypt a file.
    
    Args:
        username: The downloading user's username
        filename: Filename or file_id to download
        dest_dir: Destination directory (default: ~/Downloads/{username})
        vault_root: Root directory for the vault
        private_key_pem: User's private key for decryption
        verify_signature_with_public_key: Public key of signer to verify signature
        
    Returns:
        Tuple of (target_path, signature_valid, signature_message)
    """
    if not filename:
        raise ValueError("filename cannot be empty")

    username_c = _canon_username(username)
    
    # First check user's own vault
    user_dir = _user_dir(username, vault_root)
    entries = _load_index(user_dir)
    entry = _select_entry(entries, filename)
    source_dir = user_dir
    
    # If not found, check shared files from other users
    if not entry:
        for user_folder in vault_root.iterdir():
            if not user_folder.is_dir():
                continue
            folder_entries = _load_index(user_folder)
            for e in folder_entries:
                if (e.filename == filename or e.file_id == filename) and e.can_access(username_c):
                    entry = e
                    source_dir = user_folder
                    break
            if entry:
                break
    
    if not entry:
        raise FileNotFoundError(f"No accessible file named '{filename}' for {username}")

    # Set up destination
    if dest_dir:
        target_dir = _ensure_dir(Path(dest_dir).expanduser())
    else:
        target_dir = _ensure_dir(_default_download_dir(username))
    target_path = target_dir / entry.filename

    source_path = source_dir / entry.stored_name
    if not source_path.exists():
        raise FileNotFoundError(f"Stored blob missing: {source_path}")

    signature_valid = None
    signature_message = None

    # Decrypt if encrypted
    if entry.wrapped_key or entry.recipient_keys:
        if not private_key_pem:
            raise ValueError("Private key required to decrypt this file")
        if not entry.nonce or not entry.tag:
            raise ValueError("Missing nonce/tag for encrypted file")
        
        # Get the wrapped key for this user
        wrapped_key_b64 = entry.get_wrapped_key_for_user(username_c)
        if not wrapped_key_b64:
            raise ValueError(f"No decryption key available for user {username}")
        
        ciphertext = source_path.read_bytes()
        file_key = unwrap_key_rsa_oaep(
            base64.b64decode(wrapped_key_b64),
            private_key_pem,
        )
        plaintext = decrypt_bytes_aes_gcm(
            ciphertext,
            base64.b64decode(entry.nonce),
            base64.b64decode(entry.tag),
            file_key,
        )
        
        # Verify signature if present
        if entry.signature and verify_signature_with_public_key:
            signature_valid = verify_signature_b64(
                plaintext, 
                entry.signature, 
                verify_signature_with_public_key
            )
            if signature_valid:
                signature_message = f"Signature verified: File was signed by {entry.signer}"
            else:
                signature_message = "WARNING: Signature verification FAILED! File may be tampered."
        elif entry.signature:
            signature_message = f"File is signed by {entry.signer} (verification key not provided)"
        
        # Verify file hash if present
        if entry.file_hash:
            computed_hash = compute_file_hash_b64(plaintext)
            if computed_hash != entry.file_hash:
                raise ValueError("File integrity check failed! Hash mismatch.")
        
        target_path.write_bytes(plaintext)
    else:
        # Legacy unencrypted file
        shutil.copy2(source_path, target_path)

    return target_path, signature_valid, signature_message


def share_file(
    owner_username: str,
    filename: str,
    share_with_username: str,
    share_with_public_key_pem: bytes,
    owner_private_key_pem: bytes,
    *,
    vault_root: Path = VAULT_ROOT,
) -> FileMetadata:
    """
    Share an existing encrypted file with another user.
    
    This unwraps the file key with the owner's private key and re-wraps it
    for the recipient's public key, allowing them to decrypt the file.
    """
    owner_c = _canon_username(owner_username)
    share_c = _canon_username(share_with_username)
    
    user_dir = _user_dir(owner_username, vault_root)
    entries = _load_index(user_dir)
    entry = _select_entry(entries, filename)
    
    if not entry:
        raise FileNotFoundError(f"No file named '{filename}' found for {owner_username}")
    
    if entry.owner != owner_c:
        raise ValueError("Only the owner can share a file")
    
    # Check if already shared
    if share_c in [u.lower() for u in entry.shared_with]:
        raise ValueError(f"File already shared with {share_with_username}")
    
    # Get owner's wrapped key
    owner_wrapped_key = entry.get_wrapped_key_for_user(owner_c)
    if not owner_wrapped_key:
        raise ValueError("No wrapped key found for owner")
    
    # Unwrap with owner's private key
    file_key = unwrap_key_rsa_oaep(
        base64.b64decode(owner_wrapped_key),
        owner_private_key_pem
    )
    
    # Wrap for recipient
    wrapped_for_recipient = wrap_key_rsa_oaep(file_key, share_with_public_key_pem)
    
    # Update entry
    entry.recipient_keys.append(RecipientKey(
        username=share_c,
        wrapped_key=base64.b64encode(wrapped_for_recipient).decode("ascii")
    ))
    entry.shared_with.append(share_c)
    
    # Save updated index
    _save_index(user_dir, entries)
    return entry


def delete_file(
    username: str,
    filename: str,
    *,
    vault_root: Path = VAULT_ROOT,
) -> bool:
    """Delete a file from the vault. Only the owner can delete."""
    username_c = _canon_username(username)
    user_dir = _user_dir(username, vault_root)
    entries = _load_index(user_dir)
    entry = _select_entry(entries, filename)
    
    if not entry:
        return False
    
    if entry.owner != username_c:
        raise ValueError("Only the owner can delete a file")
    
    # Delete the stored file
    stored_path = user_dir / entry.stored_name
    if stored_path.exists():
        stored_path.unlink()
    
    # Remove from index
    entries = [e for e in entries if e.file_id != entry.file_id]
    _save_index(user_dir, entries)
    return True
