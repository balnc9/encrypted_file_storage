"""
Digital Signature Module

Implements RSA-PSS signatures for file integrity and authenticity.
Uses SHA-256 for hashing and PSS padding for signatures.
"""

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
import base64
from typing import Tuple


def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Sign data using RSA-PSS with SHA-256.
    
    Args:
        data: The raw bytes to sign (typically file content)
        private_key_pem: PEM-encoded RSA private key
        
    Returns:
        The signature bytes
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verify an RSA-PSS signature.
    
    Args:
        data: The original data that was signed
        signature: The signature to verify
        public_key_pem: PEM-encoded RSA public key of the signer
        
    Returns:
        True if signature is valid, False otherwise
    """
    public_key = serialization.load_pem_public_key(public_key_pem)
    
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False


def sign_data_b64(data: bytes, private_key_pem: bytes) -> str:
    """Sign data and return base64-encoded signature."""
    sig = sign_data(data, private_key_pem)
    return base64.b64encode(sig).decode("ascii")


def verify_signature_b64(data: bytes, signature_b64: str, public_key_pem: bytes) -> bool:
    """Verify a base64-encoded signature."""
    sig = base64.b64decode(signature_b64)
    return verify_signature(data, sig, public_key_pem)


def compute_file_hash(data: bytes) -> bytes:
    """Compute SHA-256 hash of file data."""
    from cryptography.hazmat.primitives.hashes import Hash, SHA256
    digest = Hash(SHA256())
    digest.update(data)
    return digest.finalize()


def compute_file_hash_b64(data: bytes) -> str:
    """Compute SHA-256 hash and return base64-encoded."""
    return base64.b64encode(compute_file_hash(data)).decode("ascii")

