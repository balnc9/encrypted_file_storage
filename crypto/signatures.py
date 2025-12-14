"""
Digital signature functionality using RSA with PSS padding.
Implements signing and verification as per the lab requirements.
"""
import base64
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """
    Sign data using RSA private key with PSS padding and SHA256.
    
    Args:
        data: The bytes to sign
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
    Verify a signature using RSA public key.
    
    Args:
        data: The original data that was signed
        signature: The signature to verify
        public_key_pem: PEM-encoded RSA public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem)
        
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
    except Exception:
        return False


def sign_file(filepath: str, private_key_pem: bytes) -> bytes:
    """
    Sign a file's contents.
    
    Args:
        filepath: Path to the file to sign
        private_key_pem: PEM-encoded RSA private key
    
    Returns:
        The signature bytes
    """
    data = Path(filepath).read_bytes()
    return sign_data(data, private_key_pem)


def verify_file_signature(filepath: str, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verify a file's signature.
    
    Args:
        filepath: Path to the file
        signature: The signature to verify
        public_key_pem: PEM-encoded RSA public key
    
    Returns:
        True if signature is valid, False otherwise
    """
    data = Path(filepath).read_bytes()
    return verify_signature(data, signature, public_key_pem)


def save_signature(signature: bytes, output_path: str) -> None:
    """
    Save a signature to a file in binary mode.
    
    Args:
        signature: The signature bytes
        output_path: Where to save the signature
    """
    Path(output_path).write_bytes(signature)


def load_signature(signature_path: str) -> bytes:
    """
    Load a signature from a file.
    
    Args:
        signature_path: Path to the signature file
    
    Returns:
        The signature bytes
    """
    return Path(signature_path).read_bytes()


def signature_to_base64(signature: bytes) -> str:
    """
    Convert signature bytes to base64 string for JSON storage.
    
    Args:
        signature: The signature bytes
    
    Returns:
        Base64-encoded signature string
    """
    return base64.b64encode(signature).decode('ascii')


def signature_from_base64(signature_b64: str) -> bytes:
    """
    Convert base64 signature string back to bytes.
    
    Args:
        signature_b64: Base64-encoded signature string
    
    Returns:
        The signature bytes
    """
    return base64.b64decode(signature_b64)

