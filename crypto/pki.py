"""
Mini-PKI (Public Key Infrastructure) Module

Implements a simple Certificate Authority system:
- Root CA generation and management
- User certificate signing
- Certificate verification
- Certificate storage and loading

Uses X.509 certificates with RSA keys.
"""

import os
import json
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# Directory for PKI data
PKI_DIR = Path("pki")
ROOT_CA_KEY_FILE = PKI_DIR / "root_ca_key.pem"
ROOT_CA_CERT_FILE = PKI_DIR / "root_ca_cert.pem"
USER_CERTS_DIR = PKI_DIR / "user_certs"


def _ensure_pki_dirs() -> None:
    """Ensure PKI directories exist."""
    PKI_DIR.mkdir(exist_ok=True)
    USER_CERTS_DIR.mkdir(exist_ok=True)


def generate_root_ca(
    common_name: str = "Encrypted File Storage Root CA",
    organization: str = "UC3M Crypto Lab",
    country: str = "ES",
    validity_days: int = 3650,  # 10 years
) -> Tuple[bytes, bytes]:
    """
    Generate a new Root CA key pair and self-signed certificate.
    
    Returns:
        Tuple of (private_key_pem, certificate_pem)
    """
    _ensure_pki_dirs()
    
    # Generate RSA key pair for Root CA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,  # Stronger key for CA
        backend=default_backend()
    )
    
    # Build certificate subject/issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build the certificate
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        # CA extensions
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    # Serialize to PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Save to files
    ROOT_CA_KEY_FILE.write_bytes(private_key_pem)
    ROOT_CA_CERT_FILE.write_bytes(cert_pem)
    
    return private_key_pem, cert_pem


def load_root_ca() -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Load the Root CA key and certificate from disk.
    
    Returns:
        Tuple of (private_key_pem, certificate_pem) or (None, None) if not found
    """
    if not ROOT_CA_KEY_FILE.exists() or not ROOT_CA_CERT_FILE.exists():
        return None, None
    
    return ROOT_CA_KEY_FILE.read_bytes(), ROOT_CA_CERT_FILE.read_bytes()


def get_or_create_root_ca() -> Tuple[bytes, bytes]:
    """
    Get existing Root CA or create a new one if it doesn't exist.
    
    Returns:
        Tuple of (private_key_pem, certificate_pem)
    """
    key_pem, cert_pem = load_root_ca()
    if key_pem and cert_pem:
        return key_pem, cert_pem
    return generate_root_ca()


def issue_user_certificate(
    username: str,
    user_public_key_pem: bytes,
    validity_days: int = 365,
) -> bytes:
    """
    Issue a certificate for a user, signed by the Root CA.
    
    Args:
        username: The user's username (used in certificate CN)
        user_public_key_pem: The user's RSA public key in PEM format
        validity_days: How long the certificate is valid
        
    Returns:
        The signed certificate in PEM format
    """
    _ensure_pki_dirs()
    
    # Load Root CA
    ca_key_pem, ca_cert_pem = get_or_create_root_ca()
    ca_private_key = serialization.load_pem_private_key(ca_key_pem, password=None)
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    
    # Load user's public key
    user_public_key = serialization.load_pem_public_key(user_public_key_pem)
    
    # Build certificate subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M Crypto Lab"),
        x509.NameAttribute(NameOID.COMMON_NAME, f"User: {username}"),
    ])
    
    # Build the certificate
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)  # Issued by Root CA
        .public_key(user_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=validity_days))
        # End-entity extensions
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.EMAIL_PROTECTION,
            ]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(user_public_key),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256(), default_backend())
    )
    
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    
    # Save user certificate
    user_cert_path = USER_CERTS_DIR / f"{username.lower()}.pem"
    user_cert_path.write_bytes(cert_pem)
    
    return cert_pem


def load_user_certificate(username: str) -> Optional[bytes]:
    """Load a user's certificate from disk."""
    user_cert_path = USER_CERTS_DIR / f"{username.lower()}.pem"
    if not user_cert_path.exists():
        return None
    return user_cert_path.read_bytes()


def verify_certificate(cert_pem: bytes, ca_cert_pem: Optional[bytes] = None) -> dict:
    """
    Verify a certificate against the Root CA.
    
    Args:
        cert_pem: The certificate to verify
        ca_cert_pem: Optional CA certificate (loads from disk if not provided)
        
    Returns:
        Dict with verification results:
        - valid: bool
        - subject: str
        - issuer: str
        - not_before: str
        - not_after: str
        - expired: bool
        - error: str (if invalid)
    """
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
        
        # Load CA cert if not provided
        if ca_cert_pem is None:
            _, ca_cert_pem = load_root_ca()
            if not ca_cert_pem:
                return {"valid": False, "error": "Root CA not found"}
        
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
        
        # Check if certificate is expired
        now = datetime.now(timezone.utc)
        expired = now > cert.not_valid_after_utc or now < cert.not_valid_before_utc
        
        # Verify signature using RSA PKCS1v15 (standard for X.509)
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                asym_padding.PKCS1v15(),
                hashes.SHA256(),
            )
            signature_valid = True
        except Exception:
            signature_valid = False
        
        # Extract subject CN
        subject_cn = ""
        for attr in cert.subject:
            if attr.oid == NameOID.COMMON_NAME:
                subject_cn = attr.value
                break
        
        issuer_cn = ""
        for attr in cert.issuer:
            if attr.oid == NameOID.COMMON_NAME:
                issuer_cn = attr.value
                break
        
        return {
            "valid": signature_valid and not expired,
            "signature_valid": signature_valid,
            "subject": subject_cn,
            "issuer": issuer_cn,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "expired": expired,
            "serial_number": str(cert.serial_number),
        }
        
    except Exception as e:
        return {"valid": False, "error": str(e)}


def get_public_key_from_certificate(cert_pem: bytes) -> bytes:
    """Extract the public key from a certificate."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    return cert.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def get_certificate_info(cert_pem: bytes) -> dict:
    """Get human-readable information from a certificate."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    
    subject_parts = []
    for attr in cert.subject:
        subject_parts.append(f"{attr.oid._name}={attr.value}")
    
    issuer_parts = []
    for attr in cert.issuer:
        issuer_parts.append(f"{attr.oid._name}={attr.value}")
    
    return {
        "subject": ", ".join(subject_parts),
        "issuer": ", ".join(issuer_parts),
        "serial_number": str(cert.serial_number),
        "not_valid_before": cert.not_valid_before_utc.isoformat(),
        "not_valid_after": cert.not_valid_after_utc.isoformat(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
    }

