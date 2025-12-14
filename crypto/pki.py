"""
Public Key Infrastructure (PKI) implementation.
Handles certificate generation, CSR creation, and certificate verification.
"""
import datetime
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID, ExtensionOID


def generate_self_signed_certificate(
    private_key_pem: bytes,
    common_name: str,
    validity_days: int = 365
) -> bytes:
    """
    Generate a self-signed X.509 certificate.
    
    Args:
        private_key_pem: PEM-encoded RSA private key
        common_name: Common name for the certificate (e.g., username)
        validity_days: How many days the certificate is valid
    
    Returns:
        PEM-encoded certificate bytes
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    # Create subject and issuer (same for self-signed)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Leganes"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M Crypto Project"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Serialize to PEM
    return cert.public_bytes(serialization.Encoding.PEM)


def create_csr(
    private_key_pem: bytes,
    common_name: str,
    email: Optional[str] = None
) -> bytes:
    """
    Create a Certificate Signing Request (CSR) for CA signing.
    
    Args:
        private_key_pem: PEM-encoded RSA private key
        common_name: Common name for the certificate
        email: Optional email address
    
    Returns:
        PEM-encoded CSR bytes
    """
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    
    # Build subject
    subject_attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Leganes"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M Crypto Project"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]
    
    if email:
        subject_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    
    subject = x509.Name(subject_attrs)
    
    # Build CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(common_name)]),
        critical=False,
    ).sign(private_key, hashes.SHA256())
    
    # Serialize to PEM
    return csr.public_bytes(serialization.Encoding.PEM)


def load_certificate(cert_pem: bytes) -> x509.Certificate:
    """
    Load an X.509 certificate from PEM bytes.
    
    Args:
        cert_pem: PEM-encoded certificate
    
    Returns:
        Certificate object
    """
    return x509.load_pem_x509_certificate(cert_pem)


def load_certificate_from_file(cert_path: str) -> x509.Certificate:
    """
    Load an X.509 certificate from a PEM file.
    
    Args:
        cert_path: Path to the certificate file
    
    Returns:
        Certificate object
    """
    cert_pem = Path(cert_path).read_bytes()
    return load_certificate(cert_pem)


def extract_public_key_from_cert(cert: x509.Certificate) -> bytes:
    """
    Extract the public key from a certificate.
    
    Args:
        cert: Certificate object
    
    Returns:
        PEM-encoded public key
    """
    public_key = cert.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def verify_certificate_signature(
    cert_to_verify: x509.Certificate,
    issuer_public_key_pem: bytes
) -> bool:
    """
    Verify a certificate's signature using the issuer's public key.
    
    Args:
        cert_to_verify: The certificate to verify
        issuer_public_key_pem: PEM-encoded public key of the issuer (CA)
    
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        issuer_public_key = serialization.load_pem_public_key(issuer_public_key_pem)
        
        # Extract signature components from certificate
        signature = cert_to_verify.signature
        tbs_certificate_bytes = cert_to_verify.tbs_certificate_bytes
        signature_hash_algorithm = cert_to_verify.signature_hash_algorithm
        
        # Determine padding (typically PKCS1v15 for certificates)
        cert_padding = padding.PKCS1v15()
        
        # Verify the signature
        issuer_public_key.verify(
            signature,
            tbs_certificate_bytes,
            cert_padding,
            signature_hash_algorithm
        )
        return True
    except Exception as e:
        print(f"Certificate verification failed: {e}")
        return False


def verify_certificate_chain(
    user_cert: x509.Certificate,
    ca_cert: x509.Certificate
) -> bool:
    """
    Verify a certificate chain (user cert signed by CA).
    
    Args:
        user_cert: The user's certificate
        ca_cert: The CA's certificate
    
    Returns:
        True if chain is valid, False otherwise
    """
    # First verify the CA certificate is self-signed
    ca_public_key = extract_public_key_from_cert(ca_cert)
    if not verify_certificate_signature(ca_cert, ca_public_key):
        print("CA certificate is not properly self-signed")
        return False
    
    # Then verify the user cert was signed by the CA
    if not verify_certificate_signature(user_cert, ca_public_key):
        print("User certificate was not signed by CA")
        return False
    
    # Check validity dates
    now = datetime.datetime.utcnow()
    if now < user_cert.not_valid_before or now > user_cert.not_valid_after:
        print("User certificate has expired or is not yet valid")
        return False
    
    if now < ca_cert.not_valid_before or now > ca_cert.not_valid_after:
        print("CA certificate has expired or is not yet valid")
        return False
    
    return True


def save_certificate(cert_pem: bytes, output_path: str) -> None:
    """
    Save a certificate to a file.
    
    Args:
        cert_pem: PEM-encoded certificate
        output_path: Where to save the certificate
    """
    Path(output_path).write_bytes(cert_pem)


def save_csr(csr_pem: bytes, output_path: str) -> None:
    """
    Save a CSR to a file.
    
    Args:
        csr_pem: PEM-encoded CSR
        output_path: Where to save the CSR
    """
    Path(output_path).write_bytes(csr_pem)


def get_certificate_info(cert: x509.Certificate) -> dict:
    """
    Extract human-readable information from a certificate.
    
    Args:
        cert: Certificate object
    
    Returns:
        Dictionary with certificate information
    """
    subject = cert.subject
    issuer = cert.issuer
    
    return {
        "subject_cn": subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        "issuer_cn": issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value,
        "serial_number": cert.serial_number,
        "not_valid_before": cert.not_valid_before.isoformat(),
        "not_valid_after": cert.not_valid_after.isoformat(),
        "is_self_signed": subject == issuer,
    }

