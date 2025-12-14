"""
Tool for signing Certificate Signing Requests (CSRs) with the CA.
This allows the CA to issue certificates to users.
"""
import datetime
from pathlib import Path
from getpass import getpass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID, ExtensionOID


def sign_csr_with_ca(
    csr_path: str,
    ca_cert_path: str = "pki/ca_certificate.pem",
    ca_key_path: str = "pki/ca_private_key.pem",
    output_path: str = None,
    validity_days: int = 365
) -> str:
    """
    Sign a CSR with the CA to issue a certificate.
    
    Args:
        csr_path: Path to the CSR file
        ca_cert_path: Path to CA certificate
        ca_key_path: Path to CA private key
        output_path: Where to save the signed certificate
        validity_days: How many days the certificate is valid
    
    Returns:
        Path to the signed certificate
    """
    print("=" * 60)
    print("SIGNING CERTIFICATE SIGNING REQUEST (CSR)")
    print("=" * 60)
    
    # Load CSR
    print(f"\n[1/5] Loading CSR from {csr_path}...")
    csr_pem = Path(csr_path).read_bytes()
    csr = x509.load_pem_x509_csr(csr_pem)
    
    # Verify CSR signature
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid!")
    print("   ✓ CSR signature is valid")
    
    # Load CA certificate
    print(f"[2/5] Loading CA certificate...")
    ca_cert_pem = Path(ca_cert_path).read_bytes()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    
    # Load CA private key
    print(f"[3/5] Loading CA private key...")
    ca_key_pem = Path(ca_key_path).read_bytes()
    ca_password = getpass("Enter CA private key password: ").encode('utf-8')
    
    ca_private_key = serialization.load_pem_private_key(
        ca_key_pem,
        password=ca_password
    )
    
    # Build the signed certificate
    print(f"[4/5] Creating signed certificate...")
    
    # Get subject from CSR
    subject = csr.subject
    
    # Build certificate
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject  # Issuer is the CA
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=validity_days)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=True,
            data_encipherment=True,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    
    # Copy over any extensions from the CSR
    for ext in csr.extensions:
        if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
            cert = cert.add_extension(ext.value, critical=ext.critical)
    
    # Sign with CA private key
    signed_cert = cert.sign(ca_private_key, hashes.SHA256())
    
    # Save certificate
    print(f"[5/5] Saving signed certificate...")
    if output_path is None:
        # Extract common name for filename
        cn = subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        output_path = f"pki/{cn}_certificate.pem"
    
    cert_pem = signed_cert.public_bytes(serialization.Encoding.PEM)
    Path(output_path).write_bytes(cert_pem)
    print(f"   ✓ Signed certificate saved to: {output_path}")
    
    print("\n" + "=" * 60)
    print("CERTIFICATE ISSUED SUCCESSFULLY!")
    print("=" * 60)
    print(f"\nSubject: {subject.rfc4514_string()}")
    print(f"Issuer: {ca_cert.subject.rfc4514_string()}")
    print(f"Serial Number: {signed_cert.serial_number}")
    print(f"Valid from: {signed_cert.not_valid_before}")
    print(f"Valid until: {signed_cert.not_valid_after}\n")
    
    return output_path


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python sign_csr.py <csr_file.pem>")
        sys.exit(1)
    
    csr_file = sys.argv[1]
    sign_csr_with_ca(csr_file)

