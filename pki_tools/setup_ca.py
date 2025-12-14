"""
Setup script for creating a simple Certificate Authority (CA).
This creates a Root CA that can sign user certificates.
"""
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def create_root_ca(
    ca_name: str = "UC3M_Crypto_Root_CA",
    validity_years: int = 5,
    output_dir: str = "pki"
) -> None:
    """
    Create a Root Certificate Authority.
    
    Args:
        ca_name: Common name for the CA
        validity_years: How many years the CA certificate is valid
        output_dir: Directory to save CA files
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    print("=" * 60)
    print("CREATING ROOT CERTIFICATE AUTHORITY (CA)")
    print("=" * 60)
    
    # Generate CA private key
    print(f"\n[1/4] Generating RSA key pair for CA...")
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096  # Use 4096 for CA (more secure)
    )
    ca_public_key = ca_private_key.public_key()
    
    # Create CA subject
    print(f"[2/4] Creating CA certificate...")
    ca_subject = ca_issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Leganes"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "UC3M Cryptography Project"),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Certificate Authority"),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_name),
    ])
    
    # Build CA certificate (self-signed)
    ca_cert = x509.CertificateBuilder().subject_name(
        ca_subject
    ).issuer_name(
        ca_issuer
    ).public_key(
        ca_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=validity_years * 365)
    ).add_extension(
        # Mark as CA certificate
        x509.BasicConstraints(ca=True, path_length=0),
        critical=True,
    ).add_extension(
        # CA can sign certificates
        x509.KeyUsage(
            digital_signature=True,
            key_cert_sign=True,
            crl_sign=True,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    ).sign(ca_private_key, hashes.SHA256())
    
    # Save CA private key (encrypted)
    print(f"[3/4] Saving CA private key (encrypted)...")
    ca_password = input("Enter password to protect CA private key: ").encode('utf-8')
    
    ca_private_pem = ca_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(ca_password)
    )
    
    ca_private_key_path = output_path / "ca_private_key.pem"
    ca_private_key_path.write_bytes(ca_private_pem)
    print(f"   ✓ CA private key saved to: {ca_private_key_path}")
    
    # Save CA certificate
    print(f"[4/4] Saving CA certificate...")
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    ca_cert_path = output_path / "ca_certificate.pem"
    ca_cert_path.write_bytes(ca_cert_pem)
    print(f"   ✓ CA certificate saved to: {ca_cert_path}")
    
    # Save CA public key (for convenience)
    ca_public_pem = ca_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ca_public_key_path = output_path / "ca_public_key.pem"
    ca_public_key_path.write_bytes(ca_public_pem)
    print(f"   ✓ CA public key saved to: {ca_public_key_path}")
    
    print("\n" + "=" * 60)
    print("ROOT CA CREATED SUCCESSFULLY!")
    print("=" * 60)
    print(f"\nCA Name: {ca_name}")
    print(f"Valid for: {validity_years} years")
    print(f"Serial Number: {ca_cert.serial_number}")
    print(f"\n⚠️  IMPORTANT: Keep ca_private_key.pem secure!")
    print("   This key can sign certificates for your PKI.\n")


if __name__ == "__main__":
    create_root_ca()

