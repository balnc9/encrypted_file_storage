"""
Generate a Certificate Signing Request (CSR) for a user.
This can be used to get a CA-signed certificate instead of self-signed.
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from crypto.pki import create_csr, save_csr
from cryptography.hazmat.primitives import serialization


def generate_user_csr(
    username: str,
    private_key_pem: bytes,
    email: str = None,
    output_dir: str = "pki/csrs"
) -> str:
    """
    Generate a CSR for a user.
    
    Args:
        username: Username (will be used as common name)
        private_key_pem: User's private key in PEM format
        email: Optional email address
        output_dir: Directory to save the CSR
    
    Returns:
        Path to the saved CSR
    """
    print("=" * 60)
    print("GENERATING CERTIFICATE SIGNING REQUEST (CSR)")
    print("=" * 60)
    
    print(f"\n[1/2] Creating CSR for user: {username}...")
    csr_pem = create_csr(
        private_key_pem=private_key_pem,
        common_name=username,
        email=email
    )
    
    print(f"[2/2] Saving CSR...")
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    csr_file = output_path / f"{username}_csr.pem"
    save_csr(csr_pem, str(csr_file))
    print(f"   ✓ CSR saved to: {csr_file}")
    
    print("\n" + "=" * 60)
    print("CSR GENERATED SUCCESSFULLY!")
    print("=" * 60)
    print(f"\nNext steps:")
    print(f"1. Send {csr_file} to the Certificate Authority")
    print(f"2. CA will sign it and return a certificate")
    print(f"3. Store the certificate with your account\n")
    
    return str(csr_file)


def generate_csr_from_stored_user(username: str, password: str) -> str:
    """
    Generate CSR for an existing user in the system.
    
    Args:
        username: Username of the registered user
        password: User's password to decrypt private key
    
    Returns:
        Path to the saved CSR
    """
    from accounts.manager import AccountManager
    from accounts.hashing import SimpleHasher
    from accounts.storage import JSONStorage
    
    # Load user
    storage = JSONStorage("users.json")
    hasher = SimpleHasher()
    manager = AccountManager(storage, hasher)
    
    user = manager.authenticate(username, password)
    if not user:
        raise ValueError("Invalid username or password")
    
    # Decrypt private key
    private_key_pem = manager.decrypt_private_key(user, password)
    
    # Generate CSR
    return generate_user_csr(username, private_key_pem)


if __name__ == "__main__":
    import getpass
    
    if len(sys.argv) < 2:
        print("Usage: python generate_user_csr.py <username>")
        sys.exit(1)
    
    username = sys.argv[1]
    password = getpass.getpass(f"Enter password for {username}: ")
    
    try:
        csr_path = generate_csr_from_stored_user(username, password)
        print(f"\n✓ CSR generated at: {csr_path}")
    except Exception as e:
        print(f"\n✗ Error: {e}")
        sys.exit(1)

