# Encrypted File Storage System

**UC3M Cryptography Lab Final Project**

A secure file storage application with encryption, digital signatures, PKI certificates, and multi-user file sharing capabilities.

## Features

### 1. User Authentication (0.5/4.0 ✅)
- **Password Hashing**: Uses Argon2id (via `argon2-cffi`) for secure password storage
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 200,000 iterations for deriving encryption keys
- **RSA Key Pair Generation**: 2048-bit RSA keys generated per user at registration
- **Private Key Protection**: User's RSA private key is encrypted with AES-256-GCM using a key derived from their password

### 2. Key Management (0.5/4.0 ✅)
- Per-user RSA-2048 key pairs
- Password-derived keys using PBKDF2
- Encrypted private key storage
- Public key distribution via certificates

### 3. Authenticated Encryption - AES-256-GCM (0.75/4.0 ✅)
- **Symmetric Encryption**: Files are encrypted using AES-256-GCM (Authenticated Encryption with Associated Data)
- **Random File Keys**: Each file gets a unique 256-bit random key
- **Key Wrapping**: File keys are wrapped (encrypted) with RSA-OAEP using SHA-256
- **Nonce/IV**: 96-bit random nonce per file
- **Authentication Tag**: 128-bit GCM tag ensures integrity

### 4. Digital Signatures - RSA-PSS (0.75/4.0 ✅)
- **File Signing**: Files are signed with RSA-PSS using SHA-256 at upload time
- **Signature Verification**: Signatures are verified when downloading files
- **Integrity Hash**: SHA-256 hash of plaintext stored for integrity verification
- **Non-repudiation**: Only the file owner's private key can create valid signatures

### 5. Mini-PKI - X.509 Certificates (1.0/4.0 ✅)
- **Root CA**: Self-signed 4096-bit RSA Certificate Authority
- **User Certificates**: X.509 certificates issued to each user upon registration
- **Certificate Verification**: Validates certificate chain against Root CA
- **Certificate Storage**: PEM-encoded certificates stored in `pki/` directory
- **Extensions**: BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier

### 6. BONUS: Asymmetric Encryption (+0.5/4.0 ✅)
- **RSA-OAEP Key Wrapping**: File encryption keys wrapped with recipient's public key
- **Multi-Recipient Encryption**: Same file can be encrypted for multiple users
- **Hybrid Encryption**: Combines RSA-OAEP (asymmetric) with AES-GCM (symmetric)

## Cryptographic Algorithms Used

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Password Hashing | Argon2id | Default parameters |
| Key Derivation | PBKDF2-HMAC-SHA256 | 200,000 iterations, 16-byte salt |
| File Encryption | AES-256-GCM | 256-bit key, 96-bit nonce |
| Key Wrapping | RSA-OAEP | SHA-256 for MGF1 and hash |
| Digital Signatures | RSA-PSS | SHA-256, max salt length |
| File Integrity | SHA-256 | Standard |
| CA Certificate | RSA-4096 | Self-signed, 10-year validity |
| User Certificates | RSA-2048 | CA-signed, 1-year validity |

## Project Structure

```
enc_file_storage/
├── accounts/
│   ├── __init__.py
│   ├── hashing.py      # Password hashing with Argon2
│   ├── manager.py      # User registration, authentication, key management
│   ├── models.py       # User data model
│   └── storage.py      # JSON-based user storage
├── crypto/
│   ├── __init__.py
│   ├── pki.py          # X.509 certificates and Root CA
│   └── signatures.py   # RSA-PSS digital signatures
├── storage/
│   ├── __init__.py
│   ├── file_manager.py # File upload/download, encryption, sharing
│   └── models.py       # FileMetadata and RecipientKey models
├── pki/                # PKI directory
│   ├── root_ca_cert.pem   # Root CA certificate
│   ├── root_ca_key.pem    # Root CA private key
│   └── user_certs/        # User certificates
├── vault/              # Encrypted file storage (per-user directories)
├── cli.py              # Command-line interface
├── gui.py              # Graphical user interface
├── users.json          # User database
└── requirements.txt    # Python dependencies
```

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### GUI Mode (Recommended)
```bash
python gui.py
```

### CLI Mode
```bash
python cli.py
```

## Security Model

### Threat Model
- **Server Compromise**: Even if the vault files are stolen, they cannot be decrypted without the user's private key
- **Password Recovery**: User's private key is protected by their password; password recovery is not possible
- **File Tampering**: Digital signatures detect any modification to file contents
- **Unauthorized Access**: Multi-recipient encryption ensures only authorized users can decrypt
- **Certificate Forgery**: All user certificates are signed by the Root CA

### Key Hierarchy
1. **User Password** → PBKDF2 → **AES Key** (for private key encryption)
2. **Root CA** → Signs → **User Certificate** (binds public key to identity)
3. **Random File Key** (AES-256) → RSA-OAEP wrapped with user's public key
4. **File Content** → AES-GCM encrypted with file key

### PKI Trust Model
```
Root CA (self-signed, 4096-bit RSA)
    └── User Certificate (signed by Root CA, 2048-bit RSA)
            └── Digital Signatures (RSA-PSS)
            └── Key Wrapping (RSA-OAEP)
```

## Grade Checklist

| Requirement | Points | Status |
|-------------|--------|--------|
| User authentication | 0.5/4.0 | ✅ Argon2 password hashing |
| Key management | 0.5/4.0 | ✅ RSA keys, PBKDF2, encrypted storage |
| Authenticated encryption (AES-GCM) | 0.75/4.0 | ✅ AES-256-GCM for files |
| Digital signatures | 0.75/4.0 | ✅ RSA-PSS signing and verification |
| Mini-PKI (certificates) | 1.0/4.0 | ✅ Root CA + user certificates |
| BONUS: Asymmetric encryption | +0.5/4.0 | ✅ RSA-OAEP key wrapping |
| **TOTAL** | **4.0 + 0.5** | **Full marks + bonus** |

## Requirements

- Python 3.10+
- cryptography >= 41.0.0
- argon2-cffi >= 21.0.0
- PySide6 >= 6.5.0

## Authors

Lab Group - CMAC 2025/26
