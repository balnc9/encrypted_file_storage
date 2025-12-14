# UC3M Crypto Final Project: Encrypted File Storage System

A secure file storage application with digital signatures and Public Key Infrastructure (PKI).

## Features

- **User Authentication** - Argon2id password hashing
- **Authenticated Encryption** - AES-256-GCM for file storage
- **Digital Signatures** - RSA-PSS-SHA256 for file integrity
- **Mini-PKI** - Self-signed and CA-signed X.509 certificates
- **Key Management** - PBKDF2 + AES-GCM encrypted private keys
- **BONUS: Asymmetric Encryption** - RSA-OAEP key wrapping (hybrid cryptosystem)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python gui.py

# Run tests
python test_signatures.py
```

## Cryptographic Implementation

### User Authentication (0.5 pts)
- **Argon2id** password hashing (memory-hard, GPU-resistant)
- Multi-user support with JSON persistence

### Key Management (0.5 pts)
- **RSA-2048** key pair generation
- Private keys encrypted with **PBKDF2** (200k iterations) + **AES-256-GCM**
- Keys serialized in **PEM + PKCS8** format

### Authenticated Encryption (0.75 pts)
- **AES-256-GCM** for file encryption
- 12-byte random nonce, 16-byte authentication tag
- Confidentiality + integrity in one algorithm

### Digital Signatures (0.75 pts)
- **RSA-PSS** with SHA256, MGF1, MAX_LENGTH salt
- Files signed before encryption
- Signatures verified on download

### Mini-PKI (1.0 pts)
- Self-signed **X.509** certificates generated on registration
- Certificate Signing Request (CSR) generation
- Root CA creation and certificate signing
- Certificate chain verification with **PKCS1v15**

### BONUS: Asymmetric Encryption (+0.5 pts)
- **RSA-OAEP-SHA256** for symmetric key wrapping
- Hybrid cryptosystem: RSA encrypts AES key, AES encrypts file
- Each file has unique encrypted key

## Testing

```bash
python test_signatures.py
```

All 5 tests pass:
1. Digital Signatures (RSA-PSS-SHA256)
2. File Signatures
3. Self-Signed Certificates
4. CSR Generation
5. Certificate Chain Verification (Mini-PKI)

## Project Structure

```
enc_file_storage/
├── accounts/           # User authentication & key management
│   ├── hashing.py      # Argon2id password hashing
│   ├── manager.py      # Account operations, key generation
│   ├── models.py       # User data model
│   └── storage.py      # JSON persistence
├── storage/            # File encryption & signatures
│   ├── file_manager.py # Upload/download with crypto
│   └── models.py       # File metadata model
├── crypto/             # Cryptographic primitives
│   ├── signatures.py   # RSA-PSS digital signatures
│   └── pki.py          # X.509 certificates, PKI
├── pki_tools/          # Certificate Authority tools
│   ├── setup_ca.py     # Create Root CA
│   ├── sign_csr.py     # Sign CSRs with CA
│   └── generate_user_csr.py
├── gui.py              # PySide6 GUI application
├── cli.py              # Command-line interface
├── test_signatures.py  # Comprehensive test suite
└── requirements.txt    # Dependencies
```

## Dependencies

- `argon2-cffi` - Password hashing
- `cryptography` - All cryptographic operations
- `PySide6` - GUI framework

## Grade Summary

| Criteria | Points |
|----------|--------|
| User authentication | 0.5/4.0 |
| Key management | 0.5/4.0 |
| Authenticated encryption | 0.75/4.0 |
| Digital signatures | 0.75/4.0 |
| Mini-PKI | 1.0/4.0 |
| **BONUS: Asymmetric encryption** | **+0.5/4.0** |
| **TOTAL** | **4.0/4.0 + 0.5 bonus** |
