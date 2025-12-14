# UC3M Crypto Final Project: Encrypted File Storage System

A comprehensive secure file storage system with digital signatures and Public Key Infrastructure (PKI).

## Features

✓ **Multi-user support** with secure registration and authentication  
✓ **Authenticated encryption** (AES-256-GCM) for file storage  
✓ **Digital signatures** (RSA-PSS-SHA256) for file integrity  
✓ **Mini-PKI** with self-signed and CA-signed certificates  
✓ **Key management** with encrypted private key storage  
✓ **Modern GUI** with intuitive file management  

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python gui.py
```

See [QUICKSTART.md](QUICKSTART.md) for detailed instructions.

## Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Installation and basic usage
- **[CRYPTO_REPORT.md](CRYPTO_REPORT.md)** - Full technical documentation
- **[test_signatures.py](test_signatures.py)** - Comprehensive test suite

## Implementation Status

| Feature | Status | Points |
|---------|--------|--------|
| User Authentication | ✓ Complete | 0.5/4.0 |
| Key Management | ✓ Complete | 0.5/4.0 |
| Authenticated Encryption | ✓ Complete | 0.75/4.0 |
| Digital Signatures | ✓ Complete | 0.75/4.0 |
| Mini-PKI | ✓ Complete | 1.0/4.0 |
| **BONUS:** Asymmetric Encryption | ✓ Complete | +0.5/4.0 |
| Report | ✓ Complete | 0.5/4.0 |
| **TOTAL** | **✓ Complete** | **4.5/4.0** |

## Testing

```bash
python test_signatures.py
```

All 5 tests pass:
- Digital Signatures (RSA-PSS-SHA256)
- File Signatures
- Self-Signed Certificates
- CSR Generation
- Certificate Chain Verification

## Lab Schedule

| **Date**       | **Lab Session**  | **Status** |
| -------------- | ---------------- | ---------- |
| **01/10/2025** | Introduction     | ✓ Complete |
| **08/10/2025** | Lab 2            | ✓ Complete |
| **15/10/2025** | Lab 3            | ✓ Complete |
| **29/10/2025** | Lab 4            | ✓ Complete |
| **12/11/2025** | Lab 5            | ✓ Complete |
| **26/11/2025** | Lab 6            | ✓ Complete |
| **Post-Labs**  | Final Assessment | ✓ Ready    |

## Project Structure

```
enc_file_storage/
├── accounts/         # User authentication
├── storage/          # File encryption
├── crypto/           # Signatures & PKI
├── pki_tools/        # CA management
├── gui.py            # GUI application
├── test_signatures.py # Test suite
└── CRYPTO_REPORT.md  # Technical documentation
```
