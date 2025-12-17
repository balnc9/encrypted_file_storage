# Encrypted File Storage System

**UC3M Cryptography Lab Final Project**

A secure file storage application with encryption, digital signatures, and multi-user file sharing capabilities.

## Features

### 1. User Authentication
- **Password Hashing**: Uses Argon2id (via `argon2-cffi`) for secure password storage
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 200,000 iterations for deriving encryption keys
- **RSA Key Pair Generation**: 2048-bit RSA keys generated per user at registration
- **Private Key Protection**: User's RSA private key is encrypted with AES-256-GCM using a key derived from their password

### 2. File Encryption (AES-256-GCM)
- **Symmetric Encryption**: Files are encrypted using AES-256-GCM (Authenticated Encryption with Associated Data)
- **Random File Keys**: Each file gets a unique 256-bit random key
- **Key Wrapping**: File keys are wrapped (encrypted) with RSA-OAEP using SHA-256
- **Nonce/IV**: 96-bit random nonce per file
- **Authentication Tag**: 128-bit GCM tag ensures integrity

### 3. Digital Signatures (RSA-PSS)
- **File Signing**: Files are signed with RSA-PSS using SHA-256 at upload time
- **Signature Verification**: Signatures are verified when downloading files
- **Integrity Hash**: SHA-256 hash of plaintext stored for integrity verification
- **Non-repudiation**: Only the file owner's private key can create valid signatures

### 4. Multi-Recipient Encryption (File Sharing)
- **Shared File Keys**: The same file can be encrypted for multiple recipients
- **Per-User Key Wrapping**: Each authorized user gets their own wrapped copy of the file key
- **Seamless Sharing**: Share files with other users through the GUI
- **Access Control**: Only users with wrapped keys can decrypt shared files

### 5. Modern GUI
- **PySide6/Qt6**: Cross-platform graphical interface
- **File List View**: Click to select files instead of typing filenames
- **File Details Panel**: View encryption status, signatures, and sharing info
- **Share Dialog**: Easy multi-user file sharing
- **Dark Theme**: Modern, eye-friendly interface

## Cryptographic Algorithms Used

| Component | Algorithm | Parameters |
|-----------|-----------|------------|
| Password Hashing | Argon2id | Default parameters |
| Key Derivation | PBKDF2-HMAC-SHA256 | 200,000 iterations, 16-byte salt |
| File Encryption | AES-256-GCM | 256-bit key, 96-bit nonce |
| Key Wrapping | RSA-OAEP | SHA-256 for MGF1 and hash |
| Digital Signatures | RSA-PSS | SHA-256, max salt length |
| File Integrity | SHA-256 | Standard |

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
│   └── signatures.py   # RSA-PSS digital signatures
├── storage/
│   ├── __init__.py
│   ├── file_manager.py # File upload/download, encryption, sharing
│   └── models.py       # FileMetadata and RecipientKey models
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

### Key Hierarchy
1. **User Password** → PBKDF2 → **AES Key** (for private key encryption)
2. **Random File Key** (AES-256) → RSA-OAEP wrapped with user's public key
3. **File Content** → AES-GCM encrypted with file key

## Requirements

- Python 3.10+
- cryptography >= 41.0.0
- argon2-cffi >= 21.0.0
- PySide6 >= 6.5.0

## Lab Schedule

| **Date**       | **Lab Session**  | **Focus / Goals**                                             |
| -------------- | ---------------- | ------------------------------------------------------------- |
| **01/10/2025** | Introduction     | Overview of architecture, password "super hash" discussion    |
| **08/10/2025** | **Lab 2**        | Text-based menu for registration & login (no persistence yet) |
| **15/10/2025** | Lab 3            | Password hashing (PBKDF2), JSON persistence, key generation   |
| **29/10/2025** | Lab 4            | Authenticated Encryption (AES-GCM) for file storage           |
| **12/11/2025** | Lab 5            | Digital Signatures (RSA/ECDSA) and signature verification     |
| **26/11/2025** | Lab 6            | Mini-PKI: Root CA, user certificates, OpenSSL integration     |
| **Post-Labs**  | Final Assessment | In-person demo & short written report submission              |

## Authors

Lab Group 13 - CMAC 2025/26
