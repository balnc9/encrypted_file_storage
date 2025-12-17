"""Cryptography utilities for encrypted file storage."""

from .signatures import (
    sign_data,
    sign_data_b64,
    verify_signature,
    verify_signature_b64,
    compute_file_hash,
    compute_file_hash_b64,
)

from .pki import (
    generate_root_ca,
    load_root_ca,
    get_or_create_root_ca,
    issue_user_certificate,
    load_user_certificate,
    verify_certificate,
    get_public_key_from_certificate,
    get_certificate_info,
)

__all__ = [
    # Signatures
    "sign_data",
    "sign_data_b64", 
    "verify_signature",
    "verify_signature_b64",
    "compute_file_hash",
    "compute_file_hash_b64",
    # PKI
    "generate_root_ca",
    "load_root_ca",
    "get_or_create_root_ca",
    "issue_user_certificate",
    "load_user_certificate",
    "verify_certificate",
    "get_public_key_from_certificate",
    "get_certificate_info",
]

