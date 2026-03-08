#encryption.py
#pip install cryptography

from __future__ import annotations

import os
import json
import base64
import sys
from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ====== CONFIG ======
PBKDF2_ITER = 600_000
SALT_LEN = 16
NONCE_LEN = 12
DEK_LEN = 32   # 32 bytes = AES-256
TAG_LEN = 16   # GCM tag = 128 bits


# ====== HELPERS ======
def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def canonical_json(data: dict) -> bytes:
   
    return json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")


def derive_kek(passphrase: str, salt: bytes) -> bytes:

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITER,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def build_header(file_path: Path) -> dict:

    stat = file_path.stat()

    return {
        "container_version": 1,
        "aead_algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "pbkdf2_iterations": PBKDF2_ITER,
        "nonce_length": NONCE_LEN,
        "tag_length": TAG_LEN,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "original_filename": file_path.name,
        "original_size": stat.st_size,
    }


def encrypt_file(input_path: str, output_path: str, passphrase: str) -> None:

    file_path = Path(input_path)

    if not file_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    if not file_path.is_file():
        raise ValueError(f"Input path is not a file: {input_path}")

    plaintext = file_path.read_bytes()

    header = build_header(file_path)
    aad = canonical_json(header)

    file_key = os.urandom(DEK_LEN)

    file_nonce = os.urandom(NONCE_LEN)
    file_cipher = AESGCM(file_key)
    encrypted_payload = file_cipher.encrypt(file_nonce, plaintext, aad)

    ciphertext = encrypted_payload[:-TAG_LEN]
    auth_tag = encrypted_payload[-TAG_LEN:]

    kdf_salt = os.urandom(SALT_LEN)
    kek = derive_kek(passphrase, kdf_salt)

    wrap_nonce = os.urandom(NONCE_LEN)
    wrap_aad = b"SDDV-DEK-WRAP-v1"
    key_cipher = AESGCM(kek)
    wrapped_key_full = key_cipher.encrypt(wrap_nonce, file_key, wrap_aad)

    wrapped_key = wrapped_key_full[:-TAG_LEN]
    wrapped_key_tag = wrapped_key_full[-TAG_LEN:]

    container = {
        "header": header,
        "key_envelope": {
            "kdf_salt": b64e(kdf_salt),
            "wrap_nonce": b64e(wrap_nonce),
            "wrapped_key": b64e(wrapped_key),
            "wrapped_key_tag": b64e(wrapped_key_tag),
            "wrap_algorithm": "AES-256-GCM",
            "wrap_aad": "SDDV-DEK-WRAP-v1",
        },
        "payload": {
            "nonce": b64e(file_nonce),
            "ciphertext": b64e(ciphertext),
            "tag": b64e(auth_tag),
        },
    }

    output_file = Path(output_path)
    output_file.write_text(
        json.dumps(container, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

def b64d(data: str) -> bytes:
    return base64.b64decode(data)




