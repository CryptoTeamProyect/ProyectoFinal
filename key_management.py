"""Secure key management for the Secure Digital Document Vault.

D6 goals covered by this module:
- Private keys are never stored in plaintext.
- Private keys are encrypted with a password-derived key.
- KDF parameters, salt, nonce and metadata are stored explicitly.
- Encrypted keystores can be backed up and restored without weakening security.
"""
from __future__ import annotations

import base64
import io
import json
import os
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

KEYSTORE_FORMAT = "vault-key-store"
BACKUP_FORMAT = "vault-key-backup"
VERSION = 1
SALT_LEN = 16
NONCE_LEN = 12
DERIVED_KEY_LEN = 32

# scrypt parameters selected for an academic/demo vault: memory-hard enough to
# demonstrate secure design while remaining practical for unit tests and laptops.
DEFAULT_SCRYPT_PARAMS: Dict[str, int] = {
    "n": 2**14,
    "r": 8,
    "p": 1,
    "length": DERIVED_KEY_LEN,
}


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data, validate=True)


def canonical_json(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _password_bytes(password: Optional[str | bytes]) -> bytes:
    if password is None:
        raise ValueError("Se requiere una contraseña para acceder a la llave privada.")
    if isinstance(password, bytes):
        password_b = password
    else:
        password_b = password.encode("utf-8")
    if not password_b:
        raise ValueError("La contraseña no puede estar vacía.")
    return password_b


def derive_key(password: Optional[str | bytes], salt: bytes, params: Dict[str, int]) -> bytes:
    """Derive a 256-bit encryption key from a password using scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=int(params["length"]),
        n=int(params["n"]),
        r=int(params["r"]),
        p=int(params["p"]),
    )
    return kdf.derive(_password_bytes(password))


def _private_key_to_der(private_key) -> bytes:
    return private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _load_private_key_from_der(der: bytes):
    return serialization.load_der_private_key(der, password=None)


def _protected_aad_for_keystore(record: Dict[str, Any]) -> bytes:
    """AAD that makes keystore metadata tamper-evident."""
    protected = {
        "format": record["format"],
        "version": record["version"],
        "key_type": record["key_type"],
        "protection": record["protection"],
        "kdf": record["kdf"],
        "encryption": {"algorithm": record["encryption"]["algorithm"]},
        "metadata": record["metadata"],
    }
    return canonical_json(protected)


def encrypt_private_key_record(
    private_key,
    password: Optional[str | bytes],
    key_type: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a structured encrypted keystore record for a private key."""
    if not isinstance(private_key, (RSAPrivateKey, Ed25519PrivateKey)):
        raise TypeError("Solo se soportan claves privadas RSA y Ed25519.")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    kdf_params = dict(DEFAULT_SCRYPT_PARAMS)
    key = derive_key(password, salt, kdf_params)

    record: Dict[str, Any] = {
        "format": KEYSTORE_FORMAT,
        "version": VERSION,
        "key_type": key_type,
        "protection": "ENCRYPTED_WITH_SCRYPT_AES_256_GCM",
        "kdf": {
            "algorithm": "scrypt",
            "salt": b64e(salt),
            **kdf_params,
        },
        "encryption": {
            "algorithm": "AES-256-GCM",
            "nonce": b64e(nonce),
        },
        "metadata": {
            "created": datetime.now(timezone.utc).isoformat(),
            **(metadata or {}),
        },
    }

    plaintext_der = _private_key_to_der(private_key)
    aad = _protected_aad_for_keystore(record)
    encrypted = AESGCM(key).encrypt(nonce, plaintext_der, aad)
    record["encrypted_private_key"] = b64e(encrypted)
    return record


def write_private_key_record(
    private_key,
    path: str | Path,
    password: Optional[str | bytes],
    key_type: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> None:
    record = encrypt_private_key_record(private_key, password, key_type, metadata)
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")


def is_structured_keystore(path: str | Path) -> bool:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return data.get("format") == KEYSTORE_FORMAT
    except Exception:
        return False


def load_private_key_record(path: str | Path, password: Optional[str | bytes], expected_key_type: Optional[str] = None):
    """Load and decrypt a structured encrypted private key record."""
    try:
        record = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError("Formato de keystore inválido.") from exc

    if record.get("format") != KEYSTORE_FORMAT:
        raise ValueError("El archivo no es un keystore estructurado del vault.")
    if expected_key_type and record.get("key_type") != expected_key_type:
        raise ValueError("La llave privada no coincide con el tipo esperado.")
    if record.get("kdf", {}).get("algorithm") != "scrypt":
        raise ValueError("KDF no soportado.")
    if record.get("encryption", {}).get("algorithm") != "AES-256-GCM":
        raise ValueError("Algoritmo de cifrado de keystore no soportado.")

    kdf = record["kdf"]
    params = {
        "n": int(kdf["n"]),
        "r": int(kdf["r"]),
        "p": int(kdf["p"]),
        "length": int(kdf["length"]),
    }
    salt = b64d(kdf["salt"])
    nonce = b64d(record["encryption"]["nonce"])
    encrypted = b64d(record["encrypted_private_key"])
    key = derive_key(password, salt, params)
    aad = _protected_aad_for_keystore(record)

    try:
        plaintext_der = AESGCM(key).decrypt(nonce, encrypted, aad)
    except InvalidTag as exc:
        raise ValueError("Contraseña incorrecta o keystore modificado.") from exc

    loaded_key = _load_private_key_from_der(plaintext_der)
    if record["key_type"] == "rsa-private" and not isinstance(loaded_key, RSAPrivateKey):
        raise ValueError("La llave descifrada no es RSA.")
    if record["key_type"] == "ed25519-private" and not isinstance(loaded_key, Ed25519PrivateKey):
        raise ValueError("La llave descifrada no es Ed25519.")
    return loaded_key


def _protected_aad_for_backup(record: Dict[str, Any]) -> bytes:
    protected = {
        "format": record["format"],
        "version": record["version"],
        "protection": record["protection"],
        "kdf": record["kdf"],
        "encryption": {"algorithm": record["encryption"]["algorithm"]},
        "metadata": record["metadata"],
    }
    return canonical_json(protected)


def _zip_directory_bytes(source_dir: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for file_path in sorted(p for p in source_dir.rglob("*") if p.is_file()):
            zf.write(file_path, file_path.relative_to(source_dir).as_posix())
    return buffer.getvalue()


def export_keystore_backup(source_dir: str | Path, backup_path: str | Path, backup_password: Optional[str | bytes]) -> None:
    """Export an encrypted backup of a keystore directory.

    The backup contains the encrypted keystore files and is itself encrypted with
    scrypt + AES-GCM, so copying it does not weaken private key protection.
    """
    source = Path(source_dir)
    if not source.exists() or not source.is_dir():
        raise ValueError("El directorio de keystore no existe.")

    zipped = _zip_directory_bytes(source)
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    kdf_params = dict(DEFAULT_SCRYPT_PARAMS)
    key = derive_key(backup_password, salt, kdf_params)

    file_count = sum(1 for p in source.rglob("*") if p.is_file())
    record: Dict[str, Any] = {
        "format": BACKUP_FORMAT,
        "version": VERSION,
        "protection": "ENCRYPTED_BACKUP_WITH_SCRYPT_AES_256_GCM",
        "kdf": {
            "algorithm": "scrypt",
            "salt": b64e(salt),
            **kdf_params,
        },
        "encryption": {
            "algorithm": "AES-256-GCM",
            "nonce": b64e(nonce),
        },
        "metadata": {
            "created": datetime.now(timezone.utc).isoformat(),
            "file_count": file_count,
        },
    }

    encrypted_backup = AESGCM(key).encrypt(nonce, zipped, _protected_aad_for_backup(record))
    record["encrypted_backup"] = b64e(encrypted_backup)

    output = Path(backup_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")


def _safe_extract_zip_bytes(zip_bytes: bytes, destination: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        for info in zf.infolist():
            name = Path(info.filename)
            if name.is_absolute() or ".." in name.parts:
                raise ValueError("Backup contiene rutas inseguras.")
        zf.extractall(destination)


def restore_keystore_backup(
    backup_path: str | Path,
    destination_dir: str | Path,
    backup_password: Optional[str | bytes],
    overwrite: bool = False,
) -> None:
    """Decrypt and restore a keystore backup."""
    record = json.loads(Path(backup_path).read_text(encoding="utf-8"))
    if record.get("format") != BACKUP_FORMAT:
        raise ValueError("El archivo no es un backup de keystore válido.")
    if record.get("kdf", {}).get("algorithm") != "scrypt":
        raise ValueError("KDF de backup no soportado.")

    kdf = record["kdf"]
    params = {
        "n": int(kdf["n"]),
        "r": int(kdf["r"]),
        "p": int(kdf["p"]),
        "length": int(kdf["length"]),
    }
    key = derive_key(backup_password, b64d(kdf["salt"]), params)
    nonce = b64d(record["encryption"]["nonce"])
    encrypted_backup = b64d(record["encrypted_backup"])

    try:
        zipped = AESGCM(key).decrypt(nonce, encrypted_backup, _protected_aad_for_backup(record))
    except InvalidTag as exc:
        raise ValueError("Contraseña incorrecta o backup modificado.") from exc

    destination = Path(destination_dir)
    if destination.exists() and any(destination.iterdir()):
        if not overwrite:
            raise ValueError("El directorio de destino no está vacío. Usa overwrite=True para reemplazarlo.")
        shutil.rmtree(destination)
    destination.mkdir(parents=True, exist_ok=True)
    _safe_extract_zip_bytes(zipped, destination)
