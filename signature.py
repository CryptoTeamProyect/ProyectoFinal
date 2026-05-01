from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Optional, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

Password = Optional[Union[str, bytes]]


def _password_bytes(password: Password) -> Optional[bytes]:
    if password is None:
        return None
    if isinstance(password, bytes):
        return password
    return password.encode("utf-8")


def _require_password(password: Password) -> bytes:
    password_b = _password_bytes(password)
    if not password_b:
        raise ValueError("Se requiere una contraseña no vacía para proteger la clave privada de firma.")
    return password_b


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data)


def canonical_json(data: dict) -> bytes:
    """Serialización estable para firma: llaves ordenadas y separadores fijos."""
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def generate_signing_keypair(priv: str, pub: str, password: Password) -> None:
    """Genera un par Ed25519 y cifra la privada con contraseña.

    Se usa PKCS#8 PEM cifrado para que la clave privada no quede en texto plano.
    La pública se guarda en PEM SubjectPublicKeyInfo.
    """
    password_b = _require_password(password)
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()

    priv_path = Path(priv)
    pub_path = Path(pub)
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    pub_path.parent.mkdir(parents=True, exist_ok=True)

    priv_path.write_bytes(
        sk.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(password_b),
        )
    )
    pub_path.write_bytes(
        pk.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(path: str, password: Password):
    data = Path(path).read_bytes()
    if data.startswith(b"-----BEGIN"):
        key = serialization.load_pem_private_key(data, password=_password_bytes(password))
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError("La clave privada de firma no es Ed25519.")
        return key

    # Compatibilidad de lectura para claves antiguas sin cifrar en formato Raw.
    # No se usa al generar claves nuevas.
    if password not in (None, "", b""):
        raise ValueError("La clave de firma antigua no está cifrada; no debe usarse en producción.")
    return Ed25519PrivateKey.from_private_bytes(data)


def load_public_key(path: str):
    data = Path(path).read_bytes()
    if data.startswith(b"-----BEGIN"):
        key = serialization.load_pem_public_key(data)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("La clave pública de firma no es Ed25519.")
        return key

    # Compatibilidad con claves públicas antiguas Raw.
    return Ed25519PublicKey.from_public_bytes(data)


def build_manifest(container: dict) -> dict:
    return {
        "header": container["header"],
        "recipients": container["recipients"],
        "payload": container["payload"],
    }


def sign_container(container: dict, sk: Ed25519PrivateKey, signer_id: str) -> dict:
    manifest = build_manifest(container)
    sig = sk.sign(canonical_json(manifest))

    out = dict(container)
    out["signature_block"] = {
        "algorithm": "Ed25519",
        "signer_id": signer_id,
        "signature": b64e(sig),
    }
    return out


def verify_container_signature(container: dict, pk: Ed25519PublicKey) -> bool:
    try:
        sig_block = container["signature_block"]
        if sig_block.get("algorithm") != "Ed25519":
            return False
        manifest = build_manifest(container)
        pk.verify(b64d(sig_block["signature"]), canonical_json(manifest))
        return True
    except (InvalidSignature, KeyError, TypeError, ValueError):
        return False
