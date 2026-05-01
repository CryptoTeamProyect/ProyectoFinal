from __future__ import annotations
import json, base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.exceptions import InvalidSignature


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data)


def canonical_json(data: dict) -> bytes:
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def generate_signing_keypair(priv, pub):
    sk = Ed25519PrivateKey.generate()
    pk = sk.public_key()

    Path(priv).write_bytes(sk.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption()
    ))

    Path(pub).write_bytes(pk.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    ))


def load_private_key(path):
    return Ed25519PrivateKey.from_private_bytes(Path(path).read_bytes())


def load_public_key(path):
    return Ed25519PublicKey.from_public_bytes(Path(path).read_bytes())


def build_manifest(c):
    return {
        "header": c["header"],
        "recipients": c["recipients"],
        "payload": c["payload"],
    }


def sign_container(container, sk, signer_id):
    manifest = build_manifest(container)
    sig = sk.sign(canonical_json(manifest))

    out = dict(container)
    out["signature_block"] = {
        "algorithm": "Ed25519",
        "signer_id": signer_id,
        "signature": b64e(sig),
    }
    return out


def verify_container_signature(container, pk):
    sig_block = container["signature_block"]
    manifest = build_manifest(container)

    try:
        pk.verify(
            b64d(sig_block["signature"]),
            canonical_json(manifest)
        )
        return True
    except InvalidSignature:
        return False
