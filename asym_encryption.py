"""RSA-OAEP (SHA-256) para encapsulación de la clave de archivo (encryption.py)."""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_rsa_keypair(priv_path: str, pub_path: str) -> None:
    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = Path(priv_path)
    pub = Path(pub_path)
    priv.parent.mkdir(parents=True, exist_ok=True)
    priv.write_bytes(
        pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    pub.write_bytes(
        pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(path: str):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def load_public_key(path: str):
    return serialization.load_pem_public_key(Path(path).read_bytes())


def rsa_encrypt(public_key, data: bytes) -> bytes:
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def rsa_decrypt(private_key, ciphertext: bytes) -> bytes:
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
