"""RSA-OAEP (SHA-256) para encapsular la clave de archivo.

Las claves privadas RSA se almacenan cifradas en PKCS#8 usando la protección
que ofrece `BestAvailableEncryption` de `cryptography` (PBES2 con KDF basada en
contraseña + cifrado simétrico). Esto evita guardar llaves privadas en texto
plano dentro de `vault_data/keys/`.
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

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
        raise ValueError("Se requiere una contraseña no vacía para proteger la clave privada RSA.")
    return password_b


def generate_rsa_keypair(priv_path: str, pub_path: str, password: Password) -> None:
    """Genera un par RSA 2048 y cifra la clave privada con contraseña.

    La pública se almacena sin cifrar porque está diseñada para compartirse.
    """
    password_b = _require_password(password)
    pk = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = Path(priv_path)
    pub = Path(pub_path)
    priv.parent.mkdir(parents=True, exist_ok=True)
    pub.parent.mkdir(parents=True, exist_ok=True)

    priv.write_bytes(
        pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(password_b),
        )
    )
    pub.write_bytes(
        pk.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(path: str, password: Password):
    """Carga una clave privada RSA cifrada.

    Se exige contraseña para claves PKCS#8 cifradas. Si la contraseña es
    incorrecta, `cryptography` lanza ValueError.
    """
    return serialization.load_pem_private_key(
        Path(path).read_bytes(),
        password=_password_bytes(password),
    )


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
