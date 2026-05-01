from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from asym_encryption import generate_rsa_keypair, load_private_key, load_public_key, rsa_decrypt, rsa_encrypt
from signature import (
    generate_signing_keypair,
    load_private_key as load_sign_priv,
    load_public_key as load_sign_pub,
    sign_container,
    verify_container_signature,
)

NONCE_LEN = 12
DEK_LEN = 32
TAG_LEN = 16


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data)


def canonical_json(data: dict) -> bytes:
    """Serialización canónica usada en AAD.

    Reglas: UTF-8, llaves ordenadas, sin espacios no necesarios y campos de
    seguridad explícitos. Esto evita que dos representaciones equivalentes
    generen AAD distinto por orden de llaves.
    """
    return json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_header(path: Path) -> dict:
    return {
        "version": 4,
        "aead": "AES-256-GCM",
        "asym": "RSA-OAEP-SHA256",
        "signature": "Ed25519",
        "created": datetime.now(timezone.utc).isoformat(),
        "filename": path.name,
        "size": path.stat().st_size,
    }


def _validate_recipients(recipients_dict: Dict[str, str]) -> None:
    if not recipients_dict:
        raise ValueError("Debe existir al menos un destinatario.")
    if len(set(recipients_dict.keys())) != len(recipients_dict):
        raise ValueError("Hay destinatarios duplicados.")
    for uid in recipients_dict:
        if not uid or not isinstance(uid, str):
            raise ValueError("Id de destinatario inválido.")


# ================= cifrado =================
def encrypt_file(input_path, output_path, recipients_dict, sign_priv_path, signer_id, sign_password):
    """Cifra un archivo para varios destinatarios y firma el contenedor.

    Flujo: generar DEK -> envolver DEK por destinatario -> AEAD con AAD -> firmar
    header/recipients/payload. La firma se agrega al final y debe verificarse
    antes de descifrar.
    """
    _validate_recipients(recipients_dict)
    path = Path(input_path)
    data = path.read_bytes()
    header = build_header(path)

    file_key = os.urandom(DEK_LEN)
    nonce = os.urandom(NONCE_LEN)

    recipients = []
    for uid in sorted(recipients_dict):
        pub_path = recipients_dict[uid]
        pk = load_public_key(pub_path)
        enc_key = rsa_encrypt(pk, file_key)
        recipients.append({"id": uid, "encrypted_key": b64e(enc_key)})

    aad = canonical_json({"header": header, "recipients": recipients})

    encrypted = AESGCM(file_key).encrypt(nonce, data, aad)
    ciphertext = encrypted[:-TAG_LEN]
    tag = encrypted[-TAG_LEN:]

    container = {
        "header": header,
        "recipients": recipients,
        "payload": {
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
            "tag": b64e(tag),
        },
    }

    sk = load_sign_priv(sign_priv_path, sign_password)
    container = sign_container(container, sk, signer_id)
    Path(output_path).write_text(json.dumps(container, ensure_ascii=False, indent=2), encoding="utf-8")


# ================= descifrado =================
def decrypt_file(input_path, output_path, my_priv_path, my_id, signer_pub_path, private_password):
    """Verifica la firma y, solo si es válida, descifra el archivo."""
    container = json.loads(Path(input_path).read_text(encoding="utf-8"))

    signer_pk = load_sign_pub(signer_pub_path)
    if not verify_container_signature(container, signer_pk):
        raise ValueError("Firma inválida o ausente")

    try:
        header = container["header"]
        recipients = container["recipients"]
        payload = container["payload"]
    except KeyError as exc:
        raise ValueError("Contenedor incompleto") from exc

    entry = next((r for r in recipients if r.get("id") == my_id), None)
    if not entry:
        raise ValueError("No autorizado")

    recipient_sk = load_private_key(my_priv_path, private_password)
    file_key = rsa_decrypt(recipient_sk, b64d(entry["encrypted_key"]))

    aad = canonical_json({"header": header, "recipients": recipients})
    nonce = b64d(payload["nonce"])
    ciphertext = b64d(payload["ciphertext"])
    tag = b64d(payload["tag"])

    plaintext = AESGCM(file_key).decrypt(nonce, ciphertext + tag, aad)
    Path(output_path).write_bytes(plaintext)


def _usage() -> None:
    print("Uso:")
    print("  genrsa priv.pem pub.pem password")
    print("  genkeys priv.pem pub.pem password")
    print("  enc in out signer_priv signer_id signer_password user1=pub1 user2=pub2 ...")
    print("  dec in out my_priv my_id signer_pub private_password")


def main():
    if len(sys.argv) < 2:
        _usage()
        return

    cmd = sys.argv[1]

    try:
        if cmd == "genrsa":
            if len(sys.argv) != 5:
                _usage()
                sys.exit(2)
            generate_rsa_keypair(sys.argv[2], sys.argv[3], sys.argv[4])

        elif cmd == "genkeys":
            if len(sys.argv) != 5:
                _usage()
                sys.exit(2)
            generate_signing_keypair(sys.argv[2], sys.argv[3], sys.argv[4])

        elif cmd == "enc":
            if len(sys.argv) < 8:
                _usage()
                sys.exit(2)
            input_file = sys.argv[2]
            output_file = sys.argv[3]
            sign_priv = sys.argv[4]
            signer_id = sys.argv[5]
            signer_password = sys.argv[6]

            recipients = {}
            for pair in sys.argv[7:]:
                uid, pub = pair.split("=", 1)
                recipients[uid] = pub

            encrypt_file(input_file, output_file, recipients, sign_priv, signer_id, signer_password)

        elif cmd == "dec":
            if len(sys.argv) != 8:
                _usage()
                sys.exit(2)
            decrypt_file(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7])

        else:
            _usage()
            sys.exit(2)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
