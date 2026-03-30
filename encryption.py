from __future__ import annotations
import os, json, base64, sys
from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from asym_encryption import (
    load_public_key,
    load_private_key,
    rsa_encrypt,
    rsa_decrypt,
    generate_rsa_keypair
)

from signature import (
    sign_container,
    verify_container_signature,
    load_private_key as load_sign_priv,
    load_public_key as load_sign_pub,
    generate_signing_keypair
)


NONCE_LEN = 12
DEK_LEN = 32
TAG_LEN = 16


def b64e(b): return base64.b64encode(b).decode()
def b64d(s): return base64.b64decode(s)


def canonical_json(d):
    return json.dumps(d, sort_keys=True, separators=(",", ":")).encode()


def build_header(path: Path):
    return {
        "version": 3,
        "aead": "AES-256-GCM",
        "asym": "RSA-OAEP-SHA256",
        "created": datetime.now(timezone.utc).isoformat(),
        "filename": path.name,
        "size": path.stat().st_size,
    }


# ================= encriptao =================
def encrypt_file(input_path, output_path, recipients_dict, sign_priv_path, signer_id):
    path = Path(input_path)
    data = path.read_bytes()

    header = build_header(path)

    # 1. File key
    file_key = os.urandom(DEK_LEN)

    # 2. Encrypt file
    nonce = os.urandom(NONCE_LEN)

    recipients = []
    for uid, pub_path in recipients_dict.items():
        pk = load_public_key(pub_path)
        enc_key = rsa_encrypt(pk, file_key)

        recipients.append({
            "id": uid,
            "encrypted_key": b64e(enc_key)
        })

    aad = canonical_json({
        "header": header,
        "recipients": recipients
    })

    cipher = AESGCM(file_key)
    encrypted = cipher.encrypt(nonce, data, aad)

    ciphertext = encrypted[:-TAG_LEN]
    tag = encrypted[-TAG_LEN:]

    container = {
        "header": header,
        "recipients": recipients,
        "payload": {
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
            "tag": b64e(tag)
        }
    }

    sk = load_sign_priv(sign_priv_path)
    container = sign_container(container, sk, signer_id)

    Path(output_path).write_text(json.dumps(container, indent=2))


# ================= decriptao =================
def decrypt_file(input_path, output_path, my_priv_path, my_id, signer_pub_path):
    container = json.loads(Path(input_path).read_text())

    pk = load_sign_pub(signer_pub_path)
    if not verify_container_signature(container, pk):
        raise ValueError("Firma inválida")

    header = container["header"]
    recipients = container["recipients"]
    payload = container["payload"]

    # Find my key
    entry = next((r for r in recipients if r["id"] == my_id), None)
    if not entry:
        raise ValueError("No autorizado")

    sk = load_private_key(my_priv_path)
    file_key = rsa_decrypt(sk, b64d(entry["encrypted_key"]))

    aad = canonical_json({
        "header": header,
        "recipients": recipients
    })

    nonce = b64d(payload["nonce"])
    ciphertext = b64d(payload["ciphertext"])
    tag = b64d(payload["tag"])

    cipher = AESGCM(file_key)
    plaintext = cipher.decrypt(nonce, ciphertext + tag, aad)

    Path(output_path).write_bytes(plaintext)


# ================= main - interaccion en consola =================
def main():
    if len(sys.argv) < 2:
        print("Uso:")
        print(" genrsa priv.pem pub.pem")
        print(" enc in out signer_priv signer_id user1=pub1 user2=pub2 ...")
        print(" dec in out my_priv my_id signer_pub")
        return

    cmd = sys.argv[1]

    if cmd == "genrsa":
        generate_rsa_keypair(sys.argv[2], sys.argv[3])

    elif cmd == "genkeys":
        generate_signing_keypair(sys.argv[2], sys.argv[3])

    elif cmd == "enc":
        input_file = sys.argv[2]
        output_file = sys.argv[3]
        sign_priv = sys.argv[4]
        signer_id = sys.argv[5]

        recipients = {}
        for pair in sys.argv[6:]:
            uid, pub = pair.split("=")
            recipients[uid] = pub

        encrypt_file(input_file, output_file, recipients, sign_priv, signer_id)

    elif cmd == "dec":
        decrypt_file(
            sys.argv[2],
            sys.argv[3],
            sys.argv[4],
            sys.argv[5],
            sys.argv[6]
        )


if __name__ == "__main__":
    main()