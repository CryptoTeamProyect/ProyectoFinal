from __future__ import annotations
import os, json, base64, sys
from pathlib import Path
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Asumimos que estos archivos están en la misma carpeta api/
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
        "size": path.stat().st_size if path.exists() else 0,
    }

# ================= encriptao =================
def encrypt_file(input_path, output_path, recipients_dict, sign_priv_path, signer_id):
    path = Path(input_path)
    data = path.read_bytes()

    header = build_header(path)
    file_key = os.urandom(DEK_LEN)
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

# ================= main =================
def main(args=None):
    # Si viene de python_bridge, args no será None
    actual_args = args if args is not None else sys.argv[1:]

    if len(actual_args) < 2:
        print("Uso: genrsa, genkeys, enc, dec")
        return

    # --- LÓGICA DE RUTAS PARA VERCEL ---
    is_vercel = os.environ.get('VERCEL') == '1' or os.environ.get('NODE_ENV') == 'production'
    
    def fix_path(p):
        # Si estamos en Vercel, forzamos que todo se escriba/lea de /tmp
        if is_vercel:
            return os.path.join('/tmp', os.path.basename(p))
        return p
    # ----------------------------------

    cmd = actual_args[0]

    try:
        if cmd == "genrsa":
            priv = fix_path(actual_args[1])
            pub = fix_path(actual_args[2])
            generate_rsa_keypair(priv, pub)
            print(f"Éxito: RSA generado en {priv} y {pub}")

        elif cmd == "genkeys":
            priv = fix_path(actual_args[1])
            pub = fix_path(actual_args[2])
            generate_signing_keypair(priv, pub)
            print(f"Éxito: Firma generada en {priv} y {pub}")

        elif cmd == "enc":
            in_f = fix_path(actual_args[1])
            out_f = fix_path(actual_args[2])
            s_priv = fix_path(actual_args[3])
            s_id = actual_args[4]
            
            recs = {}
            for pair in actual_args[5:]:
                uid, pub_p = pair.split("=")
                recs[uid] = fix_path(pub_p)
            
            encrypt_file(in_f, out_f, recs, s_priv, s_id)
            print(f"Éxito: Archivo cifrado en {out_f}")

        elif cmd == "dec":
            decrypt_file(
                fix_path(actual_args[1]),
                fix_path(actual_args[2]),
                fix_path(actual_args[3]),
                actual_args[4],
                fix_path(actual_args[5])
            )
            print("Éxito: Archivo descifrado")
            
    except Exception as e:
        print(f"Error en encryption.py: {str(e)}")

if __name__ == "__main__":
    main()