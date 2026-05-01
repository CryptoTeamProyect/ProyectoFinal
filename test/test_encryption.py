import base64
import json

import pytest

from asym_encryption import generate_rsa_keypair, load_private_key
from encryption import decrypt_file, encrypt_file
from signature import generate_signing_keypair, load_private_key as load_sign_private_key

PASSWORD = "ClaveSegura123!"
WRONG_PASSWORD = "ClaveIncorrecta456!"


def setup_keys(tmp_path):
    receiver_priv = tmp_path / "receiver_rsa_priv.pem"
    receiver_pub = tmp_path / "receiver_rsa_pub.pem"
    generate_rsa_keypair(str(receiver_priv), str(receiver_pub), PASSWORD)

    signer_priv = tmp_path / "signer_priv.pem"
    signer_pub = tmp_path / "signer_pub.pem"
    generate_signing_keypair(str(signer_priv), str(signer_pub), PASSWORD)

    return {
        "receiver_priv": receiver_priv,
        "receiver_pub": receiver_pub,
        "signer_priv": signer_priv,
        "signer_pub": signer_pub,
    }


def encrypt_sample(tmp_path, content=b"archivo de prueba para verificar encrypt -> decrypt."):
    keys = setup_keys(tmp_path)
    original_file = tmp_path / "original.txt"
    original_file.write_bytes(content)
    encrypted_file = tmp_path / "archivo.vault"

    encrypt_file(
        str(original_file),
        str(encrypted_file),
        {"receiver1": str(keys["receiver_pub"])},
        str(keys["signer_priv"]),
        "alice",
        PASSWORD,
    )
    return keys, original_file, encrypted_file


def test_encrypt_decrypt_roundtrip(tmp_path):
    original_content = b"archivo de prueba para verificar encrypt -> decrypt."
    keys, _, encrypted_file = encrypt_sample(tmp_path, original_content)
    decrypted_file = tmp_path / "descifrado.txt"

    decrypt_file(
        str(encrypted_file),
        str(decrypted_file),
        str(keys["receiver_priv"]),
        "receiver1",
        str(keys["signer_pub"]),
        PASSWORD,
    )

    assert decrypted_file.read_bytes() == original_content


def test_wrong_private_key_password_fails(tmp_path):
    keys, _, encrypted_file = encrypt_sample(tmp_path, b"contenido secreto")
    decrypted_file = tmp_path / "descifrado.txt"

    with pytest.raises(Exception):
        decrypt_file(
            str(encrypted_file),
            str(decrypted_file),
            str(keys["receiver_priv"]),
            "receiver1",
            str(keys["signer_pub"]),
            WRONG_PASSWORD,
        )

    assert not decrypted_file.exists()


def test_modified_ciphertext_fails(tmp_path):
    keys, _, encrypted_file = encrypt_sample(tmp_path, b"contenido secreto que sera alterado")
    tampered_file = tmp_path / "archivo_tampered.vault"
    decrypted_file = tmp_path / "descifrado.txt"

    container = json.loads(encrypted_file.read_text(encoding="utf-8"))
    ciphertext = bytearray(base64.b64decode(container["payload"]["ciphertext"]))
    ciphertext[0] ^= 0x01
    container["payload"]["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
    tampered_file.write_text(json.dumps(container, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="Firma inválida"):
        decrypt_file(
            str(tampered_file),
            str(decrypted_file),
            str(keys["receiver_priv"]),
            "receiver1",
            str(keys["signer_pub"]),
            PASSWORD,
        )

    assert not decrypted_file.exists()


def test_modified_metadata_fails(tmp_path):
    keys, _, encrypted_file = encrypt_sample(tmp_path, b"contenido secreto con metadata")
    tampered_file = tmp_path / "metadata_tampered.vault"
    decrypted_file = tmp_path / "descifrado.txt"

    container = json.loads(encrypted_file.read_text(encoding="utf-8"))
    container["header"]["filename"] = "otro_nombre.txt"
    tampered_file.write_text(json.dumps(container, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="Firma inválida"):
        decrypt_file(
            str(tampered_file),
            str(decrypted_file),
            str(keys["receiver_priv"]),
            "receiver1",
            str(keys["signer_pub"]),
            PASSWORD,
        )

    assert not decrypted_file.exists()


def test_multiple_encryptions_produce_different_ciphertexts(tmp_path):
    keys = setup_keys(tmp_path)
    original_file = tmp_path / "original.txt"
    original_file.write_bytes(b"mismo contenido, distintas salidas")

    encrypted_file_1 = tmp_path / "archivo1.vault"
    encrypted_file_2 = tmp_path / "archivo2.vault"

    recipients = {"receiver1": str(keys["receiver_pub"])}
    encrypt_file(str(original_file), str(encrypted_file_1), recipients, str(keys["signer_priv"]), "alice", PASSWORD)
    encrypt_file(str(original_file), str(encrypted_file_2), recipients, str(keys["signer_priv"]), "alice", PASSWORD)

    c1 = json.loads(encrypted_file_1.read_text(encoding="utf-8"))
    c2 = json.loads(encrypted_file_2.read_text(encoding="utf-8"))

    assert c1["payload"]["nonce"] != c2["payload"]["nonce"]
    assert c1["payload"]["ciphertext"] != c2["payload"]["ciphertext"]


def test_private_keys_are_encrypted_and_require_password(tmp_path):
    keys = setup_keys(tmp_path)

    rsa_priv_bytes = keys["receiver_priv"].read_bytes()
    sign_priv_bytes = keys["signer_priv"].read_bytes()

    assert b"ENCRYPTED" in rsa_priv_bytes
    assert b"ENCRYPTED" in sign_priv_bytes

    with pytest.raises(Exception):
        load_private_key(str(keys["receiver_priv"]), WRONG_PASSWORD)

    with pytest.raises(Exception):
        load_sign_private_key(str(keys["signer_priv"]), WRONG_PASSWORD)
