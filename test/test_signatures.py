import json
import base64
import pytest

from encryption import encrypt_file, decrypt_file
from asym_encryption import generate_rsa_keypair
from signature import generate_signing_keypair

PASSWORD = "ClaveSegura123!"


def setup_keys(tmp_path):
    # Receptor autorizado
    receiver_priv = tmp_path / "receiver_priv.pem"
    receiver_pub = tmp_path / "receiver_pub.pem"
    generate_rsa_keypair(str(receiver_priv), str(receiver_pub), PASSWORD)

    # Firmante legítimo
    signer_priv = tmp_path / "signer_priv.key"
    signer_pub = tmp_path / "signer_pub.key"
    generate_signing_keypair(str(signer_priv), str(signer_pub), PASSWORD)

    # Firmante falso
    fake_signer_priv = tmp_path / "fake_signer_priv.key"
    fake_signer_pub = tmp_path / "fake_signer_pub.key"
    generate_signing_keypair(str(fake_signer_priv), str(fake_signer_pub), PASSWORD)

    return {
        "receiver_priv": receiver_priv,
        "receiver_pub": receiver_pub,
        "signer_priv": signer_priv,
        "signer_pub": signer_pub,
        "fake_signer_pub": fake_signer_pub,
    }


def create_valid_container(tmp_path, keys):
    original_file = tmp_path / "original.txt"
    original_content = b"archivo de prueba con firma digital"
    original_file.write_bytes(original_content)

    vault_file = tmp_path / "archivo.vault"

    recipients = {
        "receiver1": str(keys["receiver_pub"])
    }

    encrypt_file(
        str(original_file),
        str(vault_file),
        recipients,
        str(keys["signer_priv"]),
        "Tristan",
        PASSWORD
    )

    return original_file, original_content, vault_file


def test_valid_signature_file_accepted(tmp_path):
    keys = setup_keys(tmp_path)
    _, original_content, vault_file = create_valid_container(tmp_path, keys)

    output_file = tmp_path / "salida.txt"

    decrypt_file(
        str(vault_file),
        str(output_file),
        str(keys["receiver_priv"]),
        "receiver1",
        str(keys["signer_pub"]),
        PASSWORD
    )

    assert output_file.exists()
    assert output_file.read_bytes() == original_content


def test_modified_ciphertext_rejected(tmp_path):
    keys = setup_keys(tmp_path)
    _, _, vault_file = create_valid_container(tmp_path, keys)

    tampered_file = tmp_path / "tampered_cipher.vault"
    output_file = tmp_path / "salida.txt"

    container = json.loads(vault_file.read_text(encoding="utf-8"))

    ciphertext = bytearray(base64.b64decode(container["payload"]["ciphertext"]))
    ciphertext[0] ^= 0x01
    container["payload"]["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("utf-8")

    tampered_file.write_text(json.dumps(container, indent=2), encoding="utf-8")

    with pytest.raises(ValueError):
        decrypt_file(
            str(tampered_file),
            str(output_file),
            str(keys["receiver_priv"]),
            "receiver1",
            str(keys["signer_pub"]),
            PASSWORD
        )

    assert not output_file.exists()


def test_modified_metadata_rejected(tmp_path):
    keys = setup_keys(tmp_path)
    _, _, vault_file = create_valid_container(tmp_path, keys)

    tampered_file = tmp_path / "tampered_metadata.vault"
    output_file = tmp_path / "salida.txt"

    container = json.loads(vault_file.read_text(encoding="utf-8"))
    container["header"]["filename"] = "archivo_modificado.txt"

    tampered_file.write_text(json.dumps(container, indent=2), encoding="utf-8")

    with pytest.raises(ValueError):
        decrypt_file(
            str(tampered_file),
            str(output_file),
            str(keys["receiver_priv"]),
            "receiver1",
            str(keys["signer_pub"]),
            PASSWORD
        )

    assert not output_file.exists()


def test_wrong_public_key_rejected(tmp_path):
    keys = setup_keys(tmp_path)
    _, _, vault_file = create_valid_container(tmp_path, keys)

    output_file = tmp_path / "salida.txt"

    with pytest.raises(ValueError):
        decrypt_file(
            str(vault_file),
            str(output_file),
            str(keys["receiver_priv"]),
            "receiver1",
            str(keys["fake_signer_pub"]),
            PASSWORD
        )

    assert not output_file.exists()


def test_signature_removed_rejected(tmp_path):
    keys = setup_keys(tmp_path)
    _, _, vault_file = create_valid_container(tmp_path, keys)

    tampered_file = tmp_path / "no_signature.vault"
    output_file = tmp_path / "salida.txt"

    container = json.loads(vault_file.read_text(encoding="utf-8"))
    del container["signature_block"]

    tampered_file.write_text(json.dumps(container, indent=2), encoding="utf-8")

    with pytest.raises(Exception):
        decrypt_file(
            str(tampered_file),
            str(output_file),
            str(keys["receiver_priv"]),
            "receiver1",
            str(keys["signer_pub"]),
            PASSWORD
        )

    assert not output_file.exists()



def test_multiple_recipients_can_decrypt(tmp_path):
    keys = setup_keys(tmp_path)

    user2_priv = tmp_path / "user2_priv.pem"
    user2_pub = tmp_path / "user2_pub.pem"
    generate_rsa_keypair(str(user2_priv), str(user2_pub), PASSWORD)

    original = tmp_path / "file.txt"
    original.write_bytes(b"multi user test")

    vault = tmp_path / "vault.json"

    recipients = {
        "user1": str(keys["receiver_pub"]),
        "user2": str(user2_pub)
    }

    encrypt_file(
        str(original),
        str(vault),
        recipients,
        str(keys["signer_priv"]),
        "Tristan",
        PASSWORD
    )

    out1 = tmp_path / "out1.txt"
    decrypt_file(str(vault), str(out1),
                 str(keys["receiver_priv"]), "user1",
                 str(keys["signer_pub"]), PASSWORD)

    out2 = tmp_path / "out2.txt"
    decrypt_file(str(vault), str(out2),
                 str(user2_priv), "user2",
                 str(keys["signer_pub"]), PASSWORD)

    assert out1.read_bytes() == b"multi user test"
    assert out2.read_bytes() == b"multi user test"


def test_unauthorized_user_cannot_decrypt(tmp_path):
    keys = setup_keys(tmp_path)

    evil_priv = tmp_path / "evil_priv.pem"
    evil_pub = tmp_path / "evil_pub.pem"
    generate_rsa_keypair(str(evil_priv), str(evil_pub), PASSWORD)

    _, _, vault = create_valid_container(tmp_path, keys)

    with pytest.raises(ValueError):
        decrypt_file(
            str(vault),
            str(tmp_path / "out.txt"),
            str(evil_priv),
            "evil",
            str(keys["signer_pub"]),
            PASSWORD
        )


def test_tampered_recipient_list_fails(tmp_path):
    keys = setup_keys(tmp_path)
    _, _, vault = create_valid_container(tmp_path, keys)

    container = json.loads(vault.read_text(encoding="utf-8"))

    container["recipients"].append({
        "id": "attacker",
        "encrypted_key": "AAAA"
    })

    tampered = tmp_path / "tampered.vault"
    tampered.write_text(json.dumps(container, indent=2), encoding="utf-8")

    with pytest.raises(ValueError):
        decrypt_file(
            str(tampered),
            str(tmp_path / "out.txt"),
            str(keys["receiver_priv"]),
            "receiver1",
            str(keys["signer_pub"]),
            PASSWORD
        )


def test_wrong_private_key_fails(tmp_path):
    keys = setup_keys(tmp_path)

    wrong_priv = tmp_path / "wrong_priv.pem"
    wrong_pub = tmp_path / "wrong_pub.pem"
    generate_rsa_keypair(str(wrong_priv), str(wrong_pub), PASSWORD)

    _, _, vault = create_valid_container(tmp_path, keys)

    with pytest.raises(Exception):
        decrypt_file(
            str(vault),
            str(tmp_path / "out.txt"),
            str(wrong_priv),
            "receiver1",
            str(keys["signer_pub"]),
            PASSWORD
        )


def test_removing_recipient_breaks_access(tmp_path):
    keys = setup_keys(tmp_path)
    _, _, vault = create_valid_container(tmp_path, keys)

    container = json.loads(vault.read_text(encoding="utf-8"))

    container["recipients"] = []

    tampered = tmp_path / "tampered.vault"
    tampered.write_text(json.dumps(container, indent=2), encoding="utf-8")

    with pytest.raises(Exception):
        decrypt_file(
            str(tampered),
            str(tmp_path / "out.txt"),
            str(keys["receiver_priv"]),
            "receiver1",
            str(keys["signer_pub"]),
            PASSWORD
        )

