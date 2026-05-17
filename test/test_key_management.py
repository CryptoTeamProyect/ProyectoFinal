import base64
import json

import pytest

from asym_encryption import generate_rsa_keypair, load_private_key
from encryption import decrypt_file, encrypt_file
from key_management import export_keystore_backup, restore_keystore_backup
from signature import generate_signing_keypair, load_private_key as load_sign_private_key

PASSWORD = "ClaveSegura123!"
WRONG_PASSWORD = "ClaveIncorrecta456!"
BACKUP_PASSWORD = "BackupSeguro789!"


def test_d6_correct_password_grants_private_key_access(tmp_path):
    rsa_priv = tmp_path / "alice_rsa_priv.pem"
    rsa_pub = tmp_path / "alice_rsa_pub.pem"
    sign_priv = tmp_path / "alice_sign_priv.pem"
    sign_pub = tmp_path / "alice_sign_pub.pem"

    generate_rsa_keypair(str(rsa_priv), str(rsa_pub), PASSWORD)
    generate_signing_keypair(str(sign_priv), str(sign_pub), PASSWORD)

    rsa_key = load_private_key(str(rsa_priv), PASSWORD)
    sign_key = load_sign_private_key(str(sign_priv), PASSWORD)

    assert rsa_key.key_size == 2048
    assert sign_key.public_key() is not None


def test_d6_wrong_password_denies_private_key_access(tmp_path):
    rsa_priv = tmp_path / "bob_rsa_priv.pem"
    rsa_pub = tmp_path / "bob_rsa_pub.pem"

    generate_rsa_keypair(str(rsa_priv), str(rsa_pub), PASSWORD)

    with pytest.raises(ValueError, match="Contraseña incorrecta|keystore modificado"):
        load_private_key(str(rsa_priv), WRONG_PASSWORD)


def test_d6_modified_keystore_fails(tmp_path):
    rsa_priv = tmp_path / "carol_rsa_priv.pem"
    rsa_pub = tmp_path / "carol_rsa_pub.pem"

    generate_rsa_keypair(str(rsa_priv), str(rsa_pub), PASSWORD)

    record = json.loads(rsa_priv.read_text(encoding="utf-8"))
    encrypted = bytearray(base64.b64decode(record["encrypted_private_key"]))
    encrypted[0] ^= 0x01
    record["encrypted_private_key"] = base64.b64encode(bytes(encrypted)).decode("ascii")
    rsa_priv.write_text(json.dumps(record, indent=2), encoding="utf-8")

    with pytest.raises(ValueError, match="Contraseña incorrecta|keystore modificado"):
        load_private_key(str(rsa_priv), PASSWORD)


def test_d6_backup_restore_works(tmp_path):
    keystore = tmp_path / "keystore"
    restored = tmp_path / "restored_keystore"
    backup = tmp_path / "keystore_backup.vaultbackup"

    generate_rsa_keypair(str(keystore / "dave_rsa_priv.pem"), str(keystore / "dave_rsa_pub.pem"), PASSWORD)
    generate_signing_keypair(str(keystore / "dave_sign_priv.pem"), str(keystore / "dave_sign_pub.pem"), PASSWORD)

    export_keystore_backup(keystore, backup, BACKUP_PASSWORD)
    restore_keystore_backup(backup, restored, BACKUP_PASSWORD)

    assert (restored / "dave_rsa_priv.pem").exists()
    assert (restored / "dave_sign_priv.pem").exists()
    assert load_private_key(str(restored / "dave_rsa_priv.pem"), PASSWORD).key_size == 2048
    assert load_sign_private_key(str(restored / "dave_sign_priv.pem"), PASSWORD).public_key() is not None


def test_d6_stolen_keystore_alone_cannot_decrypt(tmp_path):
    receiver_priv = tmp_path / "receiver_rsa_priv.pem"
    receiver_pub = tmp_path / "receiver_rsa_pub.pem"
    signer_priv = tmp_path / "signer_priv.pem"
    signer_pub = tmp_path / "signer_pub.pem"

    generate_rsa_keypair(str(receiver_priv), str(receiver_pub), PASSWORD)
    generate_signing_keypair(str(signer_priv), str(signer_pub), PASSWORD)

    original = tmp_path / "secret.txt"
    original.write_bytes(b"contenido confidencial para D6")
    vault_file = tmp_path / "secret.vault"
    output = tmp_path / "output.txt"

    encrypt_file(
        str(original),
        str(vault_file),
        {"receiver1": str(receiver_pub)},
        str(signer_priv),
        "alice",
        PASSWORD,
    )

    with pytest.raises(Exception):
        decrypt_file(
            str(vault_file),
            str(output),
            str(receiver_priv),
            "receiver1",
            str(signer_pub),
            WRONG_PASSWORD,
        )

    assert not output.exists()
