import base64
import json

import pytest

from asym_encryption import generate_rsa_keypair
from encryption import decrypt_file, encrypt_file
from signature import generate_signing_keypair

PASSWORD = "ClaveSegura123!"


def _setup_vault(tmp_path):
    receiver_priv = tmp_path / "receiver1_priv.pem"
    receiver_pub = tmp_path / "receiver1_pub.pem"
    generate_rsa_keypair(str(receiver_priv), str(receiver_pub), PASSWORD)

    signer_priv = tmp_path / "signer_priv.pem"
    signer_pub = tmp_path / "signer_pub.pem"
    generate_signing_keypair(str(signer_priv), str(signer_pub), PASSWORD)

    original = tmp_path / "documento.txt"
    original.write_bytes(b"Contenido confidencial para auditoria guiada")

    vault = tmp_path / "documento.vault"
    encrypt_file(
        str(original),
        str(vault),
        {"receiver1": str(receiver_pub)},
        str(signer_priv),
        "alice",
        PASSWORD,
    )

    return {
        "receiver_priv": receiver_priv,
        "receiver_pub": receiver_pub,
        "signer_pub": signer_pub,
        "vault": vault,
    }


def _load_container(vault_path):
    return json.loads(vault_path.read_text(encoding="utf-8"))


def _write_container(path, container):
    path.write_text(json.dumps(container, ensure_ascii=False, indent=2), encoding="utf-8")


def _try_decrypt(tmp_path, vault_path, keys):
    output = tmp_path / "salida.txt"
    decrypt_file(
        str(vault_path),
        str(output),
        str(keys["receiver_priv"]),
        "receiver1",
        str(keys["signer_pub"]),
        PASSWORD,
    )
    return output


# 1) Metadata: cambiar nombre del archivo en el header.
def test_audit_metadata_modification_is_detected(tmp_path):
    keys = _setup_vault(tmp_path)
    container = _load_container(keys["vault"])
    container["header"]["filename"] = "archivo_falso.txt"

    tampered = tmp_path / "metadata_tampered.vault"
    _write_container(tampered, container)

    with pytest.raises(ValueError, match="Firma inválida"):
        _try_decrypt(tmp_path, tampered, keys)


# 2) Recipient list: agregar un destinatario no autorizado.
def test_audit_recipient_list_modification_is_detected(tmp_path):
    keys = _setup_vault(tmp_path)
    container = _load_container(keys["vault"])
    container["recipients"].append({"id": "attacker", "encrypted_key": "AAAA"})

    tampered = tmp_path / "recipients_tampered.vault"
    _write_container(tampered, container)

    with pytest.raises(ValueError, match="Firma inválida"):
        _try_decrypt(tmp_path, tampered, keys)


# 3) Nonce: alterar un byte del nonce.
def test_audit_nonce_modification_is_detected(tmp_path):
    keys = _setup_vault(tmp_path)
    container = _load_container(keys["vault"])
    nonce = bytearray(base64.b64decode(container["payload"]["nonce"]))
    nonce[0] ^= 0x01
    container["payload"]["nonce"] = base64.b64encode(bytes(nonce)).decode("ascii")

    tampered = tmp_path / "nonce_tampered.vault"
    _write_container(tampered, container)

    with pytest.raises(ValueError, match="Firma inválida"):
        _try_decrypt(tmp_path, tampered, keys)


# 4) Signature: modificar textualemente la firma con caracteres no Base64.
#    Esta prueba DEBERÍA pasar en un sistema estricto, pero actualmente falla:
#    base64.b64decode() acepta sufijos basura como $$$ y la firma sigue validando.
def test_audit_signature_noncanonical_text_should_be_rejected_vulnerability(tmp_path):
    keys = _setup_vault(tmp_path)
    container = _load_container(keys["vault"])
    container["signature_block"]["signature"] += "$$$"

    tampered = tmp_path / "signature_noncanonical.vault"
    _write_container(tampered, container)

    with pytest.raises(ValueError, match="Firma inválida"):
        _try_decrypt(tmp_path, tampered, keys)


# 5) Key identifiers: modificar signer_id de alice a mallory.
#    Esta prueba DEBERÍA pasar en un sistema estricto, pero actualmente falla:
#    signer_id no está cubierto por la firma ni se compara contra un id esperado.
def test_audit_key_identifier_signer_id_should_be_rejected_vulnerability(tmp_path):
    keys = _setup_vault(tmp_path)
    container = _load_container(keys["vault"])
    container["signature_block"]["signer_id"] = "mallory"

    tampered = tmp_path / "signer_id_tampered.vault"
    _write_container(tampered, container)

    with pytest.raises(ValueError, match="Firma inválida"):
        _try_decrypt(tmp_path, tampered, keys)
