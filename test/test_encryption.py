import json
import base64
import pytest
from cryptography.exceptions import InvalidTag
from encryption import encrypt_file, decrypt_file


def test_encrypt_decrypt_roundtrip(tmp_path):
    original_file = tmp_path / "original.txt"
    original_content = b"archivo de prueba para verificar encrypt -> decrypt."
    original_file.write_bytes(original_content)

    encrypted_file = tmp_path / "archivo.vault"
    decrypted_file = tmp_path / "descifrado.txt"

    passphrase = "ClaveSegura123!"

    encrypt_file(str(original_file), str(encrypted_file), passphrase)
    decrypt_file(str(encrypted_file), str(decrypted_file), passphrase)

    decrypted_content = decrypted_file.read_bytes()
    assert original_content == decrypted_content


def test_wrong_key_fails(tmp_path):
    original_file = tmp_path / "original.txt"
    original_file.write_bytes(b"contenido secreto")

    encrypted_file = tmp_path / "archivo.vault"
    decrypted_file = tmp_path / "descifrado.txt"

    correct_passphrase = "ClaveSegura123!"
    wrong_passphrase = "ClaveIncorrecta456!"

    encrypt_file(str(original_file), str(encrypted_file), correct_passphrase)

    # Intentar descifrar con la incorrecta: debe fallar y lanzar una excepción
    with pytest.raises(InvalidTag):
        decrypt_file(str(encrypted_file), str(decrypted_file), wrong_passphrase)

    # Verificar que no se haya generado un archivo descifrado válido
    assert not decrypted_file.exists()


def test_modified_ciphertext_fails(tmp_path):
   
    original_file = tmp_path / "original.txt"
    original_file.write_bytes(b"contenido secreto que sera alterado")

    encrypted_file = tmp_path / "archivo.vault"
    tampered_file = tmp_path / "archivo_tampered.vault"
    decrypted_file = tmp_path / "descifrado.txt"

    passphrase = "ClaveSegura123!"

    # 1. Cifrar normalmente
    encrypt_file(str(original_file), str(encrypted_file), passphrase)

    # 2. Cargar el contenedor JSON
    container = json.loads(encrypted_file.read_text(encoding="utf-8"))

    # 3. Modificar el ciphertext de forma controlada
    ciphertext_b64 = container["payload"]["ciphertext"]
    ciphertext = bytearray(base64.b64decode(ciphertext_b64))

    # Cambiar un byte del ciphertext
    ciphertext[0] ^= 0x01

    # Volver a guardar el ciphertext alterado
    container["payload"]["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("utf-8")

    # 4. Guardar el contenedor manipulado
    tampered_file.write_text(
        json.dumps(container, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    # 5. Intentar descifrar: debe fallar
    with pytest.raises(InvalidTag):
        decrypt_file(str(tampered_file), str(decrypted_file), passphrase)

    # 6. Verificar que no se haya generado salida válida
    assert not decrypted_file.exists()
