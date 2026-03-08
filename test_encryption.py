def test_modified_metadata_fails(tmp_path):
    
    original_file = tmp_path / "original.txt"
    original_file.write_bytes(b"contenido protegido con metadata autenticada")

    
    encrypted_file = tmp_path / "archivo.vault"
    tampered_file = tmp_path / "archivo_tampered_metadata.vault"
    decrypted_file = tmp_path / "descifrado.txt"

    passphrase = "ClaveSegura123!"

    # 1. Cifrar normalmente
    encrypt_file(str(original_file), str(encrypted_file), passphrase)

    # 2. Cargar el contenedor JSON
    container = json.loads(encrypted_file.read_text(encoding="utf-8"))

    # 3. Modificar metadata autenticada del header
    container["header"]["original_filename"] = "archivo_modificado.txt"

    # 4. Guardar contenedor manipulado
    tampered_file.write_text(
        json.dumps(container, indent=2, ensure_ascii=False),
        encoding="utf-8"
    )

    # 5. Intentar descifrar: debe fallar por AAD alterado
    with pytest.raises(InvalidTag):
        decrypt_file(str(tampered_file), str(decrypted_file), passphrase)

    # 6. Verificar que no se haya generado salida válida
    assert not decrypted_file.exists()

def test_multiple_encryptions_produce_different_ciphertexts(tmp_path):
    # Archivo original
    original_file = tmp_path / "original.txt"
    original_file.write_bytes(b"mismo contenido para dos cifrados")

    # Salidas de dos cifrados distintos
    encrypted_file_1 = tmp_path / "archivo1.vault"
    encrypted_file_2 = tmp_path / "archivo2.vault"

    passphrase = "ClaveSegura123!"

    # Cifrar dos veces el mismo archivo
    encrypt_file(str(original_file), str(encrypted_file_1), passphrase)
    encrypt_file(str(original_file), str(encrypted_file_2), passphrase)

    # Cargar ambos contenedores
    container1 = json.loads(encrypted_file_1.read_text(encoding="utf-8"))
    container2 = json.loads(encrypted_file_2.read_text(encoding="utf-8"))

    # Comparar componentes relevantes
    ciphertext1 = container1["payload"]["ciphertext"]
    ciphertext2 = container2["payload"]["ciphertext"]

    nonce1 = container1["payload"]["nonce"]
    nonce2 = container2["payload"]["nonce"]

    salt1 = container1["key_envelope"]["kdf_salt"]
    salt2 = container2["key_envelope"]["kdf_salt"]

    assert ciphertext1 != ciphertext2
    assert nonce1 != nonce2
    assert salt1 != salt2
