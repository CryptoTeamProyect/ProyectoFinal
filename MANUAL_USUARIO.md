# Manual de usuario — Secure Digital Vault

Guía corta para usar la interfaz web con el módulo Python `encryption.py`.

---

## 1. Requisitos previos

| Componente | Qué hacer |
|---|---|
| Python 3 | Instalado y accesible como `python3` o configurado en `PYTHON_BIN`. |
| Dependencias Python | En la raíz: `pip install -r requirements.txt`. |
| Node.js | Necesario para ejecutar el frontend Next.js. |

---

## 2. Cómo arrancar la aplicación

Desde la raíz del proyecto:

```bash
npm install --prefix FRONT
npm run dev
```

Después abre:

```text
http://localhost:3000
```

También puedes entrar a `FRONT/` y ejecutar `npm install` y `npm run dev` desde ahí.

---

## 3. Dónde se guardan los datos

Todo queda en `vault_data/`:

| Subcarpeta | Contenido |
|---|---|
| `vault_data/keys/` | Claves RSA y Ed25519. Las privadas están cifradas con contraseña. |
| `vault_data/out/` | Contenedores `.vault`. |
| `vault_data/tmp/` | Archivos temporales. |

---

## 4. Pantalla Inicio

- Verifica si Python responde correctamente.
- Muestra claves disponibles.
- Muestra contenedores `.vault` generados.
- Permite descargar contenedores desde `vault_data/out/`.

---

## 5. Pantalla Claves

Aquí se genera el material criptográfico.

### 5.1 Identificador

Escribe un id corto, por ejemplo:

```text
alice
bob
empresa1
```

Solo usa letras, números, guion y guion bajo.

### 5.2 Contraseña de clave privada

Antes de generar una clave, escribe una contraseña y confírmala. Esta contraseña protege la clave privada en disco.

Importante:

- No pierdas la contraseña.
- La necesitarás para firmar o descifrar.
- Usa una contraseña larga y no obvia.

### 5.3 Par RSA

Pulsa **Par RSA** para crear:

| Archivo | Uso |
|---|---|
| `{id}_rsa_priv.pem` | Clave privada para descifrar. Está cifrada con contraseña. |
| `{id}_rsa_pub.pem` | Clave pública para que otros te compartan archivos. |

### 5.4 Par firma Ed25519

Pulsa **Par firma (Ed25519)** para crear:

| Archivo | Uso |
|---|---|
| `{id}_sign_priv.key` | Clave privada para firmar contenedores. Está cifrada con contraseña. |
| `{id}_sign_pub.key` | Clave pública para verificar la firma del emisor. |

---

## 6. Pantalla Cifrar

Orden recomendado:

1. Selecciona el archivo a proteger.
2. Escribe tu id de firmante, por ejemplo `alice`.
3. Selecciona tu clave privada de firma, por ejemplo `alice_sign_priv.key`.
4. Escribe la contraseña de esa clave privada.
5. Escribe un nombre de salida opcional, por ejemplo `contrato.vault`.
6. Agrega destinatarios:
   - Id destinatario, por ejemplo `bob`.
   - RSA pública del destinatario, por ejemplo `bob_rsa_pub.pem`.
7. Pulsa **Cifrar y firmar**.

El sistema genera un contenedor `.vault` en `vault_data/out/`.

---

## 7. Pantalla Verificar y descifrar

Quien recibe el `.vault` debe completar:

1. Contenedor `.vault`.
2. Su id como destinatario, por ejemplo `bob`.
3. Su RSA privada, por ejemplo `bob_rsa_priv.pem`.
4. La contraseña de su RSA privada.
5. La clave pública de firma del emisor, por ejemplo `alice_sign_pub.key`.

Pulsa **Descifrar**.

El sistema primero verifica la firma Ed25519. Si la firma no es válida, si falta o si se alteró el contenedor, no se descifra nada.

---

## 8. Flujo mínimo entre Alice y Bob

1. Alice genera RSA y firma.
2. Bob genera RSA.
3. Bob comparte con Alice su `bob_rsa_pub.pem`.
4. Alice cifra un archivo agregando a Bob como destinatario.
5. Alice comparte con Bob el `.vault` y `alice_sign_pub.key`.
6. Bob descifra usando su `bob_rsa_priv.pem`, su contraseña y la pública de firma de Alice.

---

## 9. Errores comunes

| Error | Posible causa |
|---|---|
| `Firma inválida o ausente` | El contenedor fue modificado, la firma no corresponde o usaste la pública de firma incorrecta. |
| `No autorizado` | Tu id no aparece en la lista de destinatarios. |
| Error de contraseña | La clave privada está cifrada y escribiste una contraseña incorrecta. |
| No aparecen claves | Revisa que estén dentro de `vault_data/keys/`. |
| Python no listo | Revisa `python3 --version` y `pip install -r requirements.txt`. |

---

## 10. Resumen criptográfico

```text
Archivo -> AES-256-GCM con DEK aleatoria
DEK -> RSA-OAEP-SHA256 por destinatario
Manifest -> Firma Ed25519
Claves privadas -> PKCS#8 cifrado con contraseña
Verificación -> antes de descifrar
```
