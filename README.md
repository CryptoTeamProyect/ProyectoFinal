# Secure Digital Document Vault

Sistema para proteger documentos digitales mediante cifrado autenticado, cifrado híbrido multi-destinatario, firmas digitales y protección de claves privadas. Puede usarse desde CLI o mediante la interfaz web en `FRONT/`.

## Estado del proyecto

| Entregable | Estado | Evidencia en código |
|---|---|---|
| D1 Arquitectura y modelo de amenazas | Implementado en documentación | Secciones D1, amenazas, supuestos y restricciones de diseño |
| D2 Cifrado simétrico seguro | Implementado | `encryption.py` usa AES-256-GCM, nonce aleatorio, AAD y detección de manipulación |
| D3 Cifrado híbrido | Implementado | `asym_encryption.py` usa RSA-OAEP-SHA256 para envolver la clave de archivo por destinatario |
| D5 Firmas y autenticación | Implementado | `signature.py` usa Ed25519 y `decrypt_file()` verifica antes de descifrar |
| KeyStore/KDF | Implementado | Claves privadas RSA y Ed25519 se guardan cifradas con contraseña usando PKCS#8 encrypted PEM |
| Pruebas | Implementadas | `test/test_encryption.py` y `test/test_signatures.py` |

---

# D1 — Architecture & Threat Model

## 1. System Overview

La bóveda digital segura resuelve el problema de almacenar y compartir documentos de forma que un atacante que obtenga el archivo cifrado no pueda leerlo, modificarlo silenciosamente ni falsificar su origen.

### Funciones principales

- Cifrar archivos con AEAD.
- Generar una clave simétrica única por archivo.
- Compartir archivos con varios destinatarios mediante cifrado híbrido.
- Firmar digitalmente el contenedor.
- Verificar la firma antes de descifrar.
- Proteger claves privadas con contraseña.
- Detectar manipulación de contenido, metadatos, destinatarios y firma.

### Fuera de alcance

- Sincronización en la nube.
- Autenticación de usuarios tipo login.
- Recuperación automática si el usuario pierde su contraseña.
- Protección contra un sistema operativo completamente comprometido.
- Validación externa de identidad real del dueño de una clave pública.

## 2. Architecture Diagram

```text
+-------------------+             +----------------------------+
| Usuario           |             | Claves públicas            |
| - contraseña      |             | - RSA pública receptor     |
| - archivo         |             | - Ed25519 pública emisor   |
+---------+---------+             +-------------+--------------+
          |                                     |
          v                                     v
+-------------------------------------------------------------+
| Secure Vault App                                             |
| Trusted mientras se ejecuta                                  |
|                                                             |
|  1. Genera DEK aleatoria por archivo                         |
|  2. Cifra payload con AES-256-GCM                            |
|  3. Usa header + recipients como AAD                         |
|  4. Envuelve DEK con RSA-OAEP por receptor                   |
|  5. Firma manifest con Ed25519                               |
|  6. Verifica firma antes de descifrar                        |
+---------------+----------------------+----------------------+
                |                      |
                v                      v
+---------------------------+   +-----------------------------+
| Encrypted File Container  |   | Key Store                   |
| Untrusted storage         |   | Trusted si contraseña segura|
| - header                  |   | - RSA privada cifrada       |
| - recipients              |   | - Ed25519 privada cifrada   |
| - nonce                   |   | - claves públicas           |
| - ciphertext              |   +-----------------------------+
| - tag                     |
| - signature_block         |
+---------------------------+
```

### Componentes confiables

- Aplicación local mientras se ejecuta.
- Biblioteca `cryptography`.
- Generador aleatorio del sistema operativo.
- Claves privadas solo después de desbloquearse con contraseña.

### Componentes no confiables

- Contenedores `.vault` almacenados en disco o compartidos.
- Archivos recibidos de terceros.
- Metadatos dentro del contenedor hasta que se verifica la firma y el tag AEAD.
- Claves públicas si el usuario no las obtiene por un canal confiable.

## 3. Security Requirements

| Requisito | Propiedad esperada |
|---|---|
| Confidencialidad del contenido | Un atacante con el contenedor no puede leer el archivo sin la clave privada autorizada. |
| Integridad del contenido | Cualquier cambio al ciphertext causa rechazo. |
| Autenticidad del emisor | El receptor verifica que el contenedor fue firmado por la clave Ed25519 esperada. |
| Confidencialidad de claves privadas | Las claves privadas se guardan cifradas con contraseña. |
| Protección contra manipulación | Cambios en metadatos, destinatarios, payload o firma son detectados. |
| Control de acceso | Solo destinatarios incluidos pueden desenvolver la clave de archivo. |
| Verificación antes de descifrar | La firma se verifica antes de procesar el descifrado. |

## 4. Threat Model

### Assets

- Contenido de archivos.
- Metadatos de seguridad.
- Lista de destinatarios.
- Clave simétrica de archivo, DEK.
- Claves privadas RSA y Ed25519.
- Validez de la firma.
- Contraseñas de protección de claves privadas.

### Adversarios considerados

| Adversario | Puede hacer | No puede hacer |
|---|---|---|
| Atacante externo con acceso al `.vault` | Copiar, borrar, modificar o reenviar contenedores. | Romper AES-GCM, RSA-OAEP o Ed25519. |
| Receptor malicioso | Intentar alterar destinatarios o metadata. | Descifrar para otros destinatarios sin su clave privada. |
| Atacante con acceso temporal al equipo | Copiar `vault_data/keys/`. | Usar claves privadas sin contraseña. |
| Atacante de metadatos | Cambiar filename, version, recipients o algoritmos. | Hacer que la firma y el tag sigan siendo válidos. |

## 5. Trust Assumptions

- El usuario protege sus contraseñas.
- Las claves públicas se obtienen por un canal confiable.
- El sistema operativo entrega aleatoriedad criptográficamente segura.
- La librería `cryptography` se usa sin modificar.
- El almacenamiento de contenedores es no confiable.
- El dispositivo no está completamente comprometido durante el uso.

## 6. Attack Surface Review

| Entrada | Qué puede salir mal | Propiedad en riesgo | Mitigación |
|---|---|---|---|
| Archivo de entrada | Archivo muy grande o inesperado | Disponibilidad | Validación básica y manejo de errores |
| Parser JSON del contenedor | JSON malformado o campos faltantes | Integridad | Fallar cerrado con excepciones |
| Metadata | Cambio de filename, versión o algoritmo | Integridad/autenticidad | Metadata incluida en AAD y firma |
| Lista de destinatarios | Agregar, quitar o reemplazar receptores | Control de acceso | Recipients incluidos en AAD y firma |
| Claves privadas | Robo de archivos de claves | Confidencialidad | PKCS#8 cifrado con contraseña |
| Firma | Firma ausente o alterada | Autenticidad | Verificar antes de descifrar |
| Nonce | Reutilización con la misma clave | Confidencialidad | Nonce aleatorio y DEK nueva por archivo |
| CLI/API | Parámetros incorrectos | Integridad/disponibilidad | Validación de argumentos e ids |

## 7. Design Constraints Derived from Requirements

| Requirement | Design Constraint |
|---|---|
| Confidentiality of file contents | AES-256-GCM con DEK de 32 bytes |
| Integrity must be guaranteed | AEAD tag obligatorio |
| Authenticity required | Firma Ed25519 del manifest |
| Private keys must be protected | Claves privadas cifradas con contraseña mediante PKCS#8 encrypted PEM |
| Only intended recipients can access | Cifrado híbrido: DEK envuelta por cada RSA pública |
| Metadata tampering must be detected | Header y recipients en AAD y manifest firmado |
| Signature must be checked first | `decrypt_file()` verifica firma antes de descifrar |
| Nonce reuse must be avoided | Nonce de 12 bytes aleatorio + DEK nueva por archivo |
| Storage is untrusted | Solo se guarda contenedor cifrado y firmado |

---

# D2 — Secure Symmetric Encryption Module

## Encryption Design

### AEAD seleccionado

Se usa `AESGCM` de la librería `cryptography`, con AES-256-GCM.

### Parámetros

| Parámetro | Valor |
|---|---|
| Data Encryption Key, DEK | 32 bytes, generada con `os.urandom(32)` |
| Nonce | 12 bytes, generado con `os.urandom(12)` |
| Tag | 16 bytes, producido por AES-GCM |
| AAD | JSON canónico de `header` y `recipients` |

## Metadata protegida

El AAD incluye:

```json
{
  "header": {
    "version": 4,
    "aead": "AES-256-GCM",
    "asym": "RSA-OAEP-SHA256",
    "signature": "Ed25519",
    "created": "...",
    "filename": "documento.pdf",
    "size": 1234
  },
  "recipients": [
    { "id": "bob", "encrypted_key": "..." }
  ]
}
```

Si un atacante modifica metadata o recipients, el tag AEAD deja de validar y además la firma Ed25519 también falla.

## Por qué AEAD y no cifrado + hash

AEAD combina confidencialidad e integridad en una sola primitiva segura y evita errores comunes de composición, como verificar hashes no autenticados, usar MAC incorrectamente o descifrar antes de validar.

## Qué pasa si se repite el nonce

En GCM, repetir nonce con la misma clave puede revelar relaciones entre plaintexts y comprometer la autenticación. Para evitarlo, este proyecto genera una DEK nueva por archivo y un nonce aleatorio de 96 bits por cifrado.

---

# D3 — Hybrid Encryption

## Diseño

El archivo no se cifra con RSA. Se cifra una vez con AES-GCM usando una DEK aleatoria. Después, esa DEK se cifra por separado para cada destinatario usando su clave pública RSA.

```text
Archivo original -> AES-256-GCM con DEK -> ciphertext
DEK -> RSA-OAEP-SHA256 para Bob -> encrypted_key de Bob
DEK -> RSA-OAEP-SHA256 para Alice -> encrypted_key de Alice
```

## Identificación de destinatarios

Cada destinatario tiene un `id` explícito. Durante el descifrado, el usuario indica su `my_id`; el sistema busca la entrada correspondiente y usa su RSA privada para desenvolver la DEK.

## Container format

```json
{
  "header": {},
  "recipients": [
    { "id": "alice", "encrypted_key": "base64" },
    { "id": "bob", "encrypted_key": "base64" }
  ],
  "payload": {
    "nonce": "base64",
    "ciphertext": "base64",
    "tag": "base64"
  },
  "signature_block": {
    "algorithm": "Ed25519",
    "signer_id": "tristan",
    "signature": "base64"
  }
}
```

## Decisiones de seguridad

- Se usa RSA-OAEP-SHA256 porque es un esquema moderno de cifrado asimétrico para mensajes pequeños.
- RSA solo cifra la DEK, no el archivo completo.
- Los destinatarios se ordenan por `id` antes de construir el contenedor para tener una representación estable.
- El arreglo `recipients` se incluye en AAD y en la firma, por lo que agregar o quitar destinatarios invalida el contenedor.

---

# D5 — Signatures & Authentication

## Algoritmo

Se usa Ed25519 porque ofrece firmas modernas, rápidas y con tamaño fijo. La clave privada de firma se almacena cifrada con contraseña en formato PKCS#8.

## Qué se firma

Se firma un manifest canónico con:

- `header`
- `recipients`
- `payload`, incluyendo nonce, ciphertext y tag

No se firma el propio `signature_block`, porque se agregaría después de generar la firma.

## Flujo de cifrado

```text
1. Leer archivo
2. Generar DEK
3. Cifrar archivo con AES-GCM
4. Envolver DEK para cada receptor con RSA-OAEP
5. Construir contenedor
6. Firmar manifest con Ed25519
7. Guardar .vault
```

## Flujo de verificación y descifrado

```text
1. Leer contenedor
2. Cargar clave pública Ed25519 del emisor
3. Verificar firma
4. Si la firma no es válida, rechazar
5. Buscar encrypted_key del destinatario
6. Desbloquear RSA privada con contraseña
7. Desenvolver DEK
8. Descifrar AES-GCM con AAD
```

## Por qué firmar ciphertext y no plaintext

Firmar el ciphertext permite verificar autenticidad antes de descifrar. Así el sistema no procesa plaintext ni intenta usar contenido potencialmente manipulado antes de comprobar su origen.

## Qué pasa si no se verifica primero

Si se descifra antes de verificar, el sistema procesa datos no autenticados y puede abrir la puerta a errores lógicos, exposición de información o ataques por diferencias de comportamiento.

## Qué pasa si metadata queda fuera

Un atacante podría cambiar filename, algoritmos, destinatarios o contexto sin romper la firma. Por eso metadata y recipients se incluyen en AAD y en el manifest firmado.

---

# KeyStore / KDF

Las claves privadas no se almacenan en texto plano.

- RSA privada: PEM PKCS#8 cifrado con contraseña.
- Ed25519 privada: PEM PKCS#8 cifrado con contraseña.
- Claves públicas: PEM sin cifrar.

`cryptography.serialization.BestAvailableEncryption(password)` usa un esquema estándar de cifrado de clave privada basado en contraseña. En la práctica, esto deriva una clave de cifrado desde la contraseña y guarda la clave privada protegida en disco.

Limitaciones: si el usuario usa una contraseña débil, un atacante con el archivo de clave puede intentar ataques offline. Por eso la interfaz exige mínimo 8 caracteres y el manual recomienda contraseñas largas.

---

# Uso por CLI

## Instalar dependencias

```bash
pip install -r requirements.txt
```

## Generar claves

```bash
python3 encryption.py genrsa alice_rsa_priv.pem alice_rsa_pub.pem "ClaveSegura123!"
python3 encryption.py genkeys alice_sign_priv.key alice_sign_pub.key "ClaveSegura123!"
```

## Cifrar y firmar

```bash
python3 encryption.py enc documento.pdf documento.vault alice_sign_priv.key alice "ClaveSegura123!" bob=bob_rsa_pub.pem alice=alice_rsa_pub.pem
```

## Verificar y descifrar

```bash
python3 encryption.py dec documento.vault salida.pdf bob_rsa_priv.pem bob alice_sign_pub.key "ClaveBob123!"
```

---

# Uso con interfaz web

```bash
npm install --prefix FRONT
npm run dev
```

Luego abrir:

```text
http://localhost:3000
```

La interfaz permite:

- Generar claves privadas protegidas con contraseña.
- Cifrar y firmar documentos.
- Seleccionar múltiples destinatarios.
- Verificar y descifrar contenedores.
- Descargar contenedores `.vault`.

---

# Pruebas

```bash
pytest -q
```

Pruebas incluidas:

- Encrypt → decrypt retorna el mismo archivo.
- Contraseña incorrecta de clave privada falla.
- Ciphertext modificado falla.
- Metadata modificada falla.
- Múltiples cifrados producen nonce/ciphertext distintos.
- Las claves privadas se guardan cifradas.
- Firma válida acepta el archivo.
- Firma incorrecta o ausente rechaza el archivo.
- Lista de destinatarios modificada falla.
- Usuario no autorizado no descifra.
- Remover receptor rompe acceso.
