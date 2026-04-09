# Manual de usuario — Secure Digital Vault

Guía corta para usar la interfaz web con el módulo Python (`encryption.py`).

---

## 1. Requisitos previos

| Componente | Qué hacer |
|------------|-----------|
| **Python 3** | Instalado y accesible como `python3` en la terminal (o configura la variable de entorno `PYTHON_BIN`). |
| **Dependencias Python** | En la carpeta raíz del proyecto: `pip install -r requirements.txt` |
| **Node.js** | Para ejecutar el frontend Next.js. |

---

## 2. Cómo arrancar la aplicación

1. Abre una terminal en la carpeta **`FRONT`** del proyecto.
2. Instala dependencias (solo la primera vez): `npm install`
3. Inicia el servidor: `npm run dev`
4. En el navegador entra a **http://localhost:3000**

> Si ejecutas `npm run dev` desde la **raíz** del repositorio (donde está el `package.json` que delega a `FRONT`), también funciona.

La interfaz habla con Python desde el servidor de Next.js: debe poder ejecutar `encryption.py` en la **carpeta padre de `FRONT`** (la raíz del repo). Si mueves el proyecto, define `VAULT_PROJECT_ROOT` con la ruta absoluta a esa raíz.

---

## 3. Dónde se guardan los datos

Todo queda en la carpeta **`vault_data/`** (en la raíz del proyecto, junto a `encryption.py`):

| Subcarpeta | Contenido |
|------------|-------------|
| `vault_data/keys/` | Claves generadas desde la pantalla **Claves** |
| `vault_data/out/` | Archivos cifrados (contenedores `.vault`) |
| `vault_data/tmp/` | Archivos temporales (uso interno; no hace falta tocarlos) |

---

## 4. Pantalla **Inicio**

- Indica si **Python** responde correctamente.
- Muestra cuántos archivos de clave y cuántos contenedores `.vault` hay.
- Lista los contenedores en **`out/`** con enlace **Descargar** para bajarlos a tu equipo.

---

## 5. Pantalla **Claves**

Aquí preparas el material criptográfico que usa el programa.

### 5.1 Identificador

En **Identificador nuevo** escribe un nombre corto (solo letras, números, guiones y guión bajo), por ejemplo: `alice`, `bob`, `empresa1`.

### 5.2 Par RSA

- Pulsa **Par RSA**.
- Se crean dos archivos:
  - `{id}_rsa_priv.pem` — **privada** (solo tú; sirve para **descifrar** si te envían un archivo).
  - `{id}_rsa_pub.pem` — **pública** (puedes darla a quien te vaya a cifrar algo para ti).

### 5.3 Par firma (Ed25519)

- Pulsa **Par firma (Ed25519)**.
- Se crean:
  - `{id}_sign_priv.key` — para **firmar** contenedores al cifrar.
  - `{id}_sign_pub.key` — para que el receptor **verifique** la firma al descifrar.

**Ejemplo mínimo para dos personas**

- **Alice** (quien cifra y firma): genera **RSA** y **firma** con id `alice`.
- **Bob** (quien solo recibe): genera solo **RSA** con id `bob` (necesita su privada para descifrar y su pública para que Alice lo incluya como destinatario).

---

## 6. Pantalla **Cifrar**

Orden sugerido:

1. **Archivo**: elige el documento que quieres proteger (cualquier tipo de archivo).
2. **Tu id de firmante**: el mismo texto que usaste al crear el par de firma (ej. `alice`).
3. **Clave privada de firma**: selecciona `{tu_id}_sign_priv.key`.
4. **Nombre salida** (opcional): nombre del `.vault` en `out/` (solo caracteres seguros; si no pones nada, se genera uno automático).
5. **Destinatarios**: para cada uno:
   - **Id destinatario**: debe coincidir con el id que tendrá esa persona al descifrar (ej. `bob`).
   - **RSA pública**: el archivo `{id}_rsa_pub.pem` de esa persona.

Pulsa **Cifrar y firmar**. Si todo va bien, verás un mensaje indicando que se guardó en `vault_data/out/...`.

---

## 7. Pantalla **Verificar y descifrar**

Quien recibió el `.vault` y está en la lista de destinatarios:

1. **Contenedor**: selecciona el archivo `.vault` (JSON).
2. **Tu id**: el mismo que usó el emisor en destinatarios (ej. `bob`).
3. **Tu RSA privada**: tu `{id}_rsa_priv.pem`.
4. **Clave pública de firma del emisor**: el `{id}_sign_pub.key` de quien firmó (ej. `alice_sign_pub.key`).

Pulsa **Descifrar**. El programa **verifica la firma** antes de descifrar; si falla, no obtendrás el archivo. Si es correcto, el navegador descargará el documento original.

---

## 8. Tema visual

En la barra superior, el icono **sol / luna** cambia entre modo claro y oscuro (solo afecta a la interfaz).

---

## 9. Si algo falla

- **Python no listo** en Inicio: comprueba `python3 --version`, que exista `encryption.py` en la raíz del repo y que `pip install -r requirements.txt` se haya ejecutado sin error.
- **Error al cifrar o descifrar**: revisa que los **ids** coincidan exactamente entre cifrado y descifrado y que hayas elegido las claves correctas (firma vs RSA).
- **Otro directorio de proyecto**: define `VAULT_PROJECT_ROOT` apuntando a la carpeta donde están `encryption.py` y `asym_encryption.py`.

---

## 10. Resumen del flujo

```
1) Claves → crear RSA (y firma si vas a enviar)  
2) Cifrar → archivo + firma + lista de destinatarios (ids + RSA pública de cada uno)  
3) Verificar → .vault + tu id + tu RSA privada + RSA pública de firma del emisor  
4) Inicio → descargar copias de los .vault desde la lista  
```

Para detalles técnicos del formato y del modelo de seguridad, consulta **`README.md`** en la raíz del repositorio.
