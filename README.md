# Final Proyect
We are Computer Engineering students, and we are working on a new app to implement cryptographic algorithms to protect information.
We are:
## Rodriguez Garcia Javier Antonio
### Product Manager / Full Stack

## Gutierrez Avila Tristan Bernardo
### Dessigner / Full Stack / UX UI / Tester

## Pacheco Chavarría Arturo Iván
### Backend / DB / Full stack

## Rodríguez Montes de Oca Andrés
### Full Stack  / Security / Dev OPS

# Architecture & Threat Model
## 2. Architecture Diagram
![Secure Digital Document Vault Architecture](Images/Arch.png)

## 4. Threat Model

### Assets

| Asset | Description | Sensitivity |
|--------|-------------|-------------|
| File contents | Documents stored inside `.vault` containers | **HIGH** — primary protection target |
| File metadata | Filename, timestamps, recipient identifiers in the header | **MEDIUM** — may reveal context |
| Private keys | Signing key, decryption key | **CRITICAL** — can break all security |
| User password | Used to derive the key encryption key | **HIGH** — enables private key decryption |
| Signature validity | Signatures attached to containers | **HIGH** — guarantees non-repudiation |
| Ephemeral symmetric keys | AES-256-GCM keys used per container | **HIGH** — decrypts a single container |
| Key backup files | Encrypted exports of Key Store (`.backup`) | **HIGH** — equivalent to Key Store |
| Nonces | 96-bit values used in AES-GCM | **CRITICAL** — reuse destroys confidentiality |

### Adversaries

| Adversary | Capabilities | Limitations |
|-----------|-------------|-------------|
| **A1 — External attacker (storage access)** | Can read, copy and modify all `.vault` files on disk or cloud. Can observe file sizes and access patterns. | Cannot access the user's running process memory. Does not know the user's password. Cannot break AES-256-GCM. |
| **A2 — Malicious recipient** | Possesses their own private key and can decrypt containers addressed to them. Can attempt to modify containers and re-sign with their key. | Cannot derive other recipients' keys. Cannot forge the sender's signature. Cannot decrypt symKeys wrapped for other recipients. |
| **A3 — Metadata analyst** | Observes file sizes, timestamps, filenames in headers and recipient count. | Cannot decrypt ciphertext. Cannot forge signatures. |
| **A4 — Temporary device access** | Gains brief physical access to the user's machine (e.g. 5 minutes). Could copy the Key Store file or backup files. | Does not know the user's password. Cannot install persistent malware (assumption). Cannot read process memory during execution. |
| **A5 — Network eavesdropper** | Intercepts `.vault` containers in transit over unencrypted channels. | Same as A1 — cannot decrypt without private key. Cannot forge signatures. |
| **A6 — Attacker with backup access** | Obtains the `.backup` file from USB, cloud or email. Can attempt offline brute-force. | Does not know the password. |

### What Attackers CAN Do
- Read and modify any `.vault` file on the storage medium.
- Attempt offline brute-force attacks against the password-protected Key Store or backups.
- Replay or re-order encrypted containers.
- Attempt to strip or substitute signatures (will be detected by verify-before-decrypt).
- Perform statistical analysis on encrypted containers (file size, timing).
- If recipient, decrypt containers addressed to them but not to others.

### What Attackers CANNOT Do
- Read process memory on the user's machine while the vault is running.
- Break AES-256-GCM with current computational resources.
- Reuse a nonce to break AES-GCM.
- Force users to choose weak passwords.
- Install persistent malware or keyloggers (this is OS/endpoint concern).
- Decrypt a container addressed to another recipient without that recipient's private key.

---

## 6. Attack Surface Review

| Entry Point | What Could Go Wrong | Security Property at Risk |
|-------------|---------------------|--------------------------|
| **File input (plaintext upload)** | Malicious file triggers buffer overflow or path traversal during read. Attacker could craft filenames to escape the directory. | Integrity, Availability |
| **Metadata parsing** | Crafted header in `.vault` file causes injection or parsing errors. Attacker could manipulate filename, timestamp or recipient count to cause crashes or bypass checks. | Integrity, Confidentiality |
| **Key import/export** | Importing malformed or malicious public key could cause crashes or key confusion (wrong key bound to wrong identity). Exporting to insecure location leaks public keys. | Authenticity, Confidentiality |
| **Password entry** | Shoulder surfing, keylogging or weak password enables brute-force of Key Store. Timing attacks on password verification could leak information. | Confidentiality of private keys |
| **Sharing workflow** | Encrypting to wrong public key (mislabelled in directory) sends data to unintended recipient. Attacker could swap public keys in the directory. | Confidentiality |
| **Signature verification** | Skipping verification or incorrect implementation allows attacker to present forged documents as authentic. Timing attacks on signature verification. | Authenticity, Integrity |
| **CLI arguments** | Command injection via unsanitized filenames or paths passed as arguments. E.g.: `--file \"'; rm -rf /\"` could execute arbitrary commands. | Integrity, Availability |
| **Encrypted container format** | Attacker modifies nonce, salt or ciphertext blocks in the container. | Integrity, Confidentiality |
| **Key backup/recovery** | Backup file stored in insecure location enables offline brute-force. | Confidentiality of private keys |
| **Multi-recipient key wrapping** | Error encrypting `symKey` for a recipient could send key in plaintext or encrypted with wrong public key. | Confidentiality, Integrity |
| **Nonce generation** | Nonce reuse with same key in AES-GCM enables XOR of plaintexts and destroys confidentiality. | Confidentiality |
| **Verify-before-decrypt ordering** | If verification is skipped or order reversed (decrypt→verify), system processes potentially manipulated ciphertext before verifying authenticity, opening door to side-channel attacks. | Authenticity, Integrity |


## 7. Design Constraints Derived from Requirements
| Requirement                                  | Design Constraint                                           |
| -------------------------------------------- | ----------------------------------------------------------- |
| Confidentiality of file contents             | Must use **AEAD** (AES-GCM or ChaCha20-Poly1305)            |
| Integrity of encrypted data                  | Must verify **AEAD tag** before decrypt output              |
| Authenticity of sender                       | Must implement **digital signatures**                       |
| Verify before trust                          | Must **verify signature before decrypt**                    |
| Private keys must be protected               | Must encrypt private keys with **KDF + KEK**                |
| Weak passwords must be mitigated             | Must use **Argon2id/PBKDF2** with salt and cost             |
| Only intended recipients can access file key | Must use **hybrid encryption** (per-recipient key wrapping) |
| Metadata tampering must be detected          | Must authenticate metadata as **AAD** and sign manifest     |
| Nonce reuse must be prevented                | Must generate **unique nonce per encryption**               |
| Randomness must be unpredictable             | Must use **CSPRNG only**                                    |
| Storage is untrusted                         | Must store only **encrypted containers**                    |
| Downgrade attacks must be blocked            | Must enforce **versioned crypto policy**                    |
| Malformed input must not be processed        | Must use **strict fail-closed parsing**                     |
| Key import can be abused                     | Must validate **key format/size/fingerprint**               |
| Secrets must not leak in logs                | Must implement **redacted security logging**                |
| Security must be implementable               | Must prioritize **AEAD + Signatures + Hybrid + KDF**        |
