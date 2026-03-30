# Final Proyect
We are Computer Engineering students, and we are working on a new app to implement cryptographic algorithms to protect information.
Our names are:
## Rodriguez Garcia Javier Antonio
### Product Manager / Full Stack

## Gutierrez Avila Tristan Bernardo
### Dessigner / Full Stack / UX UI / Tester

## Pacheco Chavarría Arturo Iván
### Backend / DB / Full stack

## Rodríguez Montes de Oca Andrés
### Full Stack  / Security / Dev OPS 

# Architecture & Threat Model 

## 1. System Overview

### System Purpose

The central problem the **Secure Digital Document Vault** addresses is the reliance on the security of the transport channel or on third-party storage. Today, when uploading a file to the cloud or sending it by email, it is implicitly assumed that the provider will protect the data.

This system starts from the opposite premise: storage and the network should be treated as insecure by default ("Zero Trust").

The goal is to generate digital containers that protect the information by themselves, ensuring confidentiality, integrity, and proof of origin regardless of where they are stored or how they are transmitted.

### Core Functionality

The system is implemented as a command-line application (CLI) that manages the lifecycle of a protected document through four main mechanisms:

- **Content Encryption with Integrity Protection:** The file is encrypted so that only authorized users can read it. In addition, controls are applied so that any unauthorized modification of the content automatically invalidates the container.

- **Secure Sharing:** The document is encrypted only once. The encryption key is encapsulated individually for each authorized recipient using their respective public keys.

- **Digital Signatures:** The sender cryptographically signs the entire container. This allows the recipient to verify the sender's identity and ensure the file was not altered in transit before attempting to decrypt it.

- **Local Key Protection:** The user's private keys are stored encrypted on disk, protected by a master password. This ensures that stealing the key file alone is not enough to compromise the user's identity.


### Out of Scope

To keep the design strictly focused on the cryptographic protection of the file, the following design limitations are established:

- **No endpoint security guarantees:** If the operating system is compromised (keyloggers, malware, memory access, among others), the vault's security cannot be guaranteed.

- **No full PKI infrastructure:** Certification Authorities (CAs) and online revocation mechanisms (OCSP) are not implemented. Public-key validation is assumed to happen through direct exchange.

- **No password recovery:** By secure design, there are no backdoors. If the user loses the master password, access to their keys and documents is permanently lost.

- **No storage management:** The system processes and generates `.enc` (or similar) files, but it does not handle cloud sync, automatic backups, or version control.

## 2. Architecture Diagram
![Secure Digital Document Vault Architecture](Images/Arch.png) 

## 3. Security Requirements

**R1 — Confidentiality of file contents**  
The system must ensure that the file contents are cryptographically inaccessible to any entity that does not possess the corresponding private key of an authorized recipient. This guarantee must hold even if an adversary obtains full access to the container file (`.enc`), whether stored on disk or intercepted in transit.

**R2 — Data integrity**  
Any unauthorized modification of the encrypted content—whether due to bit corruption, truncation, or intentional tampering—must invalidate the container. If the integrity check fails, the system must not decrypt or output any partial content.

**R3 — Sender authenticity**  
The recipient must be able to cryptographically verify that the file was produced by the expected sender. The system must reject any container whose digital signature does not match the corresponding sender public key, preventing identity spoofing.

**R4 — Private key protection**  
The user's private keys must never be stored in plaintext on the device. The Key Store must remain encrypted using a key derived from the user's password, so that physical access to the key file alone is not sufficient to compromise the owner's identity without knowing that password.

**R5 — Integrity of metadata and container structure**  
The system must detect any alteration of the container header or structure, including the recipient list, format version, or any parameters required for decryption. If metadata has been modified with the intent to change system behavior or mislead the recipient, the process must abort immediately.

**R6 — Verify before decrypt**  
The container's authenticity and integrity must be validated before any decryption operation is performed. If the signature or authentication mechanism is invalid, the system must not process the encrypted content, avoiding attacks that exploit malicious inputs.

**R7 — Cryptographic access control**  
Only identities explicitly selected by the sender during container creation may recover the key required to decrypt the file. There must be no alternative mechanism or "master key" that enables access for unauthorized third parties.


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


## 5. Trust Assumptions

The security guarantees described in the requirements (confidentiality, integrity, and authenticity) rely on the following assumptions. If any of these assumptions do not hold, the system may partially or fully lose its security properties.

**A1 — Reasonably trusted execution environment**  
It is assumed that the operating system and the environment where the vault runs are not compromised (no persistent malware, keyloggers, rootkits, or real-time malicious memory inspection). If the endpoint is compromised, an attacker could capture passwords, keys in use, or plaintext.

**A2 — User password protection**  
It is assumed that the user protects their master password (does not share it, does not reuse it in an obvious way, and avoids storing it in plaintext). The security of the Key Store depends on the strength and confidentiality of this password.

**A3 — Secure randomness generation**  
It is assumed that the platform provides a cryptographically secure random number generator (CSPRNG). This is required for values such as nonces/IVs and session keys.

**A4 — Authentic public keys (no full PKI)**  
It is assumed that the public keys of senders and recipients are authentic (not replaced by an attacker). Since a full PKI infrastructure is not implemented, public-key validation is performed through a mechanism external to the system (direct exchange, fingerprints, a trusted channel, etc.).

**A5 — Storage and network are untrusted**  
It is assumed that the storage and/or transmission medium can be observed and modified by an adversary ("untrusted storage/untrusted network" model). The system must remain secure under this assumption by detecting modifications and preventing content leakage.

**A6 — Software and cryptographic dependency integrity**  
It is assumed that the system implementation and the cryptographic libraries used have not been maliciously altered (e.g., supply-chain attacks) and are executed from legitimate binaries/packages.

**A7 — Basic identity management**  
It is assumed that each cryptographic identity (key pair) corresponds to a real user and that the user understands who they are sharing with (for example, by verifying a fingerprint during key exchange). The system cannot "guess" whether the user selected the correct recipient public key.

**A8 — Limited local access by attackers**  
It is assumed that an attacker with temporary access to the device may read stored files, but does not maintain persistent control during normal system use (for example, cannot observe the process while the user is actively decrypting).


## 6. Attack Surface Review

| Entry Point | What Could Go Wrong | Security Property at Risk |
|-------------|---------------------|-----------------------------|
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




---

# D2 — Secure File Encryption Module

> **"An attacker who obtains the encrypted file must not be able to read or modify its contents without detection."**

A reusable encryption module that guarantees **confidentiality**, **integrity**, and **tamper detection** using **AES-256-GCM** authenticated encryption. At this stage, the system encrypts files for a **single owner only** (no sharing yet).

---

## Encryption Design

### Selected AEAD Algorithm

**AES-256-GCM** (Galois/Counter Mode)

- Industry-standard AEAD cipher recommended by NIST (SP 800-38D).
- Provides authenticated encryption: confidentiality + integrity + authenticity in a single pass.
- Hardware-accelerated on modern CPUs via AES-NI instructions.
- Implementation via Python's [`cryptography`](https://cryptography.io/) library (`cryptography.hazmat.primitives.ciphers.aead.AESGCM`).

### Key Size

| Parameter | Value |
|-----------|-------|
| Data Encryption Key (DEK) | **256 bits** (32 bytes) — AES-256 |
| Key Encryption Key (KEK) | **256 bits** (32 bytes) — derived via PBKDF2 |
| GCM Authentication Tag | **128 bits** (16 bytes) |
| PBKDF2 Iterations | **600,000** |
| KDF Salt | **128 bits** (16 bytes) |

A **fresh DEK** is generated per file using `os.urandom()`. The DEK is then **wrapped** with a KEK derived from the user's passphrase via **PBKDF2-HMAC-SHA256** (random salt, 600,000 iterations).

### Nonce Strategy

| Parameter | Value |
|-----------|-------|
| Nonce length | **96 bits** (12 bytes) |
| Generation method | `os.urandom(12)` — cryptographically secure |
| Storage | Stored in plaintext inside the `.vault` container |

**Uniqueness guarantees:**

1. Every call to `encrypt_file()` generates a new 12-byte nonce via `os.urandom()`.
2. A fresh DEK is also generated per file, making a (key, nonce) reuse practically impossible.
3. We never seed the RNG manually — all randomness comes from the OS-level CSPRNG.

#### Why Nonce Reuse Breaks Security

If the same nonce is used with the same key in AES-GCM:

- **Confidentiality is destroyed**: XOR of two ciphertexts reveals the XOR of plaintexts.
- **Authentication is compromised**: The GHASH key can be recovered, enabling tag forgery.
- **This is catastrophic and unrecoverable** — a single reuse can compromise all messages encrypted with that key.

### Metadata Authentication Strategy (AAD)

The header is bound to encryption as **Associated Authenticated Data**:

```json
{
  "container_version": 1,
  "aead_algorithm": "AES-256-GCM",
  "kdf": "PBKDF2-HMAC-SHA256",
  "pbkdf2_iterations": 600000,
  "nonce_length": 12,
  "tag_length": 16,
  "created_at": "2026-03-08T05:45:18+00:00",
  "original_filename": "document.pdf",
  "original_size": 1024
}
```

### Project Structure
ProyectoFinal/
├── Images/
│ ├── Arch.png # Architecture diagram
│ └── Architecture.png # Detailed architecture diagram
├── test/
│ └── test_encryption.py # Unit tests for encryption module
├── encryption.py # Core encryption/decryption module
└── README.md # This file


---

# D3 — Hybrid Encryption & Multi-Recipient Sharing

> **"A document encrypted once must be securely accessible to multiple recipients, each using their own private key, without exposing the content key to unauthorized parties."**

---

## Hybrid Design Explanation

### Why Hybrid Encryption Is Used

Asymmetric encryption algorithms (such as RSA or ECDH) are computationally expensive and have strict limits on the size of data they can encrypt directly. **Hybrid encryption** solves this by combining the strengths of both worlds:

- A **symmetric key** (DEK — Data Encryption Key) encrypts the actual file content using AES-256-GCM. This is fast and handles arbitrary file sizes.
- An **asymmetric algorithm** (RSA-OAEP or ECDH) encrypts *only the DEK* for each recipient using their public key.

This means the file is encrypted **once**, regardless of how many recipients there are, and only the small DEK is encrypted multiple times — once per recipient.

### Why Symmetric Encryption Is Still Needed

Asymmetric algorithms cannot efficiently encrypt large files:

- **Performance**: AES-256-GCM encrypts gigabytes per second with hardware acceleration. RSA/ECC encryption is orders of magnitude slower.
- **Size limitation**: RSA-2048 can encrypt at most ~214 bytes of plaintext. Real documents are far larger.
- **AEAD guarantees**: AES-256-GCM provides built-in integrity and authenticity via its authentication tag, protecting the ciphertext against tampering.

Symmetric encryption handles the bulk data; asymmetric encryption handles the **key distribution problem**.

### Why Per-Recipient Key Encryption Is Required

Each recipient must be able to independently recover the DEK using **only their own private key**, without requiring coordination with other recipients or access to their keys. This design:

- **Isolates access**: A compromised recipient private key only exposes containers they were explicitly added to — it does not affect other recipients.
- **Enables granular sharing**: The sender controls exactly who can decrypt by choosing which public keys to wrap the DEK with.
- **Avoids a single point of failure**: There is no shared group secret that, if leaked, would expose all recipients at once.

Each `EncryptedKeyEntry` in the container stores: `recipient_id`, a fresh `ephemeral_public_key` (for ECDH), and the `wrapped_dek` — the DEK encrypted with a key derived from the ECDH shared secret.

---

## Security Decisions

### How Do Recipients Identify Their Key?

Each container header contains a **recipient list** — an array of entries, each including:

- A `recipient_id`: a stable identifier bound to the recipient's public key (e.g., a SHA-256 fingerprint of the public key, or a username registered in the local key store).
- An `ephemeral_public_key`: the sender's ephemeral EC public key used for that specific ECDH key agreement.
- A `wrapped_dek`: the DEK encrypted with the key derived from the ECDH shared secret between the sender's ephemeral key and the recipient's static public key.

During decryption, the system scans the recipient list, computes the fingerprint of the local private key, and matches it against `recipient_id`. If a match is found, the corresponding `wrapped_dek` is unwrapped using the private key. If no match is found, decryption is aborted with an explicit error: **"No entry found for this key."**

This design avoids leaking which recipients are present to unauthorized parties — only the holder of the matching private key can confirm their entry.

### What Happens If an Attacker Modifies the Recipient List?

The recipient list is included as part of the **AAD (Associated Authenticated Data)** passed to AES-256-GCM during file encryption, and it is also covered by the **container-level digital signature**.

If an attacker adds, removes, or modifies any recipient entry:

1. **AEAD tag verification fails** — the GCM authentication tag is computed over the ciphertext and AAD. Any change to the AAD (which includes the recipient list) causes tag verification to fail, and decryption is aborted. No plaintext is released.
2. **Signature verification fails** — the container signature is computed over the full manifest (including the recipient list). A modified recipient list produces a different manifest hash, causing signature verification to fail before any decryption is attempted (verify-before-decrypt policy).

The system **fails closed**: if either check fails, the container is rejected entirely.

### What Happens If the Public Key Is Wrong?

If the sender encrypts the DEK with an **incorrect or mismatched public key** (e.g., wrong recipient's key, or a key that has been substituted by an attacker):

- The intended recipient will **not find a matching entry** in the recipient list (their fingerprint won't match any `recipient_id`). Decryption aborts with "No entry found."
- If an attacker substituted their own public key, **only the attacker** can unwrap the DEK — but they would need to also forge the container signature to present a valid container, which requires the sender's private signing key.
- The system cannot automatically detect a wrong-but-valid public key (e.g., an honest mistake by the sender). This is a **key distribution problem** documented in Trust Assumption A4 and A7: public key authenticity must be verified out-of-band (fingerprint comparison, trusted channel, etc.).

This is why the README and threat model explicitly state that **public key validation is the user's responsibility** — the cryptographic system protects against active tampering, but cannot substitute for proper key management.

---

## Container Format (Multi-Recipient)

```json
{
  "container_version": 2,
  "aead_algorithm": "AES-256-GCM",
  "kdf": "HKDF-SHA256",
  "created_at": "2026-03-30T00:00:00+00:00",
  "original_filename": "document.pdf",
  "original_size": 4096,
  "nonce": "<base64>",
  "recipients": [
    {
      "recipient_id": "<SHA-256 fingerprint of recipient public key>",
      "ephemeral_public_key": "<base64 encoded EC public key>",
      "wrapped_dek": "<base64 encoded encrypted DEK>"
    }
  ],
  "ciphertext": "<base64 encoded encrypted file content>",
  "signature": "<base64 encoded Ed25519 signature over full manifest>"
}
```

---

## Unit Tests

Unit tests covering the hybrid encryption module are located in `test/test_encryption.py`. The test suite covers:

- **Key generation**: Verify that RSA/EC key pairs are generated with correct parameters.
- **DEK wrapping/unwrapping**: Confirm that the DEK can be recovered by the correct recipient and rejected for all others.
- **Wrong key rejection**: Assert that decryption with a mismatched private key raises an appropriate exception.
- **Recipient list integrity**: Verify that modifying the recipient list causes AEAD tag verification to fail.
- **Signature verification**: Confirm that a tampered container is rejected before decryption.
- **Multi-recipient round-trip**: Encrypt for N recipients; verify each can independently decrypt and all others are rejected.

Run the tests with:

```bash
pytest test/test_encryption.py -v
```

---
