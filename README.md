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
