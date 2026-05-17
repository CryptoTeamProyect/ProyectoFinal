# Deliverable 6 — Key Management

## 1. Goal

This deliverable adds a secure key management layer to the Secure Digital Document Vault. The goal is to ensure that private keys remain confidential and usable only by authorized users, even if the keystore directory or backup file is stolen.

The implementation is located in:

- `key_management.py`
- `asym_encryption.py`
- `signature.py`
- `encryption.py`
- `test/test_key_management.py`

---

## 2. Private Key Protection

Private keys are never stored in plaintext.

The system encrypts private keys using:

- **KDF:** scrypt
- **Private key encryption:** AES-256-GCM
- **Salt:** 16 random bytes per private key
- **Nonce:** 12 random bytes per keystore encryption
- **Derived key length:** 32 bytes

Private keys are serialized as PKCS#8 DER internally, then encrypted with AES-256-GCM. The plaintext private key is not written to disk.

### KDF parameters

| Parameter | Value |
|---|---:|
| Algorithm | scrypt |
| Salt length | 16 bytes |
| n | 16384 |
| r | 8 |
| p | 1 |
| Derived key length | 32 bytes |
| Encryption algorithm | AES-256-GCM |
| Nonce length | 12 bytes |

scrypt was selected because it is memory-hard and helps slow down offline password guessing if an attacker steals the keystore.

---

## 3. Password-Based Access to Keys

When a private key is needed, the system follows this process:

1. Read the encrypted keystore file.
2. Require a non-empty password.
3. Derive a 256-bit encryption key using scrypt, the stored salt, and the stored KDF parameters.
4. Decrypt the private key with AES-256-GCM.
5. Load the private key only when needed.
6. Reject access if the password is wrong or the keystore was modified.

Passwords are not stored by the system.

---

## 4. Key Storage Format

The keystore file is a structured JSON document.

Example:

```json
{
  "format": "vault-key-store",
  "version": 1,
  "key_type": "rsa-private",
  "protection": "ENCRYPTED_WITH_SCRYPT_AES_256_GCM",
  "kdf": {
    "algorithm": "scrypt",
    "salt": "base64",
    "n": 16384,
    "r": 8,
    "p": 1,
    "length": 32
  },
  "encryption": {
    "algorithm": "AES-256-GCM",
    "nonce": "base64"
  },
  "metadata": {
    "created": "timestamp",
    "usage": "file_key_unwrapping",
    "algorithm": "RSA-OAEP-SHA256"
  },
  "encrypted_private_key": "base64"
}
```

The following fields are included as AES-GCM Associated Authenticated Data (AAD):

- `format`
- `version`
- `key_type`
- `protection`
- `kdf`
- `encryption.algorithm`
- `metadata`

This makes the keystore tamper-evident. If an attacker modifies metadata, KDF parameters, key type, or ciphertext, decryption fails.

---

## 5. Key Lifecycle

| Stage | Design |
|---|---|
| Key generation | RSA-2048 keys are generated for file key unwrapping. Ed25519 keys are generated for signatures. |
| Key storage | Private keys are encrypted with password-derived keys using scrypt + AES-256-GCM. Public keys are stored unencrypted. |
| Key usage | Private keys are decrypted only when needed for signing or decrypting. |
| Key rotation | Generate a new key pair and use it for new documents. Keep old encrypted private keys only to access previously encrypted containers. |
| Key compromise response | Stop trusting the compromised public key, generate a new pair, distribute the new public key through a trusted channel, and re-share documents if needed. |
| Key expiration | Optional policy: define periodic replacement and store planned expiration in metadata. |

---

## 6. Key Backup and Recovery

The system supports encrypted backups using:

- `export_keystore_backup()`
- `restore_keystore_backup()`

The backup process:

1. Compresses the keystore directory in memory.
2. Derives a backup encryption key using scrypt.
3. Encrypts the backup using AES-256-GCM.
4. Stores salt, nonce, KDF parameters, metadata, and encrypted backup data.

Backup file format:

```json
{
  "format": "vault-key-backup",
  "version": 1,
  "protection": "ENCRYPTED_BACKUP_WITH_SCRYPT_AES_256_GCM",
  "kdf": {
    "algorithm": "scrypt",
    "salt": "base64",
    "n": 16384,
    "r": 8,
    "p": 1,
    "length": 32
  },
  "encryption": {
    "algorithm": "AES-256-GCM",
    "nonce": "base64"
  },
  "metadata": {
    "created": "timestamp",
    "file_count": 4
  },
  "encrypted_backup": "base64"
}
```

The backup does not weaken security because it does not expose plaintext private keys. The private keys remain encrypted, and the backup file is encrypted as an additional layer.

CLI usage:

```bash
python3 encryption.py backup vault_data/keys keystore_backup.vaultbackup "BackupSeguro789!"
python3 encryption.py restore keystore_backup.vaultbackup vault_data/keys_restored "BackupSeguro789!"
```

---

## 7. Access Control via Keys

The system enforces access through private keys and recipient entries.

- A user can decrypt only if their recipient ID exists in the container.
- The recipient must have the correct RSA private key.
- The recipient must know the correct password to unlock that private key.
- Sharing still depends on encrypted file keys from D3.
- Wrong key usage, wrong password, missing recipient entry, or modified keystore causes failure.

---

## 8. Threat Model Alignment

### What if an attacker steals the keystore?

The attacker obtains encrypted private keys only. Without the password, they cannot decrypt RSA or Ed25519 private keys. They may attempt offline password guessing, but scrypt slows down that process.

### What if the password is weak?

A weak password can be guessed offline if the attacker has the keystore. The KDF reduces attack speed but cannot make a weak password safe. Users must choose long, high-entropy passwords.

### What if the device is compromised?

The system protects keys at rest. It does not fully protect against malware, keyloggers, memory scraping, or an attacker controlling the device while keys are being used.

### What does the system protect against?

- Stolen keystore files.
- Stolen encrypted backups.
- Wrong passwords.
- Modified keystore files.
- Unauthorized recipient access.

### What does the system not protect against?

- Passwords captured by malware.
- Fully compromised operating systems.
- Users sharing their passwords.
- Public keys obtained from an untrusted source.

---

## 9. Required Tests

The required D6 tests are implemented in `test/test_key_management.py`.

| Requirement | Test |
|---|---|
| Correct password → access granted | `test_d6_correct_password_grants_private_key_access` |
| Wrong password → access denied | `test_d6_wrong_password_denies_private_key_access` |
| Modified keystore → failure | `test_d6_modified_keystore_fails` |
| Backup → restore works | `test_d6_backup_restore_works` |
| Stolen keystore alone → cannot decrypt | `test_d6_stolen_keystore_alone_cannot_decrypt` |

Test result:

```bash
28 passed
```

---

## 10. Security Discussion

### Why encrypt private keys?

Private keys are the root of trust for decryption and signing. If they were stored in plaintext, anyone with access to the storage directory could decrypt files or forge signatures. Encrypting private keys protects them when the device storage or backup is copied.

### What happens if the password is weak?

If the password is weak, an attacker who steals the keystore can attempt offline guessing. scrypt slows down the attack, but it cannot compensate for a very weak password.

### System limitations

- The system depends on users choosing strong passwords.
- The system assumes public keys are authentic.
- The system protects keys at rest, not against a fully compromised device during active use.
- Key rotation is defined and minimally supported by generating new keys, but not fully automated across old containers.
