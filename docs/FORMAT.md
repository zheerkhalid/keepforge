# KeepForge file formats

All integers are little-endian unless stated otherwise. Offsets are in bytes.

Cryptographic building blocks (RustCrypto crates, nothing home-made):

| Purpose | Algorithm |
|---|---|
| Key stretching | Argon2id, version 1.3 (0x13), 64-byte output |
| Key separation | HKDF-SHA-256 |
| Encryption | XChaCha20-Poly1305 (24-byte nonce, 16-byte tag) |
| Header check | HMAC-SHA-256 |
| Attachment binding | SHA-256 |

## 1. Vault file (`.kfv`), format version 1

```
+--------------------+  0
| header (128 bytes) |
+--------------------+  128
| payload ciphertext |  payload_len bytes (includes the 16-byte tag)
+--------------------+
| attachment section |  repeated `attachments` times
+--------------------+  end of file (nothing may follow)
```

### 1.1 Header (plaintext, 128 bytes)

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 8 | magic | `4B 46 56 41 55 4C 54 00` ("KFVAULT\0") |
| 8 | 2 | format version | 1 |
| 10 | 2 | header length | 128 |
| 12 | 1 | KDF id | 1 = Argon2id v1.3 |
| 13 | 1 | cipher id | 1 = XChaCha20-Poly1305 |
| 14 | 1 | payload encoding | 1 = length-prefixed CBOR, zero padded |
| 15 | 1 | flags | bit 0: a key file is required. Other bits must be 0 |
| 16 | 4 | Argon2 memory | in KiB |
| 20 | 4 | Argon2 passes (t) | |
| 24 | 4 | Argon2 lanes (p) | |
| 28 | 4 | attachments | number of attachment sections |
| 32 | 32 | salt | random, new whenever the password, key file or KDF settings change |
| 64 | 24 | payload nonce | random, new on every save |
| 88 | 8 | payload_len | ciphertext length including the tag |
| 96 | 32 | header MAC | HMAC-SHA-256(mac key, header[0..96]) |

Nothing secret is in the header. There is no password hint and no vault name.

### 1.2 Keys

```
master (64 bytes) = Argon2id(password = UTF-8 master password,
                             salt     = header salt,
                             secret   = SHA-256(key file bytes)   // only if a key file is used
                             m, t, p  = from the header)

enc key = HKDF-SHA-256(salt = header salt, ikm = master, info = "KeepForge v1 vault encryption",      32 bytes)
mac key = HKDF-SHA-256(salt = header salt, ikm = master, info = "KeepForge v1 header authentication", 32 bytes)
att key = HKDF-SHA-256(salt = header salt, ikm = master, info = "KeepForge v1 attachment encryption", 32 bytes)
```

The key file digest goes into Argon2's own "secret" (K) input. A generated
key file is the text `KeepForge key file v1`, CRLF, 64 hex characters (32
random bytes), CRLF; any other file works too, since only the SHA-256 of
its bytes is used (limit 16 MiB). The master password is used exactly as
typed, as UTF-8, without Unicode normalisation.

Accepted KDF settings when opening:

| Settings | Behaviour |
|---|---|
| memory > 4 GiB, t > 64, p > 64, t = 0, p = 0, memory < 8·p KiB | refused before any allocation |
| memory < 19 MiB or t < 2 (below the OWASP minimum) | opened only after the user confirms |
| memory > 1 GiB or t > 16 | opened only after the user confirms |
| otherwise | opened |

New vaults use 256 MiB, t = 3, p = 4 if that derives within about 1.5 s on
the PC; otherwise a weaker rung is chosen by a one-second benchmark, never
below 19 MiB, t = 2, p = 1.

### 1.3 Payload

```
plaintext  = u32 body_len | CBOR(vault) | zero bytes up to a multiple of 4096
ciphertext = XChaCha20-Poly1305(key = enc key, nonce = header nonce,
                                aad = header[0..128], plaintext) || tag
```

The whole header, MAC included, is the associated data, so changing any
header byte makes decryption fail. The padding must be all zero. The vault
is not compressed (compression would leak information through the length
and leave unwipeable copies in memory).

Opening checks, in this order: header fields and sizes against the real file
length; the header MAC (failure = wrong password or key file, or a changed
header); the payload tag (failure = changed or damaged content); the
padding; every attachment.

The CBOR body is the serde encoding of the `Vault` structure in
`src/model.rs` (maps keyed by field name; unknown fields are ignored and
missing fields take defaults, which is how later versions can add fields).
`schema` is 1. Secrets (passwords, one-time-code seeds, notes, hidden
fields, recovery codes, service keys) are CBOR byte strings.

Since 1.2.0 the `Vault` structure has one more field, `exposure`: a text
holding the saved Exposure check results as JSON (`exposure::Cache` in
`src/exposure/mod.rs`: the values checked, when, what each source answered,
and which breaches of saved sites were found). It is inside the encrypted
payload like everything else. Vaults without it read as having no saved
results; 1.0 and 1.1 ignore it (and drop it if they save the vault). A text
that cannot be read is treated as empty, never as an error. API keys for
the Exposure check sources are kept as `service_keys` entries
(`hibp-api-key`, `leaklookup-api-key`, `enzoic-api-key`).

### 1.4 Attachment sections

Sections appear in the order in which items, and attachments within an
item, appear in the payload.

```
u64 len | blob (len bytes)

blob = XChaCha20-Poly1305(key = att key, nonce = attachment.nonce,
                          aad = "KeepForge v1 attachment" || id (16 bytes, LE) || header salt,
                          file content) || tag
```

The attachment's `id`, `nonce`, original `size`, `name` and
`digest = SHA-256(blob)` live in the encrypted payload. A section whose
digest or tag does not match, a missing section, an extra section and
trailing bytes are all rejected. Attachment keys change with the salt, so
attachments are re-encrypted when the password or KDF settings change.

### 1.5 Files next to the vault

| Name | Meaning |
|---|---|
| `name.kfv.bak1` … `.bakN` | rolling backups, complete vault files; `.bak1` is the newest |
| `name.kfv.<12 hex>.tmp` | a save in progress; renamed over the vault when complete |

Saving writes the temporary file, flushes it (`FlushFileBuffers`), then
renames it over the vault.

## 2. Encrypted file (`.kfx`), format version 1

For the "Encrypt text / file" tool. Streamed in chunks.

### 2.1 Header (plaintext, 80 bytes)

| Offset | Size | Field | Value |
|---:|---:|---|---|
| 0 | 8 | magic | `4B 46 58 46 49 4C 45 00` ("KFXFILE\0") |
| 8 | 2 | format version | 1 |
| 10 | 1 | KDF id | 1 = Argon2id v1.3 |
| 11 | 1 | cipher id | 1 = XChaCha20-Poly1305 |
| 12 | 4 | Argon2 memory | in KiB |
| 16 | 4 | Argon2 passes | |
| 20 | 4 | Argon2 lanes | |
| 24 | 4 | chunk size | 65536 (plaintext bytes per chunk) |
| 28 | 32 | salt | random |
| 60 | 19 | nonce prefix | random |
| 79 | 1 | reserved | 0 |

Only KDF settings in the normal range of section 1.2 are accepted.

### 2.2 Key

```
master = Argon2id(password, salt, m, t, p)                    // 64 bytes, no key file
key    = HKDF-SHA-256(salt, master, info = "KeepForge v1 kfx file encryption", 32 bytes)
```

### 2.3 Chunks

The plaintext stream is a small record followed by the content:

```
u8 kind (0 = file, 1 = text) | u16 name_len | name (UTF-8, at most 255 bytes) | content
```

It is cut into chunks of exactly 65536 bytes; the last chunk may be shorter
(and may be empty). Each chunk is stored as ciphertext followed by its
16-byte tag:

```
nonce(i) = prefix (19 bytes) || counter i (u32, big-endian) || last (1 byte: 1 for the final chunk, else 0)
chunk(i) = XChaCha20-Poly1305(key, nonce(i), aad = header[0..80], plaintext(i)) || tag
```

This is the STREAM construction as implemented by RustCrypto's
`aead::stream` (`EncryptorBE32` / `DecryptorBE32`). Because the counter and
the "last" flag are part of the nonce, swapping, repeating, dropping or
appending chunks, and cutting the file short (at any point, including a
chunk boundary), fail authentication. A reader must treat the output as
valid only after the final chunk has verified; KeepForge writes to a
temporary file and deletes it on any failure. The stored name is reduced to
a plain file name before use.
