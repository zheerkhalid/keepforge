//! `.kfx`: a text or a file encrypted with a password, for sharing a secret
//! with someone. Same construction as the vault (Argon2id, HKDF-SHA-256,
//! XChaCha20-Poly1305), but streamed in chunks so large files work.
//!
//! Chunks use the STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár)
//! as implemented by RustCrypto's `aead::stream` (BE32 flavour): every
//! chunk's nonce is a random 19-byte prefix, a 32-bit big-endian chunk
//! counter and a one-byte "last chunk" flag. Reordered, dropped, repeated or
//! missing-at-the-end chunks therefore fail authentication. The header is
//! the associated data of every chunk. Layout: see `docs/FORMAT.md`.

use crate::secret::{random_array, SecretString};
use crate::vaultfile::{self, KdfCheck, KdfParams, VaultError};
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 8] = b"KFXFILE\0";
pub const VERSION: u16 = 1;
pub const HEADER_LEN: usize = 80;
/// Plaintext bytes per chunk.
pub const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;
const MAX_NAME: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Content {
    File,
    Text,
}

/// What is stored (encrypted) in front of the content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Meta {
    pub content: Content,
    /// The original file name (no folders). Empty for text.
    pub name: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum KfxError {
    NotKfx,
    NewerVersion(u16),
    /// Wrong password, or the file was changed, cut short or reordered.
    Failed,
    UnusualKdf(KdfParams),
    Cancelled,
    Io(String),
    Kdf(VaultError),
}

impl std::fmt::Display for KfxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KfxError::NotKfx => f.write_str("This is not a KeepForge encrypted file (.kfx)."),
            KfxError::NewerVersion(v) => write!(
                f,
                "This file was made by a newer version of KeepForge (format {v})."
            ),
            KfxError::Failed => f.write_str(
                "Could not decrypt: the password is wrong, or the file was changed or is incomplete.",
            ),
            KfxError::UnusualKdf(p) => write!(
                f,
                "This file asks for unusual key-stretching settings ({}), so it was not opened.",
                p.describe()
            ),
            KfxError::Cancelled => f.write_str("Cancelled."),
            KfxError::Io(e) => f.write_str(e),
            KfxError::Kdf(e) => e.fmt(f),
        }
    }
}

fn io(e: std::io::Error) -> KfxError {
    KfxError::Io(format!("File error: {e}"))
}

fn header_bytes(kdf: &KdfParams, salt: &[u8; 32], prefix: &[u8; 19]) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..8].copy_from_slice(MAGIC);
    h[8..10].copy_from_slice(&VERSION.to_le_bytes());
    h[10] = vaultfile::KDF_ARGON2ID;
    h[11] = vaultfile::CIPHER_XCHACHA20_POLY1305;
    h[12..16].copy_from_slice(&kdf.m_kib.to_le_bytes());
    h[16..20].copy_from_slice(&kdf.t.to_le_bytes());
    h[20..24].copy_from_slice(&kdf.p.to_le_bytes());
    h[24..28].copy_from_slice(&(CHUNK as u32).to_le_bytes());
    h[28..60].copy_from_slice(salt);
    h[60..79].copy_from_slice(prefix);
    h
}

fn cipher(
    password: &SecretString,
    kdf: &KdfParams,
    salt: &[u8; 32],
) -> Result<XChaCha20Poly1305, KfxError> {
    let master = vaultfile::derive_master(password, None, kdf, salt).map_err(KfxError::Kdf)?;
    let key = vaultfile::subkey(&master, salt, vaultfile::LABEL_KFX);
    Ok(XChaCha20Poly1305::new_from_slice(key.as_slice()).expect("32-byte key"))
}

/// Fills `buf` as far as the reader allows; returns the number of bytes read.
fn read_full(r: &mut impl Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

/// Encrypts `input` into `output`. `progress` gets the plaintext bytes done.
pub fn encrypt(
    mut input: impl Read,
    mut output: impl Write,
    password: &SecretString,
    kdf: KdfParams,
    meta: &Meta,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<(), KfxError> {
    let kdf = kdf.clamped();
    let salt: [u8; 32] = random_array();
    let prefix: [u8; 19] = random_array();
    let header = header_bytes(&kdf, &salt, &prefix);
    let aead = cipher(password, &kdf, &salt)?;
    let mut stream = EncryptorBE32::from_aead(aead, prefix.as_ref().into());
    output.write_all(&header).map_err(io)?;

    // The first chunk starts with the metadata record.
    let name: String = meta.name.chars().take(MAX_NAME).collect();
    let name = &name.as_bytes()[..name.len().min(MAX_NAME)];
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(CHUNK + TAG));
    buf.push(match meta.content {
        Content::File => 0,
        Content::Text => 1,
    });
    buf.extend_from_slice(&(name.len() as u16).to_le_bytes());
    buf.extend_from_slice(name);

    let mut done = 0u64;
    // One chunk of read-ahead tells us which chunk is the last one.
    let mut next: Zeroizing<Vec<u8>> = Zeroizing::new(vec![0u8; CHUNK]);
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(KfxError::Cancelled);
        }
        let room = CHUNK - buf.len();
        let got = read_full(&mut input, &mut next[..room]).map_err(io)?;
        buf.extend_from_slice(&next[..got]);
        done += got as u64;
        progress(done);
        if buf.len() < CHUNK {
            // The input ended inside this chunk: it is the last one.
            stream
                .encrypt_last_in_place(&header, &mut *buf)
                .map_err(|_| KfxError::Io("Encryption failed.".into()))?;
            output.write_all(&buf).map_err(io)?;
            break;
        }
        // The chunk is full. Peek one byte to see whether more follows.
        let mut peek = [0u8; 1];
        let more = read_full(&mut input, &mut peek).map_err(io)?;
        if more == 0 {
            stream
                .encrypt_last_in_place(&header, &mut *buf)
                .map_err(|_| KfxError::Io("Encryption failed.".into()))?;
            output.write_all(&buf).map_err(io)?;
            break;
        }
        stream
            .encrypt_next_in_place(&header, &mut *buf)
            .map_err(|_| KfxError::Io("The file is too large.".into()))?;
        output.write_all(&buf).map_err(io)?;
        buf.zeroize();
        buf.push(peek[0]);
        done += 1;
    }
    output.flush().map_err(io)?;
    Ok(())
}

/// Decrypts `input`. Once the metadata is known, `open_output` is called to
/// get the place the content is written to. On any error the caller should
/// discard what was written: only a successful return means the content is
/// complete and authentic.
pub fn decrypt<W: Write>(
    mut input: impl Read,
    password: &SecretString,
    open_output: impl FnOnce(&Meta) -> std::io::Result<W>,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> Result<(Meta, W), KfxError> {
    let mut header = [0u8; HEADER_LEN];
    let n = read_full(&mut input, &mut header).map_err(io)?;
    if n < 10 || &header[0..8] != MAGIC {
        return Err(KfxError::NotKfx);
    }
    let version = u16::from_le_bytes([header[8], header[9]]);
    if version > VERSION {
        return Err(KfxError::NewerVersion(version));
    }
    let u32_at = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().expect("4 bytes"));
    if n < HEADER_LEN
        || version == 0
        || header[10] != vaultfile::KDF_ARGON2ID
        || header[11] != vaultfile::CIPHER_XCHACHA20_POLY1305
        || u32_at(24) as usize != CHUNK
        || header[79] != 0
    {
        return Err(KfxError::NotKfx);
    }
    let kdf = KdfParams {
        m_kib: u32_at(12),
        t: u32_at(16),
        p: u32_at(20),
    };
    if kdf.check() != KdfCheck::Ok {
        return Err(KfxError::UnusualKdf(kdf));
    }
    let salt: [u8; 32] = header[28..60].try_into().expect("32 bytes");
    let prefix: [u8; 19] = header[60..79].try_into().expect("19 bytes");
    let aead = cipher(password, &kdf, &salt)?;
    let mut stream = Some(DecryptorBE32::from_aead(aead, prefix.as_ref().into()));

    let mut open_output = Some(open_output);
    let mut out: Option<(Meta, W)> = None;
    let mut done = 0u64;
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(CHUNK + TAG));
    let mut carry: Option<u8> = None;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Err(KfxError::Cancelled);
        }
        buf.zeroize();
        buf.resize(CHUNK + TAG, 0);
        let mut have = 0;
        if let Some(b) = carry.take() {
            buf[0] = b;
            have = 1;
        }
        have += read_full(&mut input, &mut buf[have..]).map_err(io)?;
        buf.truncate(have);
        let mut last = have < CHUNK + TAG;
        if !last {
            let mut peek = [0u8; 1];
            if read_full(&mut input, &mut peek).map_err(io)? == 0 {
                last = true;
            } else {
                carry = Some(peek[0]);
            }
        }
        if have < TAG {
            return Err(KfxError::Failed);
        }
        if last {
            stream
                .take()
                .ok_or(KfxError::Failed)?
                .decrypt_last_in_place(&header, &mut *buf)
                .map_err(|_| KfxError::Failed)?;
        } else {
            stream
                .as_mut()
                .ok_or(KfxError::Failed)?
                .decrypt_next_in_place(&header, &mut *buf)
                .map_err(|_| KfxError::Failed)?;
        }
        // Authenticated plaintext from here on.
        let mut body: &[u8] = &buf;
        if out.is_none() {
            if body.len() < 3 {
                return Err(KfxError::Failed);
            }
            let content = match body[0] {
                0 => Content::File,
                1 => Content::Text,
                _ => return Err(KfxError::Failed),
            };
            let name_len = u16::from_le_bytes([body[1], body[2]]) as usize;
            if name_len > MAX_NAME || body.len() < 3 + name_len {
                return Err(KfxError::Failed);
            }
            let name = safe_name(&String::from_utf8_lossy(&body[3..3 + name_len]));
            body = &body[3 + name_len..];
            let meta = Meta { content, name };
            let open = open_output.take().expect("used once");
            let w = open(&meta).map_err(io)?;
            out = Some((meta, w));
        }
        let (_, w) = out.as_mut().expect("set above");
        w.write_all(body).map_err(io)?;
        done += body.len() as u64;
        progress(done);
        if last {
            let (meta, mut w) = out.take().expect("set above");
            w.flush().map_err(io)?;
            return Ok((meta, w));
        }
    }
}

/// Reduces a stored name to a plain file name that is safe to create:
/// no folders, no reserved characters, never empty.
pub fn safe_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_control() || "<>:\"/\\|?*".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').trim().to_string();
    let stem = cleaned.split('.').next().unwrap_or("").to_uppercase();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.as_bytes()[3].is_ascii_digit());
    if cleaned.is_empty() || reserved {
        "decrypted file".to_string()
    } else {
        cleaned
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret::secret_string;
    use crate::vaultfile::tests::TEST_KDF;

    fn enc(data: &[u8], pw: &str, meta: &Meta) -> Vec<u8> {
        let mut out = Vec::new();
        encrypt(
            data,
            &mut out,
            &secret_string(pw),
            TEST_KDF,
            meta,
            &AtomicBool::new(false),
            |_| {},
        )
        .unwrap();
        out
    }

    fn dec(file: &[u8], pw: &str) -> Result<(Meta, Vec<u8>), KfxError> {
        decrypt(
            file,
            &secret_string(pw),
            |_| Ok(Vec::new()),
            &AtomicBool::new(false),
            |_| {},
        )
    }

    fn file_meta() -> Meta {
        Meta {
            content: Content::File,
            name: "holiday photo.jpg".into(),
        }
    }

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    #[test]
    fn round_trips_at_chunk_boundaries() {
        let meta = file_meta();
        let meta_len = 3 + meta.name.len();
        // Sizes around the points where a chunk fills up exactly.
        let sizes = [
            0,
            1,
            1000,
            CHUNK - meta_len - 1,
            CHUNK - meta_len,
            CHUNK - meta_len + 1,
            CHUNK,
            2 * CHUNK - meta_len,
            2 * CHUNK + 17,
        ];
        // One key derivation per file: keep the list short but pointed.
        for size in sizes {
            let data = pattern(size);
            let file = enc(&data, "pw", &meta);
            let chunks = (meta_len + size).div_ceil(CHUNK).max(1);
            assert_eq!(
                file.len(),
                HEADER_LEN + meta_len + size + chunks * TAG,
                "size {size}"
            );
            let (m, back) = dec(&file, "pw").unwrap();
            assert_eq!(m, meta);
            assert_eq!(back, data, "size {size}");
        }
    }

    #[test]
    fn text_and_wrong_password() {
        let meta = Meta {
            content: Content::Text,
            name: String::new(),
        };
        let file = enc("the gate code is 2468 — ünïcode".as_bytes(), "right", &meta);
        assert!(!file.windows(4).any(|w| w == b"2468"));
        let (m, text) = dec(&file, "right").unwrap();
        assert_eq!(m.content, Content::Text);
        assert_eq!(
            String::from_utf8(text).unwrap(),
            "the gate code is 2468 — ünïcode"
        );
        assert_eq!(dec(&file, "wrong").err(), Some(KfxError::Failed));
        assert_eq!(
            dec(b"not a kfx file at all", "x").err(),
            Some(KfxError::NotKfx)
        );
        assert_eq!(dec(b"", "x").err(), Some(KfxError::NotKfx));
        let mut newer = file.clone();
        newer[8] = 7;
        assert_eq!(dec(&newer, "right").err(), Some(KfxError::NewerVersion(7)));
        // Two encryptions of the same text share nothing.
        let again = enc("the gate code is 2468 — ünïcode".as_bytes(), "right", &meta);
        assert_ne!(file[28..60], again[28..60]);
        assert_ne!(file[HEADER_LEN..], again[HEADER_LEN..]);
    }

    /// Decrypts with a key derived once, so the tamper loops stay fast.
    fn dec_fast(file: &[u8], aead: &XChaCha20Poly1305) -> Result<Vec<u8>, ()> {
        let header: [u8; HEADER_LEN] = file.get(..HEADER_LEN).ok_or(())?.try_into().unwrap();
        let prefix: [u8; 19] = header[60..79].try_into().unwrap();
        let mut stream = DecryptorBE32::from_aead(aead.clone(), prefix.as_ref().into());
        let mut out = Vec::new();
        let body = &file[HEADER_LEN..];
        let mut chunks: Vec<&[u8]> = body.chunks(CHUNK + TAG).collect();
        let last = chunks.pop().ok_or(())?;
        for c in chunks {
            let mut buf = c.to_vec();
            stream
                .decrypt_next_in_place(&header, &mut buf)
                .map_err(|_| ())?;
            out.extend_from_slice(&buf);
        }
        let mut buf = last.to_vec();
        stream
            .decrypt_last_in_place(&header, &mut buf)
            .map_err(|_| ())?;
        out.extend_from_slice(&buf);
        Ok(out)
    }

    #[test]
    fn tamper_truncate_and_reorder_are_detected() {
        let meta = file_meta();
        let data = pattern(3 * CHUNK + 100);
        let file = enc(&data, "pw", &meta);
        let salt: [u8; 32] = file[28..60].try_into().unwrap();
        let aead = cipher(&secret_string("pw"), &TEST_KDF, &salt).unwrap();
        assert!(dec_fast(&file, &aead).is_ok());
        let full = CHUNK + TAG;

        // Any flipped byte: sampled across the file, plus all of the header
        // and the area around every chunk boundary.
        let mut positions: Vec<usize> = (0..HEADER_LEN).collect();
        positions.extend((HEADER_LEN..file.len()).step_by(4099));
        for boundary in 1..=3 {
            let at = HEADER_LEN + boundary * full;
            positions.extend(at - 20..at + 20);
        }
        positions.extend(file.len() - 40..file.len());
        for i in positions {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            // Flips in KDF fields or the salt change the key: full path.
            let rejected = if i < 60 {
                dec(&bad, "pw").is_err()
            } else {
                dec_fast(&bad, &aead).is_err()
            };
            assert!(rejected, "flip at {i} accepted");
        }

        // Truncation: at a chunk boundary, inside a chunk, and to the header.
        for cut in [
            HEADER_LEN,
            HEADER_LEN + 5,
            HEADER_LEN + full,
            HEADER_LEN + 2 * full,
            HEADER_LEN + 3 * full,
            file.len() - 1,
            file.len() - TAG,
        ] {
            assert!(
                dec_fast(&file[..cut], &aead).is_err(),
                "cut at {cut} accepted"
            );
            assert_eq!(
                dec(&file[..cut], "pw").err(),
                Some(KfxError::Failed),
                "cut at {cut}"
            );
        }
        // Extra data appended.
        let mut longer = file.clone();
        longer.extend_from_slice(&[0u8; 40]);
        assert!(dec(&longer, "pw").is_err());

        // Reordered, duplicated and dropped chunks.
        let chunk = |n: usize| &file[HEADER_LEN + n * full..HEADER_LEN + (n + 1) * full];
        let tail = &file[HEADER_LEN + 3 * full..];
        let build = |parts: &[&[u8]]| {
            let mut f = file[..HEADER_LEN].to_vec();
            for p in parts {
                f.extend_from_slice(p);
            }
            f
        };
        let swapped = build(&[chunk(1), chunk(0), chunk(2), tail]);
        let duplicated = build(&[chunk(0), chunk(0), chunk(1), chunk(2), tail]);
        let dropped = build(&[chunk(0), chunk(2), tail]);
        let headless = build(&[chunk(1), chunk(2), tail]);
        for (name, f) in [
            ("swap", swapped),
            ("dup", duplicated),
            ("drop", dropped),
            ("head", headless),
        ] {
            assert!(dec_fast(&f, &aead).is_err(), "{name} accepted");
            assert_eq!(dec(&f, "pw").err(), Some(KfxError::Failed), "{name}");
        }
        // A chunk from another file encrypted with the same password.
        let other = enc(&data, "pw", &meta);
        let mixed = build(&[
            chunk(0),
            &other[HEADER_LEN + full..HEADER_LEN + 2 * full],
            chunk(2),
            tail,
        ]);
        assert!(dec(&mixed, "pw").is_err());
    }

    #[test]
    fn unusual_kdf_and_cancel() {
        let meta = file_meta();
        let mut file = enc(b"x", "pw", &meta);
        file[12..16].copy_from_slice(&1024u32.to_le_bytes());
        assert!(matches!(dec(&file, "pw"), Err(KfxError::UnusualKdf(_))));
        file[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(dec(&file, "pw"), Err(KfxError::UnusualKdf(_))));
        let cancel = AtomicBool::new(true);
        let mut out = Vec::new();
        assert_eq!(
            encrypt(
                &b"data"[..],
                &mut out,
                &secret_string("pw"),
                TEST_KDF,
                &meta,
                &cancel,
                |_| {}
            ),
            Err(KfxError::Cancelled)
        );
    }

    #[test]
    fn stored_names_are_made_safe() {
        assert_eq!(safe_name("report.pdf"), "report.pdf");
        assert_eq!(safe_name("..\\..\\Windows\\evil.dll"), "evil.dll");
        assert_eq!(safe_name("/etc/passwd"), "passwd");
        assert_eq!(safe_name("a<b>:c?.txt"), "a_b__c_.txt");
        assert_eq!(safe_name("CON"), "decrypted file");
        assert_eq!(safe_name("com1.txt"), "decrypted file");
        assert_eq!(safe_name(".."), "decrypted file");
        assert_eq!(safe_name(""), "decrypted file");
    }
}
