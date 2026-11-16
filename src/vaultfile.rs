//! The `.kfv` vault file: key derivation, encoding and decoding.
//! The byte layout is documented in `docs/FORMAT.md`.

use crate::model::{Attachment, Vault};
use crate::secret::{
    random_array, with_session, LockedBytes, SecretBuf, SecretBytes, SecretString, SessionKey,
};
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 8] = b"KFVAULT\0";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 128;
/// The part of the header covered by the header MAC.
pub const MAC_OFFSET: usize = 96;
pub const KDF_ARGON2ID: u8 = 1;
pub const CIPHER_XCHACHA20_POLY1305: u8 = 1;
pub const ENCODING_CBOR_PADDED: u8 = 1;
pub const FLAG_KEY_FILE: u8 = 1;
/// The serialized vault is padded to a multiple of this many bytes.
pub const PAD_BLOCK: usize = 4096;
/// Files larger than this are refused before anything is allocated.
pub const MAX_FILE_LEN: u64 = 1 << 30;

pub const LABEL_ENC: &[u8] = b"KeepForge v1 vault encryption";
pub const LABEL_MAC: &[u8] = b"KeepForge v1 header authentication";
pub const LABEL_ATT: &[u8] = b"KeepForge v1 attachment encryption";
pub const LABEL_KFX: &[u8] = b"KeepForge v1 kfx file encryption";
const ATT_AAD: &[u8] = b"KeepForge v1 attachment";

// --------------------------------------------------------------------------------------
// KDF parameters
// --------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes over the memory.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

/// What to do with a file's KDF parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KdfCheck {
    Ok,
    /// Weaker than the OWASP minimum: open only if the user confirms.
    BelowFloor,
    /// Unusually expensive: open only if the user confirms.
    VeryHigh,
    /// Outside what KeepForge will ever run.
    Refused,
}

impl KdfParams {
    /// 256 MiB, 3 passes, 4 lanes.
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: 256 * 1024,
        t: 3,
        p: 4,
    };
    /// OWASP's minimum Argon2id configuration: 19 MiB, 2 passes, 1 lane.
    pub const FLOOR: KdfParams = KdfParams {
        m_kib: 19 * 1024,
        t: 2,
        p: 1,
    };
    pub const MAX_M_KIB: u32 = 4 * 1024 * 1024;
    pub const MAX_T: u32 = 64;
    pub const MAX_P: u32 = 64;
    /// Above this, opening asks for confirmation first.
    pub const CONFIRM_M_KIB: u32 = 1024 * 1024;
    pub const CONFIRM_T: u32 = 16;

    pub fn mib(&self) -> u32 {
        self.m_kib / 1024
    }

    pub fn check(&self) -> KdfCheck {
        if self.m_kib > Self::MAX_M_KIB
            || self.t > Self::MAX_T
            || self.p > Self::MAX_P
            || self.t == 0
            || self.p == 0
            || self.m_kib < 8 * self.p
        {
            return KdfCheck::Refused;
        }
        if self.m_kib < Self::FLOOR.m_kib || self.t < Self::FLOOR.t {
            return KdfCheck::BelowFloor;
        }
        if self.m_kib > Self::CONFIRM_M_KIB || self.t > Self::CONFIRM_T {
            return KdfCheck::VeryHigh;
        }
        KdfCheck::Ok
    }

    /// Raises anything below the floor up to the floor and caps the rest.
    pub fn clamped(self) -> KdfParams {
        let p = self.p.clamp(Self::FLOOR.p, Self::MAX_P);
        KdfParams {
            m_kib: self
                .m_kib
                .clamp(Self::FLOOR.m_kib.max(8 * p), Self::CONFIRM_M_KIB),
            t: self.t.clamp(Self::FLOOR.t, Self::CONFIRM_T),
            p,
        }
    }

    pub fn describe(&self) -> String {
        format!(
            "Argon2id, {} MiB memory, {} passes, {} lanes",
            self.mib(),
            self.t,
            self.p
        )
    }
}

/// The result of the "target one second" benchmark.
#[derive(Clone, Copy, Debug)]
pub struct Calibration {
    pub params: KdfParams,
    pub took: Duration,
}

/// Candidate settings from strongest to weakest; never below the floor.
const LADDER: [KdfParams; 9] = [
    KdfParams::DEFAULT,
    KdfParams {
        m_kib: 192 * 1024,
        t: 3,
        p: 4,
    },
    KdfParams {
        m_kib: 128 * 1024,
        t: 3,
        p: 4,
    },
    KdfParams {
        m_kib: 96 * 1024,
        t: 3,
        p: 4,
    },
    KdfParams {
        m_kib: 64 * 1024,
        t: 3,
        p: 4,
    },
    KdfParams {
        m_kib: 64 * 1024,
        t: 2,
        p: 4,
    },
    KdfParams {
        m_kib: 48 * 1024,
        t: 2,
        p: 2,
    },
    KdfParams {
        m_kib: 32 * 1024,
        t: 2,
        p: 2,
    },
    KdfParams::FLOOR,
];

/// Picks the first rung whose estimated time fits `target`, given that the
/// default took `default_took`. Cost is proportional to memory × passes.
pub fn pick_rung(default_took: Duration, target: Duration) -> KdfParams {
    let base = KdfParams::DEFAULT.m_kib as f64 * KdfParams::DEFAULT.t as f64;
    for rung in LADDER.iter().skip(1) {
        let est = default_took.as_secs_f64() * (rung.m_kib as f64 * rung.t as f64) / base;
        if est <= target.as_secs_f64() {
            return *rung;
        }
    }
    KdfParams::FLOOR
}

/// Measures the default parameters on this machine. If they take longer than
/// about 1.5 s, steps down to a setting that takes about one second, never
/// below the floor. Run on a worker thread.
pub fn calibrate() -> Calibration {
    let time = |params: KdfParams| -> Duration {
        let start = Instant::now();
        let pw = crate::secret::secret_string("calibration");
        let _ = derive_master(&pw, None, &params, &[0u8; 32]);
        start.elapsed()
    };
    let took = time(KdfParams::DEFAULT);
    if took <= Duration::from_millis(1500) {
        return Calibration {
            params: KdfParams::DEFAULT,
            took,
        };
    }
    let params = pick_rung(took, Duration::from_secs(1));
    Calibration {
        params,
        took: time(params),
    }
}

// --------------------------------------------------------------------------------------
// Errors
// --------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VaultError {
    /// Not a KeepForge vault (bad magic or impossible sizes).
    NotAVault,
    /// Written by a newer KeepForge.
    NewerVersion(u16),
    /// The file ends early or has trailing data.
    Damaged(&'static str),
    /// Header authentication failed: wrong password or key file, or the header was changed.
    WrongKey,
    /// The header verified but the content did not: the file was changed or is damaged.
    Tampered,
    /// The file asks for KDF settings below the minimum; needs confirmation.
    WeakKdf(KdfParams),
    /// The file asks for unusually expensive KDF settings; needs confirmation.
    HeavyKdf(KdfParams),
    /// KDF settings outside the accepted range.
    KdfRefused,
    /// A key file is needed and none was given.
    KeyFileNeeded,
    /// Not enough memory to run the KDF.
    OutOfMemory,
    Internal(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::NotAVault => f.write_str("This file is not a KeepForge vault."),
            VaultError::NewerVersion(v) => write!(
                f,
                "This vault was written by a newer version of KeepForge (format {v}). Update KeepForge to open it."
            ),
            VaultError::Damaged(what) => write!(f, "The vault file is damaged ({what})."),
            VaultError::WrongKey => f.write_str(
                "That did not unlock the vault. Check the master password (and key file, if the vault uses one).",
            ),
            VaultError::Tampered => f.write_str(
                "The password is right, but the vault's content failed its integrity check. The file was changed or is damaged. Try one of the .bak backups next to it.",
            ),
            VaultError::WeakKdf(p) => write!(
                f,
                "This vault uses key-stretching settings below the recommended minimum ({}).",
                p.describe()
            ),
            VaultError::HeavyKdf(p) => write!(
                f,
                "This vault asks for unusually heavy key stretching ({}).",
                p.describe()
            ),
            VaultError::KdfRefused => f.write_str(
                "This file asks for key-stretching settings KeepForge refuses to run. It is damaged or was not made by KeepForge.",
            ),
            VaultError::KeyFileNeeded => {
                f.write_str("This vault needs its key file as well as the master password.")
            }
            VaultError::OutOfMemory => f.write_str(
                "There is not enough free memory to unlock this vault. Close some programs and try again.",
            ),
            VaultError::Internal(e) => write!(f, "Unexpected error: {e}"),
        }
    }
}

// --------------------------------------------------------------------------------------
// Keys
// --------------------------------------------------------------------------------------

/// What the user supplies to unlock.
pub struct Credentials {
    pub password: SecretString,
    /// SHA-256 of the key file, if one is used.
    pub key_file: Option<Zeroizing<[u8; 32]>>,
}

impl Credentials {
    pub fn password_only(password: &str) -> Credentials {
        Credentials {
            password: crate::secret::secret_string(password),
            key_file: None,
        }
    }

    /// Wipes the password now, without waiting for the value to be dropped.
    pub fn wipe(&mut self) {
        self.password.zeroize();
        if let Some(k) = &mut self.key_file {
            k.zeroize();
        }
    }
}

/// The three working keys of an unlocked vault, each in a locked page.
pub struct Keys {
    enc: LockedBytes,
    mac: LockedBytes,
    att: LockedBytes,
}

impl Keys {
    /// Whether every key page could be locked into RAM.
    pub fn pages_locked(&self) -> bool {
        self.enc.is_locked() && self.mac.is_locked() && self.att.is_locked()
    }

    #[cfg(test)]
    pub(crate) fn raw(&self) -> [&[u8]; 3] {
        [
            self.enc.as_slice(),
            self.mac.as_slice(),
            self.att.as_slice(),
        ]
    }
}

/// Argon2id over the password (and the key file digest as Argon2's secret
/// input). Returns the 64-byte master key.
pub fn derive_master(
    password: &SecretString,
    key_file: Option<&[u8; 32]>,
    kdf: &KdfParams,
    salt: &[u8; 32],
) -> Result<Zeroizing<[u8; 64]>, VaultError> {
    if kdf.check() == KdfCheck::Refused {
        return Err(VaultError::KdfRefused);
    }
    let params =
        Params::new(kdf.m_kib, kdf.t, kdf.p, Some(64)).map_err(|_| VaultError::KdfRefused)?;
    let blocks_needed = params.block_count();
    let mut blocks: Vec<Block> = Vec::new();
    blocks
        .try_reserve_exact(blocks_needed)
        .map_err(|_| VaultError::OutOfMemory)?;
    blocks.resize(blocks_needed, Block::default());
    let mut out = Zeroizing::new([0u8; 64]);
    let argon = match key_file {
        Some(secret) => {
            Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, params)
                .map_err(|e| VaultError::Internal(e.to_string()))?
        }
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, params),
    };
    let result =
        argon.hash_password_into_with_memory(password.as_bytes(), salt, &mut out[..], &mut blocks);
    for b in blocks.iter_mut() {
        b.zeroize();
    }
    result.map_err(|e| VaultError::Internal(e.to_string()))?;
    Ok(out)
}

/// HKDF-SHA-256 expansion of the master key under one label.
pub fn subkey(master: &[u8; 64], salt: &[u8; 32], label: &[u8]) -> LockedBytes {
    let hk = Hkdf::<Sha256>::new(Some(salt), master);
    let mut key = LockedBytes::zeroed(32);
    hk.expand(label, key.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    key
}

pub fn keys_from_master(master: &[u8; 64], salt: &[u8; 32]) -> Keys {
    Keys {
        enc: subkey(master, salt, LABEL_ENC),
        mac: subkey(master, salt, LABEL_MAC),
        att: subkey(master, salt, LABEL_ATT),
    }
}

/// Runs the KDF and derives the working keys. The password inside `creds` is
/// wiped before this returns.
pub fn derive_keys(
    creds: &mut Credentials,
    kdf: &KdfParams,
    salt: &[u8; 32],
) -> Result<Keys, VaultError> {
    let master = derive_master(&creds.password, creds.key_file.as_deref(), kdf, salt);
    creds.wipe();
    let master = master?;
    Ok(keys_from_master(&master, salt))
}

// --------------------------------------------------------------------------------------
// Header
// --------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    pub flags: u8,
    pub kdf: KdfParams,
    pub attachments: u32,
    pub salt: [u8; 32],
    pub nonce: [u8; 24],
    pub payload_len: u64,
}

impl Header {
    pub fn needs_key_file(&self) -> bool {
        self.flags & FLAG_KEY_FILE != 0
    }

    fn write(&self, out: &mut [u8; HEADER_LEN]) {
        out[0..8].copy_from_slice(MAGIC);
        out[8..10].copy_from_slice(&self.version.to_le_bytes());
        out[10..12].copy_from_slice(&(HEADER_LEN as u16).to_le_bytes());
        out[12] = KDF_ARGON2ID;
        out[13] = CIPHER_XCHACHA20_POLY1305;
        out[14] = ENCODING_CBOR_PADDED;
        out[15] = self.flags;
        out[16..20].copy_from_slice(&self.kdf.m_kib.to_le_bytes());
        out[20..24].copy_from_slice(&self.kdf.t.to_le_bytes());
        out[24..28].copy_from_slice(&self.kdf.p.to_le_bytes());
        out[28..32].copy_from_slice(&self.attachments.to_le_bytes());
        out[32..64].copy_from_slice(&self.salt);
        out[64..88].copy_from_slice(&self.nonce);
        out[88..96].copy_from_slice(&self.payload_len.to_le_bytes());
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[at..at + 8]);
    u64::from_le_bytes(a)
}

/// Reads and sanity-checks the plaintext header. Nothing is trusted yet.
pub fn parse_header(file: &[u8]) -> Result<Header, VaultError> {
    if file.len() < 12 || &file[0..8] != MAGIC {
        return Err(VaultError::NotAVault);
    }
    let version = u16::from_le_bytes([file[8], file[9]]);
    if version > FORMAT_VERSION {
        return Err(VaultError::NewerVersion(version));
    }
    if version == 0 {
        return Err(VaultError::NotAVault);
    }
    if file.len() < HEADER_LEN {
        return Err(VaultError::Damaged("the header is cut short"));
    }
    if u16::from_le_bytes([file[10], file[11]]) as usize != HEADER_LEN
        || file[12] != KDF_ARGON2ID
        || file[13] != CIPHER_XCHACHA20_POLY1305
        || file[14] != ENCODING_CBOR_PADDED
        || file[15] & !FLAG_KEY_FILE != 0
    {
        return Err(VaultError::Damaged("unknown header fields"));
    }
    let header = Header {
        version,
        flags: file[15],
        kdf: KdfParams {
            m_kib: u32_at(file, 16),
            t: u32_at(file, 20),
            p: u32_at(file, 24),
        },
        attachments: u32_at(file, 28),
        salt: file[32..64].try_into().expect("32 bytes"),
        nonce: file[64..88].try_into().expect("24 bytes"),
        payload_len: u64_at(file, 88),
    };
    let rest = (file.len() - HEADER_LEN) as u64;
    if header.payload_len < 16 + PAD_BLOCK as u64
        || header.payload_len > rest
        || !(header.payload_len - 16).is_multiple_of(PAD_BLOCK as u64)
    {
        return Err(VaultError::Damaged("the content is cut short"));
    }
    // Each attachment section needs at least its 8-byte length and a 16-byte tag.
    if header.attachments as u64 > (rest - header.payload_len) / 24 {
        return Err(VaultError::Damaged("attachments are missing"));
    }
    if header.kdf.check() == KdfCheck::Refused {
        return Err(VaultError::KdfRefused);
    }
    Ok(header)
}

fn header_mac(keys: &Keys, header: &[u8]) -> Hmac<Sha256> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(keys.mac.as_slice())
        .expect("HMAC accepts any key length");
    mac.update(&header[..MAC_OFFSET]);
    mac
}

fn cipher(key: &LockedBytes) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key.as_slice()).expect("32-byte key")
}

fn attachment_aad(id: crate::model::Id, salt: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ATT_AAD.len() + 16 + 32);
    aad.extend_from_slice(ATT_AAD);
    aad.extend_from_slice(&id.0.to_le_bytes());
    aad.extend_from_slice(salt);
    aad
}

// --------------------------------------------------------------------------------------
// Attachments
// --------------------------------------------------------------------------------------

fn seal_blob(
    keys: &Keys,
    salt: &[u8; 32],
    id: crate::model::Id,
    content: &[u8],
) -> ([u8; 24], Vec<u8>) {
    let nonce: [u8; 24] = random_array();
    let mut blob = Vec::with_capacity(content.len() + 16);
    blob.extend_from_slice(content);
    let tag = cipher(&keys.att)
        .encrypt_in_place_detached(
            XNonce::from_slice(&nonce),
            &attachment_aad(id, salt),
            &mut blob,
        )
        .expect("attachment sizes are limited well below the cipher's maximum");
    blob.extend_from_slice(&tag);
    (nonce, blob)
}

/// Encrypts a file's content into an attachment record.
pub fn seal_attachment(keys: &Keys, salt: &[u8; 32], name: &str, content: &[u8]) -> Attachment {
    let id = crate::model::Id::random();
    let (nonce, blob) = seal_blob(keys, salt, id, content);
    Attachment {
        id,
        name: name.to_string(),
        size: content.len() as u64,
        nonce,
        digest: Sha256::digest(&blob).into(),
        blob: Arc::new(blob),
    }
}

/// Decrypts an attachment's content.
pub fn open_attachment(
    keys: &Keys,
    salt: &[u8; 32],
    att: &Attachment,
) -> Result<SecretBytes, VaultError> {
    if att.blob.len() < 16 {
        return Err(VaultError::Tampered);
    }
    let (body, tag) = att.blob.split_at(att.blob.len() - 16);
    let mut plain = Zeroizing::new(Vec::with_capacity(body.len()));
    plain.extend_from_slice(body);
    cipher(&keys.att)
        .decrypt_in_place_detached(
            XNonce::from_slice(&att.nonce),
            &attachment_aad(att.id, salt),
            &mut plain,
            Tag::from_slice(tag),
        )
        .map_err(|_| VaultError::Tampered)?;
    Ok(plain)
}

// --------------------------------------------------------------------------------------
// Encode / decode
// --------------------------------------------------------------------------------------

/// Everything needed to write a vault again without the master password.
pub struct Sealer {
    pub keys: Arc<Keys>,
    pub kdf: KdfParams,
    pub salt: [u8; 32],
    pub key_file: bool,
}

impl Sealer {
    /// Derives fresh keys with a new random salt (new vault, or new password).
    pub fn create(creds: &mut Credentials, kdf: KdfParams) -> Result<Sealer, VaultError> {
        let salt: [u8; 32] = random_array();
        let key_file = creds.key_file.is_some();
        let keys = derive_keys(creds, &kdf, &salt)?;
        Ok(Sealer {
            keys: Arc::new(keys),
            kdf,
            salt,
            key_file,
        })
    }

    pub fn share(&self) -> Sealer {
        Sealer {
            keys: self.keys.clone(),
            kdf: self.kdf,
            salt: self.salt,
            key_file: self.key_file,
        }
    }
}

/// Serializes and encrypts a vault. A fresh random nonce is used every time.
pub fn encode(vault: &Vault, sealer: &Sealer) -> Result<Vec<u8>, VaultError> {
    // Plaintext: length prefix, CBOR, zero padding to a block multiple.
    let mut plain = SecretBuf::with_capacity(64 * 1024);
    plain.extend(&[0u8; 4]);
    ciborium::into_writer(vault, &mut plain).map_err(|e| VaultError::Internal(e.to_string()))?;
    let body_len = plain.len() - 4;
    let body_len32 = u32::try_from(body_len)
        .map_err(|_| VaultError::Internal("the vault is too large".into()))?;
    plain.as_mut_slice()[..4].copy_from_slice(&body_len32.to_le_bytes());
    let padded = plain.len().div_ceil(PAD_BLOCK) * PAD_BLOCK;
    plain.resize(padded);

    let attachments: Vec<&Attachment> = vault.items.iter().flat_map(|i| &i.attachments).collect();
    let header = Header {
        version: FORMAT_VERSION,
        flags: if sealer.key_file { FLAG_KEY_FILE } else { 0 },
        kdf: sealer.kdf,
        attachments: attachments.len() as u32,
        salt: sealer.salt,
        nonce: random_array(),
        payload_len: padded as u64 + 16,
    };
    let mut head = [0u8; HEADER_LEN];
    header.write(&mut head);
    let mac = header_mac(&sealer.keys, &head).finalize().into_bytes();
    head[MAC_OFFSET..].copy_from_slice(&mac);

    let tag = cipher(&sealer.keys.enc)
        .encrypt_in_place_detached(
            XNonce::from_slice(&header.nonce),
            &head,
            plain.as_mut_slice(),
        )
        .map_err(|_| VaultError::Internal("encryption failed".into()))?;

    let att_total: usize = attachments.iter().map(|a| a.blob.len() + 8).sum();
    let mut out = Vec::with_capacity(HEADER_LEN + padded + 16 + att_total);
    out.extend_from_slice(&head);
    out.extend_from_slice(plain.as_slice());
    out.extend_from_slice(&tag);
    for a in attachments {
        out.extend_from_slice(&(a.blob.len() as u64).to_le_bytes());
        out.extend_from_slice(&a.blob);
    }
    Ok(out)
}

/// Verifies and decrypts a vault file with keys that are already derived.
pub fn decode_with_keys(
    file: &[u8],
    keys: &Keys,
    session: &Arc<SessionKey>,
) -> Result<(Vault, Header), VaultError> {
    let header = parse_header(file)?;
    let head = &file[..HEADER_LEN];
    header_mac(keys, head)
        .verify_slice(&head[MAC_OFFSET..])
        .map_err(|_| VaultError::WrongKey)?;

    let payload_end = HEADER_LEN + header.payload_len as usize;
    let body = &file[HEADER_LEN..payload_end - 16];
    let tag = &file[payload_end - 16..payload_end];
    let mut plain = SecretBuf::with_capacity(body.len());
    plain.extend(body);
    cipher(&keys.enc)
        .decrypt_in_place_detached(
            XNonce::from_slice(&header.nonce),
            head,
            plain.as_mut_slice(),
            Tag::from_slice(tag),
        )
        .map_err(|_| VaultError::Tampered)?;

    let plain = plain.as_slice();
    let body_len = u32_at(plain, 0) as usize;
    if body_len > plain.len() - 4 || plain[4 + body_len..].iter().any(|b| *b != 0) {
        return Err(VaultError::Tampered);
    }
    let mut vault: Vault = with_session(session, || {
        ciborium::from_reader(&plain[4..4 + body_len])
            .map_err(|_| VaultError::Damaged("the content could not be read"))
    })?;
    if vault.schema > crate::model::SCHEMA {
        return Err(VaultError::NewerVersion(header.version));
    }

    // Attachment sections follow, in the order the items list them.
    let mut at = payload_end;
    let mut seen = 0u32;
    for item in &mut vault.items {
        for a in &mut item.attachments {
            if file.len() - at < 8 {
                return Err(VaultError::Damaged("an attachment is cut short"));
            }
            let len = u64_at(file, at);
            at += 8;
            if len < 16 || len > (file.len() - at) as u64 {
                return Err(VaultError::Damaged("an attachment is cut short"));
            }
            let blob = &file[at..at + len as usize];
            at += len as usize;
            let digest: [u8; 32] = Sha256::digest(blob).into();
            if digest != a.digest {
                return Err(VaultError::Tampered);
            }
            a.blob = Arc::new(blob.to_vec());
            // Authenticate now, so damage is reported at unlock, not at save-out.
            open_attachment(keys, &header.salt, a)?;
            seen += 1;
        }
    }
    if seen != header.attachments {
        return Err(VaultError::Tampered);
    }
    if at != file.len() {
        return Err(VaultError::Damaged("unexpected data after the end"));
    }
    Ok((vault, header))
}

/// Unlocks a vault file with a password (and key file). `allow_unusual`
/// must be set, after asking the user, for KDF settings outside the normal range.
pub fn open(
    file: &[u8],
    creds: &mut Credentials,
    allow_unusual: bool,
    session: &Arc<SessionKey>,
) -> Result<(Vault, Sealer), VaultError> {
    let header = parse_header(file).inspect_err(|_| creds.wipe())?;
    let precheck = match header.kdf.check() {
        KdfCheck::BelowFloor if !allow_unusual => Err(VaultError::WeakKdf(header.kdf)),
        KdfCheck::VeryHigh if !allow_unusual => Err(VaultError::HeavyKdf(header.kdf)),
        KdfCheck::Refused => Err(VaultError::KdfRefused),
        _ if header.needs_key_file() && creds.key_file.is_none() => Err(VaultError::KeyFileNeeded),
        _ => Ok(()),
    };
    if let Err(e) = precheck {
        // The password stays with the caller only for the "confirm" cases.
        if !matches!(
            e,
            VaultError::WeakKdf(_) | VaultError::HeavyKdf(_) | VaultError::KeyFileNeeded
        ) {
            creds.wipe();
        }
        return Err(e);
    }
    if !header.needs_key_file() {
        // A key file offered for a vault that does not use one is ignored.
        creds.key_file = None;
    }
    let keys = derive_keys(creds, &header.kdf, &header.salt)?;
    let (vault, header) = decode_with_keys(file, &keys, session)?;
    Ok((
        vault,
        Sealer {
            keys: Arc::new(keys),
            kdf: header.kdf,
            salt: header.salt,
            key_file: header.needs_key_file(),
        },
    ))
}

/// Re-encrypts every attachment from one key set to another (new password or
/// new KDF settings mean a new salt and new keys).
pub fn rekey_attachments(vault: &mut Vault, from: &Sealer, to: &Sealer) -> Result<(), VaultError> {
    for item in &mut vault.items {
        for a in &mut item.attachments {
            let plain = open_attachment(&from.keys, &from.salt, a)?;
            let (nonce, blob) = seal_blob(&to.keys, &to.salt, a.id, &plain);
            a.nonce = nonce;
            a.digest = Sha256::digest(&blob).into();
            a.blob = Arc::new(blob);
        }
    }
    Ok(())
}

/// SHA-256 of a key file's bytes.
pub fn key_file_digest(content: &[u8]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(Sha256::digest(content).into())
}

/// The text of a newly generated key file: 32 random bytes as hex.
pub fn new_key_file() -> Zeroizing<String> {
    let bytes: Zeroizing<[u8; 32]> = Zeroizing::new(random_array());
    Zeroizing::new(format!(
        "KeepForge key file v1\r\n{}\r\n",
        crate::util::hex(&bytes[..])
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::model::{CustomField, Item, Kind};
    use crate::secret::Protected;

    pub(crate) const TEST_KDF: KdfParams = KdfParams::FLOOR;

    pub(crate) fn sample(session: &Arc<SessionKey>) -> Vault {
        let mut v = Vault::new("Sample", 1_700_000_000);
        let mut login = Item::new(Kind::Login, 1_700_000_000);
        login.title = "Example Mail".into();
        login.username = "alex.morgan@example.com".into();
        login.password = Protected::seal_str(session, "correct horse battery staple");
        login.urls = vec!["https://mail.example.com".into()];
        login.totp = Protected::seal_str(session, "JBSWY3DPEHPK3PXP");
        login.notes = Protected::seal_str(session, "Línea uno\nline two");
        login
            .fields
            .push(CustomField::hidden(session, "PIN", "4821"));
        login.fields.push(CustomField::plain("Plan", "Family"));
        login.tags = vec!["mail".into()];
        v.items.push(login);
        let mut note = Item::new(Kind::Note, 1_700_000_100);
        note.title = "Garden shed code".into();
        note.notes = Protected::seal_str(session, "2468");
        v.items.push(note);
        v
    }

    fn sealer(password: &str, key_file: Option<&[u8]>) -> Sealer {
        let mut creds = Credentials::password_only(password);
        creds.key_file = key_file.map(key_file_digest);
        Sealer::create(&mut creds, TEST_KDF).unwrap()
    }

    fn creds(password: &str, key_file: Option<&[u8]>) -> Credentials {
        let mut c = Credentials::password_only(password);
        c.key_file = key_file.map(key_file_digest);
        c
    }

    #[test]
    fn round_trip() {
        let s = SessionKey::new();
        let mut v = sample(&s);
        let sl = sealer("pw one", None);
        let att = seal_attachment(&sl.keys, &sl.salt, "scan.pdf", b"%PDF-1.7 pretend");
        v.items[0].attachments.push(att);
        let file = encode(&v, &sl).unwrap();
        assert_eq!((file.len() - HEADER_LEN - 16 - 8 - 32) % PAD_BLOCK, 0);
        // Nothing readable in the file.
        for needle in [
            &b"Example Mail"[..],
            b"alex.morgan",
            b"battery",
            b"scan.pdf",
            b"pretend",
        ] {
            assert!(!file.windows(needle.len()).any(|w| w == needle));
        }
        let s2 = SessionKey::new();
        let (back, sl2) = open(&file, &mut creds("pw one", None), false, &s2).unwrap();
        assert_eq!(back.name, "Sample");
        assert_eq!(back.items.len(), 2);
        let l = &back.items[0];
        assert_eq!(l.title, "Example Mail");
        assert_eq!(
            l.password.open_str().as_str(),
            "correct horse battery staple"
        );
        assert_eq!(l.notes.open_str().as_str(), "Línea uno\nline two");
        assert_eq!(l.fields[0].text().as_str(), "4821");
        assert_eq!(l.fields[1].text().as_str(), "Family");
        assert_eq!(
            &open_attachment(&sl2.keys, &sl2.salt, &l.attachments[0]).unwrap()[..],
            b"%PDF-1.7 pretend"
        );
        assert_eq!(sl2.kdf, TEST_KDF);
        assert!(!sl2.key_file);
    }

    #[test]
    fn password_is_wiped_after_derivation() {
        let mut c = creds("wipe me please", None);
        let _ = Sealer::create(&mut c, TEST_KDF).unwrap();
        assert!(c.password.is_empty());
    }

    #[test]
    fn wrong_password_and_key_file_fail_cleanly() {
        let s = SessionKey::new();
        let v = sample(&s);
        let file = encode(&v, &sealer("right", None)).unwrap();
        assert_eq!(
            open(&file, &mut creds("wrong", None), false, &s).err(),
            Some(VaultError::WrongKey)
        );
        assert_eq!(
            open(&file, &mut creds("", None), false, &s).err(),
            Some(VaultError::WrongKey)
        );
        // A stray key file is ignored for a vault without one.
        assert!(open(&file, &mut creds("right", Some(b"k")), false, &s).is_ok());

        let file = encode(&v, &sealer("right", Some(b"key file A"))).unwrap();
        assert_eq!(
            open(&file, &mut creds("right", None), false, &s).err(),
            Some(VaultError::KeyFileNeeded)
        );
        assert_eq!(
            open(&file, &mut creds("right", Some(b"key file B")), false, &s).err(),
            Some(VaultError::WrongKey)
        );
        assert!(open(&file, &mut creds("right", Some(b"key file A")), false, &s).is_ok());
    }

    #[test]
    fn every_single_byte_flip_is_rejected() {
        let s = SessionKey::new();
        let mut v = sample(&s);
        let sl = sealer("flip", None);
        v.items[0]
            .attachments
            .push(seal_attachment(&sl.keys, &sl.salt, "a.bin", &[9u8; 300]));
        let file = encode(&v, &sl).unwrap();
        assert!(decode_with_keys(&file, &sl.keys, &s).is_ok());
        let mut full_kdf_runs = 0;
        for i in 0..file.len() {
            let mut bad = file.clone();
            bad[i] ^= 0x01;
            // Bytes that feed the KDF need the full path; for all others the
            // keys are unchanged, so the derived keys can be reused.
            let feeds_kdf = (15..28).contains(&i) || (32..64).contains(&i);
            let rejected = if feeds_kdf {
                full_kdf_runs += 1;
                open(&bad, &mut creds("flip", None), true, &s).is_err()
            } else {
                decode_with_keys(&bad, &sl.keys, &s).is_err()
            };
            assert!(rejected, "flip at byte {i} was accepted");
            if i % 97 == 0 || i >= file.len() - 400 {
                bad[i] = file[i] ^ 0x80;
                assert!(decode_with_keys(&bad, &sl.keys, &s).is_err());
            }
        }
        assert_eq!(full_kdf_runs, 13 + 32);
    }

    #[test]
    fn truncated_garbage_and_huge_params_never_panic() {
        let s = SessionKey::new();
        let v = sample(&s);
        let sl = sealer("x", None);
        let file = encode(&v, &sl).unwrap();
        for cut in [0, 1, 7, 8, 11, 12, 64, 127, 128, 129, 500, file.len() - 1] {
            assert!(decode_with_keys(&file[..cut], &sl.keys, &s).is_err());
            assert!(open(&file[..cut], &mut creds("x", None), true, &s).is_err());
        }
        let mut longer = file.clone();
        longer.push(0);
        assert!(decode_with_keys(&longer, &sl.keys, &s).is_err());

        let mut noise = vec![0u8; 5000];
        for (i, b) in noise.iter_mut().enumerate() {
            *b = (i * 31 + 7) as u8;
        }
        assert_eq!(parse_header(&noise).err(), Some(VaultError::NotAVault));
        noise[..8].copy_from_slice(MAGIC);
        assert!(parse_header(&noise).is_err());

        // Absurd KDF settings are refused before any memory is allocated.
        for (at, value) in [
            (16, u32::MAX),
            (20, u32::MAX),
            (24, u32::MAX),
            (16, 0),
            (20, 0),
        ] {
            let mut bad = file.clone();
            bad[at..at + 4].copy_from_slice(&value.to_le_bytes());
            assert_eq!(
                open(&bad, &mut creds("x", None), true, &s).err(),
                Some(VaultError::KdfRefused)
            );
        }
        // Absurd lengths and counts are refused without allocating.
        let mut bad = file.clone();
        bad[88..96].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_header(&bad).is_err());
        let mut bad = file.clone();
        bad[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_header(&bad).is_err());
        let mut newer = file.clone();
        newer[8] = 9;
        assert_eq!(
            parse_header(&newer).err(),
            Some(VaultError::NewerVersion(9))
        );
    }

    #[test]
    fn nonce_differs_between_saves() {
        let s = SessionKey::new();
        let v = sample(&s);
        let sl = sealer("x", None);
        let a = encode(&v, &sl).unwrap();
        let b = encode(&v, &sl).unwrap();
        assert_ne!(a[64..88], b[64..88]);
        assert_ne!(
            a[HEADER_LEN..HEADER_LEN + 64],
            b[HEADER_LEN..HEADER_LEN + 64]
        );
        assert_eq!(a[32..64], b[32..64]);
        assert_eq!(a.len(), b.len());
    }

    #[test]
    fn kdf_floor_and_cap() {
        assert_eq!(KdfParams::DEFAULT.check(), KdfCheck::Ok);
        assert_eq!(KdfParams::FLOOR.check(), KdfCheck::Ok);
        let weak = KdfParams {
            m_kib: 8 * 1024,
            t: 1,
            p: 1,
        };
        assert_eq!(weak.check(), KdfCheck::BelowFloor);
        assert_eq!(
            KdfParams {
                t: 1,
                ..KdfParams::DEFAULT
            }
            .check(),
            KdfCheck::BelowFloor
        );
        assert_eq!(
            KdfParams {
                m_kib: 2 * 1024 * 1024,
                ..KdfParams::DEFAULT
            }
            .check(),
            KdfCheck::VeryHigh
        );
        assert_eq!(
            KdfParams {
                m_kib: 4 * 1024 * 1024 + 1,
                ..KdfParams::DEFAULT
            }
            .check(),
            KdfCheck::Refused
        );
        assert_eq!(
            KdfParams {
                t: 65,
                ..KdfParams::DEFAULT
            }
            .check(),
            KdfCheck::Refused
        );
        assert_eq!(
            KdfParams {
                p: 0,
                ..KdfParams::DEFAULT
            }
            .check(),
            KdfCheck::Refused
        );
        assert_eq!(weak.clamped(), KdfParams::FLOOR);
        assert_eq!(
            KdfParams {
                m_kib: u32::MAX,
                t: 99,
                p: 99
            }
            .clamped()
            .check(),
            KdfCheck::Ok
        );

        // A weak file opens only with explicit confirmation.
        let s = SessionKey::new();
        let v = sample(&s);
        let mut c = creds("x", None);
        let salt = [3u8; 32];
        let keys = derive_keys(&mut c, &weak, &salt).unwrap();
        let sl = Sealer {
            keys: Arc::new(keys),
            kdf: weak,
            salt,
            key_file: false,
        };
        let file = encode(&v, &sl).unwrap();
        assert_eq!(
            open(&file, &mut creds("x", None), false, &s).err(),
            Some(VaultError::WeakKdf(weak))
        );
        assert!(open(&file, &mut creds("x", None), true, &s).is_ok());

        // Calibration never goes below the floor and prefers the default.
        assert_eq!(
            pick_rung(Duration::from_secs(3), Duration::from_secs(1)).m_kib,
            64 * 1024
        );
        assert_eq!(
            pick_rung(Duration::from_secs(600), Duration::from_secs(1)),
            KdfParams::FLOOR
        );
        for rung in LADDER {
            assert_eq!(rung.check(), KdfCheck::Ok);
        }
    }

    #[test]
    fn hkdf_labels_give_independent_keys() {
        let master = [0x42u8; 64];
        let salt = [1u8; 32];
        let keys = keys_from_master(&master, &salt);
        let [enc, mac, att] = keys.raw();
        assert_ne!(enc, mac);
        assert_ne!(enc, att);
        assert_ne!(mac, att);
        let kfx = subkey(&master, &salt, LABEL_KFX);
        assert_ne!(kfx.as_slice(), enc);
        // Deterministic for the same inputs, different for another salt.
        assert_eq!(keys_from_master(&master, &salt).raw()[0], enc);
        assert_ne!(keys_from_master(&master, &[2u8; 32]).raw()[0], enc);
    }

    #[test]
    fn attachments_cannot_be_swapped_or_dropped() {
        let s = SessionKey::new();
        let mut v = sample(&s);
        let sl = sealer("x", None);
        let a = seal_attachment(&sl.keys, &sl.salt, "a", &[1u8; 64]);
        let b = seal_attachment(&sl.keys, &sl.salt, "b", &[2u8; 64]);
        v.items[0].attachments.push(a);
        v.items[0].attachments.push(b);
        let file = encode(&v, &sl).unwrap();
        let sec = 8 + 64 + 16;
        let start = file.len() - 2 * sec;
        let mut swapped = file[..start].to_vec();
        swapped.extend_from_slice(&file[start + sec..]);
        swapped.extend_from_slice(&file[start..start + sec]);
        assert!(decode_with_keys(&swapped, &sl.keys, &s).is_err());
        assert!(decode_with_keys(&file[..file.len() - sec], &sl.keys, &s).is_err());

        // Changing the password re-encrypts attachments under the new keys.
        let sl2 = sealer("y", None);
        rekey_attachments(&mut v, &sl, &sl2).unwrap();
        let file2 = encode(&v, &sl2).unwrap();
        let (back, _) = open(&file2, &mut creds("y", None), false, &s).unwrap();
        assert_eq!(
            &open_attachment(&sl2.keys, &sl2.salt, &back.items[0].attachments[1]).unwrap()[..],
            &[2u8; 64]
        );
        assert!(open_attachment(&sl.keys, &sl.salt, &back.items[0].attachments[1]).is_err());
    }

    #[test]
    fn key_files() {
        let k = new_key_file();
        assert!(k.starts_with("KeepForge key file v1"));
        assert_ne!(*new_key_file(), *k);
        assert_ne!(key_file_digest(b"a"), key_file_digest(b"b"));
    }
}
