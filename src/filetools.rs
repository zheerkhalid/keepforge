//! File tools: checksums and "secure shred".

use blake2::Blake2b512;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use subtle::ConstantTimeEq;

// --------------------------------------------------------------------------------------
// Checksums
// --------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HashAlgo {
    Sha256,
    Sha512,
    Sha1,
    Blake2b,
}

impl HashAlgo {
    pub const ALL: [HashAlgo; 4] = [
        HashAlgo::Sha256,
        HashAlgo::Sha512,
        HashAlgo::Sha1,
        HashAlgo::Blake2b,
    ];

    pub fn label(self) -> &'static str {
        match self {
            HashAlgo::Sha256 => "SHA-256",
            HashAlgo::Sha512 => "SHA-512",
            HashAlgo::Sha1 => "SHA-1",
            HashAlgo::Blake2b => "BLAKE2b-512",
        }
    }
}

enum Hasher {
    Sha256(Sha256),
    Sha512(Sha512),
    Sha1(Sha1),
    Blake2b(Box<Blake2b512>),
}

/// Hashes a stream. Returns `None` when cancelled.
pub fn hash_reader(
    mut reader: impl Read,
    algo: HashAlgo,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64),
) -> std::io::Result<Option<String>> {
    let mut h = match algo {
        HashAlgo::Sha256 => Hasher::Sha256(Sha256::new()),
        HashAlgo::Sha512 => Hasher::Sha512(Sha512::new()),
        HashAlgo::Sha1 => Hasher::Sha1(Sha1::new()),
        HashAlgo::Blake2b => Hasher::Blake2b(Box::new(Blake2b512::new())),
    };
    let mut buf = vec![0u8; 256 * 1024];
    let mut done = 0u64;
    loop {
        if cancel.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        match &mut h {
            Hasher::Sha256(x) => x.update(&buf[..n]),
            Hasher::Sha512(x) => x.update(&buf[..n]),
            Hasher::Sha1(x) => x.update(&buf[..n]),
            Hasher::Blake2b(x) => x.update(&buf[..n]),
        }
        done += n as u64;
        progress(done);
    }
    let digest = match h {
        Hasher::Sha256(x) => x.finalize().to_vec(),
        Hasher::Sha512(x) => x.finalize().to_vec(),
        Hasher::Sha1(x) => x.finalize().to_vec(),
        Hasher::Blake2b(x) => x.finalize().to_vec(),
    };
    Ok(Some(crate::util::hex(&digest)))
}

/// Compares a computed hash with one the user pasted, in constant time.
/// Spaces, colons, dashes and letter case in the pasted text are ignored.
/// `None` when the pasted text is empty.
pub fn hashes_match(computed_hex: &str, expected: &str) -> Option<bool> {
    let clean: String = expected
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':' && *c != '-')
        .flat_map(|c| c.to_lowercase())
        .collect();
    if clean.is_empty() {
        return None;
    }
    let a = computed_hex.to_lowercase();
    Some(a.len() == clean.len() && bool::from(a.as_bytes().ct_eq(clean.as_bytes())))
}

// --------------------------------------------------------------------------------------
// Shred
// --------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum ShredError {
    NotAFile,
    Folder,
    Link,
    Protected,
    Cancelled,
    Io(String),
}

impl std::fmt::Display for ShredError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShredError::NotAFile => f.write_str("That file does not exist."),
            ShredError::Folder => f.write_str("Folders are not shredded. Choose a single file."),
            ShredError::Link => f.write_str(
                "This is a link to something else, not a normal file. It was left alone.",
            ),
            ShredError::Protected => f.write_str(
                "This file belongs to Windows or to an installed program. It was left alone.",
            ),
            ShredError::Cancelled => f.write_str("Cancelled. The file may be partly overwritten."),
            ShredError::Io(e) => write!(f, "Could not shred the file: {e}"),
        }
    }
}

fn protected_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for var in [
        "SystemRoot",
        "ProgramFiles",
        "ProgramFiles(x86)",
        "ProgramW6432",
        "ProgramData",
    ] {
        if let Some(v) = std::env::var_os(var) {
            if let Ok(p) = std::fs::canonicalize(PathBuf::from(v)) {
                roots.push(p);
            }
        }
    }
    roots
}

/// Checks that `path` is something shredding may touch: an existing regular
/// file, not a link or reparse point, not a system file and not inside
/// Windows or a program folder. Returns the resolved path and its size.
pub fn shred_check(path: &Path) -> Result<(PathBuf, u64), ShredError> {
    let link_meta = std::fs::symlink_metadata(path).map_err(|_| ShredError::NotAFile)?;
    if link_meta.file_type().is_symlink() {
        return Err(ShredError::Link);
    }
    if link_meta.is_dir() {
        return Err(ShredError::Folder);
    }
    if !link_meta.is_file() {
        return Err(ShredError::NotAFile);
    }
    use std::os::windows::fs::MetadataExt;
    const SYSTEM: u32 = 0x4;
    const REPARSE: u32 = 0x400;
    if link_meta.file_attributes() & REPARSE != 0 {
        return Err(ShredError::Link);
    }
    if link_meta.file_attributes() & SYSTEM != 0 {
        return Err(ShredError::Protected);
    }
    let full = std::fs::canonicalize(path).map_err(|_| ShredError::NotAFile)?;
    if protected_roots().iter().any(|root| full.starts_with(root)) {
        return Err(ShredError::Protected);
    }
    Ok((full, link_meta.len()))
}

/// Overwrites the file once with random data, flushes it to disk, renames
/// it to a random name, then deletes it.
///
/// This is honest best effort: on SSDs, on copy-on-write or journaling file
/// systems, and in cloud-synced or backed-up folders, the old data may
/// survive elsewhere and no program can reach it.
pub fn shred(
    path: &Path,
    cancel: &AtomicBool,
    mut progress: impl FnMut(u64, u64),
) -> Result<(), ShredError> {
    let (full, len) = shred_check(path)?;
    let io = |e: std::io::Error| ShredError::Io(e.to_string());
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .open(&full)
        .map_err(io)?;
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut buf = vec![0u8; 1024 * 1024];
    let mut done = 0u64;
    while done < len {
        if cancel.load(Ordering::Relaxed) {
            let _ = file.sync_all();
            return Err(ShredError::Cancelled);
        }
        let n = buf.len().min((len - done) as usize);
        crate::secret::random_bytes(&mut buf[..n]);
        file.write_all(&buf[..n]).map_err(io)?;
        done += n as u64;
        progress(done, len);
    }
    file.sync_all().map_err(io)?;
    drop(file);
    // A random name hides the original one in the folder's records.
    let renamed = full.with_file_name(format!(
        "{}.tmp",
        crate::util::hex(&crate::secret::random_array::<12>())
    ));
    let target = match std::fs::rename(&full, &renamed) {
        Ok(()) => renamed,
        Err(_) => full,
    };
    std::fs::remove_file(&target).map_err(io)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_hashes() {
        let cancel = AtomicBool::new(false);
        let h = |algo| {
            hash_reader(&b"abc"[..], algo, &cancel, |_| {})
                .unwrap()
                .unwrap()
        };
        assert_eq!(
            h(HashAlgo::Sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            h(HashAlgo::Sha1),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert!(h(HashAlgo::Sha512).starts_with("ddaf35a193617abacc417349ae204131"));
        assert!(h(HashAlgo::Blake2b).starts_with("ba80a53f981c4d0d6a2797b69f12f6e9"));
        let empty = hash_reader(&b""[..], HashAlgo::Sha256, &cancel, |_| {})
            .unwrap()
            .unwrap();
        assert_eq!(
            empty,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // Streaming over more than one buffer gives the same as one shot.
        let big = vec![0x5au8; 700_000];
        let mut seen = 0;
        let streamed = hash_reader(&big[..], HashAlgo::Sha256, &cancel, |n| seen = n)
            .unwrap()
            .unwrap();
        assert_eq!(streamed, crate::util::hex(&Sha256::digest(&big)));
        assert_eq!(seen, 700_000);
        assert_eq!(
            hash_reader(&big[..], HashAlgo::Sha256, &AtomicBool::new(true), |_| {}).unwrap(),
            None
        );
    }

    #[test]
    fn hash_comparison() {
        let h = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(hashes_match(h, h), Some(true));
        assert_eq!(hashes_match(h, &h.to_uppercase()), Some(true));
        assert_eq!(
            hashes_match(h, &format!("  {} {}\n", &h[..32], &h[32..])),
            Some(true)
        );
        assert_eq!(hashes_match("a9993e", "A9:99:3E"), Some(true));
        assert_eq!(hashes_match(h, &h[..63]), Some(false));
        assert_eq!(hashes_match(h, &h.replace('b', "c")), Some(false));
        assert_eq!(hashes_match(h, "   "), None);
    }

    #[test]
    fn shred_overwrites_and_deletes_only_plain_files() {
        let dir = crate::util::unique_temp_dir("shred");
        let file = dir.join("secret notes.txt");
        std::fs::write(&file, vec![b'A'; 3_000_000]).unwrap();
        let mut last = (0, 0);
        shred(&file, &AtomicBool::new(false), |d, t| last = (d, t)).unwrap();
        assert_eq!(last, (3_000_000, 3_000_000));
        assert!(!file.exists());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);

        let empty = dir.join("empty.bin");
        std::fs::write(&empty, b"").unwrap();
        shred(&empty, &AtomicBool::new(false), |_, _| {}).unwrap();
        assert!(!empty.exists());

        assert_eq!(shred_check(&dir).err(), Some(ShredError::Folder));
        assert_eq!(
            shred_check(&dir.join("missing")).err(),
            Some(ShredError::NotAFile)
        );
        let windows = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
        assert_eq!(
            shred_check(&windows.join("System32").join("kernel32.dll")).err(),
            Some(ShredError::Protected)
        );
        // Cancelling stops and leaves the (partly overwritten) file in place.
        let keep = dir.join("keep.bin");
        std::fs::write(&keep, vec![1u8; 10]).unwrap();
        assert_eq!(
            shred(&keep, &AtomicBool::new(true), |_, _| {}).err(),
            Some(ShredError::Cancelled)
        );
        assert!(keep.exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
