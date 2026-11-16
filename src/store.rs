//! An unlocked vault and its file: atomic saves, rolling backups, detecting
//! changes made by another device, merging, and one-instance-per-file.

use crate::model::{Attachment, Id, Vault};
use crate::secret::{random_array, SecretBytes, SessionKey};
use crate::util;
use crate::vaultfile::{self, Credentials, KdfParams, Sealer, VaultError};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use windows::core::HSTRING;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::System::Threading::CreateMutexW;

/// Take a new backup at most this often while a vault stays open.
pub const BACKUP_INTERVAL: i64 = 3600;

/// What the file looked like when we last read or wrote it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileStamp {
    pub len: u64,
    pub sha256: [u8; 32],
}

pub fn stamp(bytes: &[u8]) -> FileStamp {
    FileStamp {
        len: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    }
}

/// Reads a vault file, refusing anything implausibly large before reading it.
pub fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("Could not open the file: {e}"))?;
    if !meta.is_file() {
        return Err("That is not a file.".into());
    }
    if meta.len() > vaultfile::MAX_FILE_LEN {
        return Err("This file is too large to be a KeepForge vault.".into());
    }
    std::fs::read(path).map_err(|e| format!("Could not read the file: {e}"))
}

/// `vault.kfv` → `vault.kfv.bak3`.
pub fn backup_path(path: &Path, n: u32) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".bak{n}"));
    path.with_file_name(name)
}

/// Shifts `.bak1..` up by one (dropping the oldest) and copies the current
/// file to `.bak1`. With `keep == 0` nothing is kept.
pub fn rotate_backups(path: &Path, keep: u32) -> std::io::Result<()> {
    if keep == 0 || !path.exists() {
        return Ok(());
    }
    let _ = std::fs::remove_file(backup_path(path, keep));
    for n in (1..keep).rev() {
        let from = backup_path(path, n);
        if from.exists() {
            std::fs::rename(&from, backup_path(path, n + 1))?;
        }
    }
    std::fs::copy(path, backup_path(path, 1))?;
    Ok(())
}

/// Writes `bytes` to a temporary file in the same folder, flushes it to
/// disk, then renames it over `path`. A crash leaves either the old file or
/// the new one, never a half-written vault.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp_name = path.file_name().unwrap_or_default().to_os_string();
    tmp_name.push(format!(".{}.tmp", util::hex(&random_array::<6>())));
    let tmp = path.with_file_name(tmp_name);
    let result = (|| {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        // FlushFileBuffers: the data is on the disk before the rename.
        f.sync_all()?;
        drop(f);
        // MoveFileExW with MOVEFILE_REPLACE_EXISTING.
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

// --------------------------------------------------------------------------------------
// One instance per vault file
// --------------------------------------------------------------------------------------

/// A named mutex held while a vault file is open in this process.
pub struct InstanceLock(HANDLE);

// SAFETY: a mutex handle may be closed from any thread.
unsafe impl Send for InstanceLock {}

impl InstanceLock {
    /// `None` when another KeepForge already has this file open.
    pub fn acquire(path: &Path) -> Option<InstanceLock> {
        // The file may not exist yet (a vault being created), so resolve the
        // folder and append the file name.
        let folder = path.parent().filter(|p| !p.as_os_str().is_empty());
        let folder = folder
            .and_then(|p| std::fs::canonicalize(p).ok())
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_default();
        let canonical = folder.join(path.file_name().unwrap_or_default());
        let key = canonical.to_string_lossy().to_lowercase();
        let digest = Sha256::digest(key.as_bytes());
        let name = HSTRING::from(format!(
            "Local\\KeepForge-vault-{}",
            util::hex(&digest[..16])
        ));
        // SAFETY: plain Win32 call with a valid, NUL-terminated name.
        let handle = unsafe { CreateMutexW(None, false, &name) }.ok()?;
        // SAFETY: reads the calling thread's last error set by CreateMutexW.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: the handle was just returned to us.
            unsafe {
                let _ = CloseHandle(handle);
            }
            return None;
        }
        Some(InstanceLock(handle))
    }
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value.
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

// --------------------------------------------------------------------------------------
// Merging
// --------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MergeStats {
    pub added: usize,
    pub updated: usize,
    pub kept: usize,
}

/// Merges `theirs` into `mine`, item by item: an item only on one side is
/// kept, and where both sides have it the more recently modified one wins.
pub fn merge_newest(mine: &mut Vault, theirs: Vault) -> MergeStats {
    let mut stats = MergeStats::default();
    for f in theirs.folders {
        if !mine.folders.iter().any(|m| m.id == f.id) {
            mine.folders.push(f);
        }
    }
    for item in theirs.items {
        match mine.items.iter_mut().find(|m| m.id == item.id) {
            None => {
                mine.items.push(item);
                stats.added += 1;
            }
            Some(existing) if item.modified > existing.modified => {
                *existing = item;
                stats.updated += 1;
            }
            Some(_) => stats.kept += 1,
        }
    }
    for k in theirs.service_keys {
        if mine.service_key(&k.service).is_none() {
            mine.service_keys.push(k);
        }
    }
    mine.modified = mine.modified.max(theirs.modified);
    stats
}

// --------------------------------------------------------------------------------------
// The unlocked vault
// --------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenError {
    Vault(VaultError),
    Io(String),
    /// Another KeepForge window has this file open.
    AlreadyOpen,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::Vault(e) => e.fmt(f),
            OpenError::Io(e) => f.write_str(e),
            OpenError::AlreadyOpen => {
                f.write_str("This vault is already open in another KeepForge window.")
            }
        }
    }
}

impl From<VaultError> for OpenError {
    fn from(e: VaultError) -> Self {
        OpenError::Vault(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SaveError {
    /// The file on disk is not the one we opened or last saved.
    ChangedOnDisk,
    Io(String),
}

/// A vault that is unlocked. Dropping it (or calling [`OpenVault::lock`])
/// wipes the session key, which makes every secret it held unreadable.
pub struct OpenVault {
    pub vault: Vault,
    pub sealer: Sealer,
    pub session: Arc<SessionKey>,
    /// `None` for the in-memory demo vault.
    pub path: Option<PathBuf>,
    stamp: Option<FileStamp>,
    last_backup: Option<i64>,
    alive: Arc<()>,
    _lock: Option<InstanceLock>,
}

/// Everything a worker thread needs to write the vault.
pub struct SaveJob {
    vault: Vault,
    sealer: Sealer,
    path: PathBuf,
    expected: Option<FileStamp>,
    backups: u32,
    make_backup: bool,
    /// Write even if the file changed on disk.
    pub force: bool,
}

pub struct Saved {
    pub stamp: FileStamp,
    pub backed_up: bool,
    pub at: i64,
}

impl SaveJob {
    pub fn run(self) -> Result<Saved, SaveError> {
        let io = |e: std::io::Error| SaveError::Io(format!("Could not save the vault: {e}"));
        if self.path.exists() && !self.force {
            let current = read_file(&self.path).map_err(SaveError::Io)?;
            if Some(stamp(&current)) != self.expected {
                return Err(SaveError::ChangedOnDisk);
            }
        }
        let bytes = vaultfile::encode(&self.vault, &self.sealer)
            .map_err(|e| SaveError::Io(e.to_string()))?;
        let mut backed_up = false;
        if self.make_backup && self.path.exists() {
            rotate_backups(&self.path, self.backups).map_err(io)?;
            backed_up = self.backups > 0;
        }
        write_atomic(&self.path, &bytes).map_err(io)?;
        Ok(Saved {
            stamp: stamp(&bytes),
            backed_up,
            at: util::now(),
        })
    }
}

impl OpenVault {
    /// Creates a new vault file. Fails if the file already exists.
    pub fn create(
        path: &Path,
        name: &str,
        creds: &mut Credentials,
        kdf: KdfParams,
    ) -> Result<OpenVault, OpenError> {
        if path.exists() {
            creds.wipe();
            return Err(OpenError::Io(
                "A file with this name already exists. Choose another name.".into(),
            ));
        }
        let lock = InstanceLock::acquire(path);
        let sealer = Sealer::create(creds, kdf)?;
        let vault = Vault::new(name, util::now());
        let bytes = vaultfile::encode(&vault, &sealer)?;
        write_atomic(path, &bytes)
            .map_err(|e| OpenError::Io(format!("Could not create the vault file: {e}")))?;
        Ok(OpenVault {
            vault,
            sealer,
            session: SessionKey::new(),
            path: Some(path.to_path_buf()),
            stamp: Some(stamp(&bytes)),
            last_backup: None,
            alive: Arc::new(()),
            _lock: lock,
        })
    }

    /// Unlocks an existing vault file.
    pub fn open(
        path: &Path,
        creds: &mut Credentials,
        allow_unusual: bool,
    ) -> Result<OpenVault, OpenError> {
        let Some(lock) = InstanceLock::acquire(path) else {
            creds.wipe();
            return Err(OpenError::AlreadyOpen);
        };
        let bytes = read_file(path).map_err(|e| {
            creds.wipe();
            OpenError::Io(e)
        })?;
        let session = SessionKey::new();
        let (vault, sealer) = vaultfile::open(&bytes, creds, allow_unusual, &session)?;
        Ok(OpenVault {
            vault,
            sealer,
            session,
            path: Some(path.to_path_buf()),
            stamp: Some(stamp(&bytes)),
            last_backup: None,
            alive: Arc::new(()),
            _lock: Some(lock),
        })
    }

    /// A vault that lives only in memory (demo mode). Its keys are random.
    pub fn in_memory(build: impl FnOnce(&Arc<SessionKey>) -> Vault) -> OpenVault {
        let session = SessionKey::new();
        let master = zeroize::Zeroizing::new(random_array::<64>());
        let salt = random_array();
        OpenVault {
            vault: build(&session),
            sealer: Sealer {
                keys: Arc::new(vaultfile::keys_from_master(&master, &salt)),
                kdf: KdfParams::DEFAULT,
                salt,
                key_file: false,
            },
            session,
            path: None,
            stamp: None,
            last_backup: None,
            alive: Arc::new(()),
            _lock: None,
        }
    }

    /// A token that dies with this unlocked vault (used to prove a lock
    /// left nothing alive).
    pub fn alive_token(&self) -> Weak<()> {
        Arc::downgrade(&self.alive)
    }

    /// When the last backup of this session was taken.
    pub fn last_backup(&self) -> Option<i64> {
        self.last_backup
    }

    /// A snapshot to save on a worker thread. `None` for in-memory vaults.
    pub fn save_job(&mut self, backups: u32, now: i64) -> Option<SaveJob> {
        let path = self.path.clone()?;
        self.vault.modified = now;
        let make_backup = match self.last_backup {
            None => true,
            Some(t) => now - t >= BACKUP_INTERVAL,
        };
        Some(SaveJob {
            vault: self.vault.clone(),
            sealer: self.sealer.share(),
            path,
            expected: self.stamp.clone(),
            backups,
            make_backup,
            force: false,
        })
    }

    pub fn saved(&mut self, done: &Saved) {
        self.stamp = Some(done.stamp.clone());
        if done.backed_up || self.last_backup.is_none() {
            self.last_backup = Some(done.at);
        }
    }

    /// Saves on the calling thread (self-test and tests).
    pub fn save_now(&mut self, backups: u32) -> Result<(), SaveError> {
        let Some(job) = self.save_job(backups, util::now()) else {
            return Ok(());
        };
        let done = job.run()?;
        self.saved(&done);
        Ok(())
    }

    /// Reads the copy on disk with the keys we already hold (for merging
    /// after another device changed the file). Fails with `WrongKey` if
    /// that copy uses another password or other KDF settings.
    pub fn read_disk_copy(&self) -> Result<Vault, OpenError> {
        let path = self.path.as_ref().ok_or(OpenError::Io("No file.".into()))?;
        let bytes = read_file(path).map_err(OpenError::Io)?;
        let header = vaultfile::parse_header(&bytes)?;
        if header.salt != self.sealer.salt {
            return Err(OpenError::Vault(VaultError::WrongKey));
        }
        let (vault, _) = vaultfile::decode_with_keys(&bytes, &self.sealer.keys, &self.session)?;
        Ok(vault)
    }

    /// Changes the master password, key file and/or KDF strength: new salt,
    /// new keys, attachments re-encrypted. The caller saves afterwards.
    pub fn change_credentials(
        &mut self,
        creds: &mut Credentials,
        kdf: KdfParams,
    ) -> Result<(), VaultError> {
        let fresh = Sealer::create(creds, kdf)?;
        self.replace_sealer(fresh)
    }

    /// Switches to keys that were derived elsewhere (on a worker thread).
    /// The next save takes a backup first.
    pub fn replace_sealer(&mut self, fresh: Sealer) -> Result<(), VaultError> {
        vaultfile::rekey_attachments(&mut self.vault, &self.sealer, &fresh)?;
        self.sealer = fresh;
        self.last_backup = None;
        Ok(())
    }

    pub fn add_attachment(&mut self, item: Id, name: &str, content: &[u8]) -> bool {
        let att = vaultfile::seal_attachment(&self.sealer.keys, &self.sealer.salt, name, content);
        match self.vault.item_mut(item) {
            Some(i) => {
                i.attachments.push(att);
                true
            }
            None => false,
        }
    }

    pub fn read_attachment(&self, att: &Attachment) -> Result<SecretBytes, VaultError> {
        vaultfile::open_attachment(&self.sealer.keys, &self.sealer.salt, att)
    }

    /// Locks the vault: wipes the session key and drops everything.
    pub fn lock(self) {
        drop(self);
    }
}

impl Drop for OpenVault {
    fn drop(&mut self) {
        self.session.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Item, Kind};
    use crate::secret::Protected;
    use crate::vaultfile::tests::TEST_KDF;

    fn temp_dir(tag: &str) -> PathBuf {
        util::unique_temp_dir(tag)
    }

    fn creds(p: &str) -> Credentials {
        Credentials::password_only(p)
    }

    #[test]
    fn atomic_save_and_backup_rotation() {
        let dir = temp_dir("rotate");
        let path = dir.join("v.kfv");
        for round in 0..6u8 {
            if round > 0 {
                rotate_backups(&path, 3).unwrap();
            }
            write_atomic(&path, &[round; 10]).unwrap();
        }
        assert_eq!(std::fs::read(&path).unwrap(), [5u8; 10]);
        assert_eq!(std::fs::read(backup_path(&path, 1)).unwrap(), [4u8; 10]);
        assert_eq!(std::fs::read(backup_path(&path, 2)).unwrap(), [3u8; 10]);
        assert_eq!(std::fs::read(backup_path(&path, 3)).unwrap(), [2u8; 10]);
        assert!(!backup_path(&path, 4).exists());
        // No temporary files are left behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty());
        // keep = 0 keeps nothing.
        let other = dir.join("w.kfv");
        write_atomic(&other, b"a").unwrap();
        rotate_backups(&other, 0).unwrap();
        assert!(!backup_path(&other, 1).exists());
        assert_eq!(backup_path(&path, 2).file_name().unwrap(), "v.kfv.bak2");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn create_open_save_and_detect_outside_changes() {
        let dir = temp_dir("open");
        let path = dir.join("my.kfv");
        let mut v = OpenVault::create(&path, "Mine", &mut creds("pw"), TEST_KDF).unwrap();
        // A second open of the same file in this session is refused.
        assert_eq!(
            OpenVault::open(&path, &mut creds("pw"), false).err(),
            Some(OpenError::AlreadyOpen)
        );
        assert!(OpenVault::create(&path, "Again", &mut creds("pw"), TEST_KDF).is_err());
        let mut item = Item::new(Kind::Login, 5);
        item.title = "Example Mail".into();
        item.password = Protected::seal_str(&v.session, "s3cret");
        let id = item.id;
        v.vault.items.push(item);
        assert!(v.add_attachment(id, "note.txt", b"attached text"));
        v.save_now(5).unwrap();
        assert!(backup_path(&path, 1).exists());
        v.save_now(5).unwrap();
        // Within the hour, no second backup.
        assert!(!backup_path(&path, 2).exists());

        // Someone else rewrites the file: our next save must notice.
        let original = std::fs::read(&path).unwrap();
        let other_copy = {
            let mut other = v.vault.clone();
            other.items[0].title = "Changed elsewhere".into();
            other.items[0].modified += 100;
            let mut extra = Item::new(Kind::Note, 9);
            extra.title = "Added elsewhere".into();
            other.items.push(extra);
            vaultfile::encode(&other, &v.sealer).unwrap()
        };
        std::fs::write(&path, &other_copy).unwrap();
        v.vault.items[0].username = "local edit".into();
        assert_eq!(v.save_now(5).err(), Some(SaveError::ChangedOnDisk));
        assert_eq!(std::fs::read(&path).unwrap(), other_copy);
        // Merge by newest, then a forced save goes through.
        let theirs = v.read_disk_copy().unwrap();
        let stats = merge_newest(&mut v.vault, theirs);
        assert_eq!(
            stats,
            MergeStats {
                added: 1,
                updated: 1,
                kept: 0
            }
        );
        assert_eq!(v.vault.items[0].title, "Changed elsewhere");
        let mut job = v.save_job(5, util::now()).unwrap();
        job.force = true;
        let done = job.run().unwrap();
        v.saved(&done);
        v.save_now(5).unwrap();
        assert_ne!(std::fs::read(&path).unwrap(), original);

        let att = v.vault.items[0].attachments[0].clone();
        assert_eq!(&v.read_attachment(&att).unwrap()[..], b"attached text");
        drop(v);
        let v = OpenVault::open(&path, &mut creds("pw"), false).unwrap();
        assert_eq!(v.vault.items.len(), 2);
        assert_eq!(
            OpenVault::open(&dir.join("missing.kfv"), &mut creds("pw"), false)
                .err()
                .map(|e| matches!(e, OpenError::Io(_))),
            Some(true)
        );
        drop(v);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn lock_wipes_state() {
        let mut v = OpenVault::in_memory(|s| {
            let mut vault = Vault::new("Demo", 1);
            let mut i = Item::new(Kind::Login, 1);
            i.password = Protected::seal_str(s, "do not keep me");
            vault.items.push(i);
            vault
        });
        assert!(v.save_job(5, 1).is_none());
        let token = v.alive_token();
        let session = v.session.clone();
        // A copy of a secret that escaped (say, into a worker thread).
        let escaped = v.vault.items[0].password.clone();
        let keys = Arc::downgrade(&v.sealer.keys);
        assert_eq!(escaped.open_str().as_str(), "do not keep me");
        assert!(token.upgrade().is_some());
        v.lock();
        // No vault object is alive, the keys are gone, and the escaped
        // ciphertext can no longer be opened by anyone.
        assert!(token.upgrade().is_none());
        assert!(keys.upgrade().is_none());
        assert!(!session.is_alive());
        assert!(escaped.open().is_err());
    }

    #[test]
    fn change_master_password() {
        let dir = temp_dir("rekey");
        let path = dir.join("r.kfv");
        let mut v = OpenVault::create(&path, "R", &mut creds("old"), TEST_KDF).unwrap();
        let item = Item::new(Kind::Note, 1);
        let id = item.id;
        v.vault.items.push(item);
        v.add_attachment(id, "a", b"abc");
        v.save_now(2).unwrap();
        let salt = v.sealer.salt;
        let stronger = KdfParams { t: 3, ..TEST_KDF };
        v.change_credentials(&mut creds("new"), stronger).unwrap();
        assert_ne!(v.sealer.salt, salt);
        v.save_now(2).unwrap();
        drop(v);
        assert_eq!(
            OpenVault::open(&path, &mut creds("old"), false).err(),
            Some(OpenError::Vault(VaultError::WrongKey))
        );
        let v = OpenVault::open(&path, &mut creds("new"), false).unwrap();
        assert_eq!(v.sealer.kdf, stronger);
        let att = v.vault.items[0].attachments[0].clone();
        assert_eq!(&v.read_attachment(&att).unwrap()[..], b"abc");
        // The backup still opens with the old password.
        drop(v);
        let b = OpenVault::open(&backup_path(&path, 1), &mut creds("old"), false).unwrap();
        drop(b);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
