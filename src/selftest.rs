//! `--selftest`: an end-to-end run in a temporary folder with the real key
//! stretching settings. Creates a vault, fills it, saves, reopens, changes
//! the master password, checks backups, export and import, tampering and
//! locking, then cleans up. It never touches the clipboard, the network,
//! global hotkeys or any real vault.

use crate::model::{CustomField, Item, Kind, RecoveryCode};
use crate::secret::{secret_string, Protected};
use crate::store::{self, OpenError, OpenVault};
use crate::vaultfile::{Credentials, KdfParams, VaultError};
use std::sync::atomic::AtomicBool;

fn check(log: &mut Vec<String>, ok: bool, what: &str) -> Result<(), String> {
    if ok {
        log.push(format!("ok    {what}"));
        Ok(())
    } else {
        Err(format!("FAIL  {what}"))
    }
}

pub fn run() -> Result<Vec<String>, String> {
    let dir = crate::util::unique_temp_dir("selftest");
    let result = run_in(&dir);
    let cleaned = std::fs::remove_dir_all(&dir).is_ok() && !dir.exists();
    let mut log = result?;
    check(&mut log, cleaned, "temporary folder removed")?;
    Ok(log)
}

fn run_in(dir: &std::path::Path) -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    let e = |x: OpenError| x.to_string();
    let path = dir.join("Selftest.kfv");
    let kdf = KdfParams::DEFAULT;
    let pw1 = "stoop-unrated-blizzard-ferret";
    let pw2 = "second: orchid tunnel magnet 41";
    let now = crate::util::now();

    // Create and fill.
    let started = std::time::Instant::now();
    let mut v = OpenVault::create(&path, "Selftest", &mut Credentials::password_only(pw1), kdf)
        .map_err(e)?;
    log.push(format!(
        "info  key stretching ({}) took {:.2} s",
        kdf.describe(),
        started.elapsed().as_secs_f64()
    ));
    check(&mut log, path.exists(), "vault file created")?;
    check(
        &mut log,
        v.sealer.keys.pages_locked(),
        "key pages locked into memory (VirtualLock)",
    )?;
    let s = v.session.clone();
    let mut ids = Vec::new();
    for kind in Kind::ALL {
        let mut item = Item::new(kind, now);
        item.title = format!("{} sample", kind.label());
        item.username = "alex.morgan@example.com".into();
        item.password = Protected::seal_str(&s, &format!("pw for {kind:?} ✓"));
        item.notes = Protected::seal_str(&s, "note line 1\nnote line 2");
        item.urls = vec!["https://example.com".into()];
        item.fields
            .push(CustomField::hidden(&s, "Hidden", "hidden value"));
        item.tags = vec!["selftest".into()];
        if kind == Kind::Login {
            item.totp = Protected::seal_str(&s, "JBSWY3DPEHPK3PXP");
            item.recovery_codes.push(RecoveryCode {
                code: Protected::seal_str(&s, "1111-2222"),
                used: false,
            });
        }
        item.folder = v.vault.folder_id("Tests");
        ids.push(item.id);
        v.vault.items.push(item);
    }
    let attachment: Vec<u8> = (0..200_000u32).map(|i| (i * 31 % 251) as u8).collect();
    check(
        &mut log,
        v.add_attachment(ids[0], "sample.bin", &attachment),
        "attachment added",
    )?;
    v.save_now(5).map_err(|x| format!("{x:?}"))?;
    check(
        &mut log,
        store::backup_path(&path, 1).exists(),
        "first save kept a backup of the previous file",
    )?;
    let raw = std::fs::read(&path).map_err(|x| x.to_string())?;
    let leaks = [
        &b"alex.morgan"[..],
        b"sample",
        b"Selftest",
        b"hidden value",
        b"JBSWY3",
    ]
    .iter()
    .any(|needle| raw.windows(needle.len()).any(|w| w == *needle));
    check(&mut log, !leaks, "no plaintext in the vault file")?;

    // A second open of the same file is refused while it is open.
    check(
        &mut log,
        matches!(
            OpenVault::open(&path, &mut Credentials::password_only(pw1), false),
            Err(OpenError::AlreadyOpen)
        ),
        "second instance on the same vault refused",
    )?;

    // Lock, and prove nothing is left alive.
    let token = v.alive_token();
    let escaped = v.vault.items[0].password.clone();
    v.lock();
    check(
        &mut log,
        token.upgrade().is_none() && escaped.open().is_err(),
        "lock wiped the session key and dropped the vault",
    )?;

    // Wrong password, then reopen.
    check(
        &mut log,
        matches!(
            OpenVault::open(
                &path,
                &mut Credentials::password_only("wrong password"),
                false
            ),
            Err(OpenError::Vault(VaultError::WrongKey))
        ),
        "wrong password rejected",
    )?;
    let mut v = OpenVault::open(&path, &mut Credentials::password_only(pw1), false).map_err(e)?;
    check(
        &mut log,
        v.vault.items.len() == Kind::ALL.len(),
        "all item types came back",
    )?;
    let all_ok = Kind::ALL.iter().all(|kind| {
        v.vault.items.iter().any(|i| {
            i.kind == *kind
                && i.password.open_str().as_str() == format!("pw for {kind:?} ✓")
                && i.notes.open_str().as_str() == "note line 1\nnote line 2"
                && i.fields
                    .last()
                    .map(|f| f.text().as_str() == "hidden value")
                    .unwrap_or(false)
        })
    });
    check(
        &mut log,
        all_ok,
        "passwords, notes and hidden fields round-trip",
    )?;
    let att = v.vault.items[0].attachments[0].clone();
    check(
        &mut log,
        v.read_attachment(&att)
            .map(|b| b[..] == attachment[..])
            .unwrap_or(false),
        "attachment round-trips",
    )?;
    let totp =
        crate::totp::Totp::parse(&v.vault.items[0].totp.open_str()).map_err(|x| x.to_string())?;
    check(&mut log, totp.code_at(59).len() == 6, "one-time code works")?;

    // Change the master password; backups rotate.
    v.change_credentials(&mut Credentials::password_only(pw2), kdf)
        .map_err(|x| x.to_string())?;
    v.save_now(5).map_err(|x| format!("{x:?}"))?;
    check(
        &mut log,
        store::backup_path(&path, 2).exists(),
        "backups rotated (.bak1, .bak2)",
    )?;
    drop(v);
    check(
        &mut log,
        OpenVault::open(&path, &mut Credentials::password_only(pw1), false).is_err(),
        "old master password no longer opens the vault",
    )?;
    let old_backup = OpenVault::open(
        &store::backup_path(&path, 1),
        &mut Credentials::password_only(pw1),
        false,
    );
    check(
        &mut log,
        old_backup.is_ok(),
        "the backup still opens with the old password",
    )?;
    drop(old_backup);
    let v = OpenVault::open(&path, &mut Credentials::password_only(pw2), false).map_err(e)?;
    let att = v.vault.items[0].attachments[0].clone();
    check(
        &mut log,
        v.read_attachment(&att)
            .map(|b| b[..] == attachment[..])
            .unwrap_or(false),
        "attachment readable after the password change",
    )?;

    // Rolling backups never exceed the limit.
    for round in 0..8u8 {
        store::rotate_backups(&path, 3).map_err(|x| x.to_string())?;
        let _ = round;
    }
    check(
        &mut log,
        store::backup_path(&path, 3).exists() && !store::backup_path(&path, 6).exists(),
        "rolling backups stay within the limit",
    )?;

    // Export and import round trip.
    let csv = crate::export::to_csv(&v.vault);
    let text = std::str::from_utf8(csv.as_slice()).map_err(|x| x.to_string())?;
    let loaded = crate::import::load(text)?;
    let mut other = OpenVault::in_memory(|_| crate::model::Vault::new("Import", now));
    let session = other.session.clone();
    let added = crate::import::apply(&mut other.vault, &session, &loaded.drafts, &[], now);
    check(
        &mut log,
        added == Kind::ALL.len(),
        "CSV export imports back completely",
    )?;
    let same = other.vault.items.iter().all(|i| {
        v.vault
            .items
            .iter()
            .any(|o| o.title == i.title && o.password.same_secret(&i.password) && o.kind == i.kind)
    });
    check(&mut log, same, "imported entries match the originals")?;
    let again = crate::import::find_duplicates(&other.vault, &loaded.drafts);
    check(
        &mut log,
        again.iter().all(|d| *d),
        "re-import is recognised as duplicates",
    )?;
    let json = crate::export::to_json(&v.vault);
    let doc: serde_json::Value =
        serde_json::from_slice(json.as_slice()).map_err(|x| x.to_string())?;
    check(
        &mut log,
        doc["items"].as_array().map(|a| a.len()) == Some(Kind::ALL.len()),
        "JSON export is valid",
    )?;
    drop(other);

    // Tampering and truncation.
    let good = std::fs::read(&path).map_err(|x| x.to_string())?;
    drop(v);
    let mut all_rejected = true;
    for at in [9usize, 20, 40, 70, 100, 130, good.len() / 2, good.len() - 1] {
        let mut bad = good.clone();
        bad[at] ^= 0x04;
        std::fs::write(&path, &bad).map_err(|x| x.to_string())?;
        all_rejected &= OpenVault::open(&path, &mut Credentials::password_only(pw2), true).is_err();
    }
    std::fs::write(&path, &good[..good.len() - 100]).map_err(|x| x.to_string())?;
    all_rejected &= OpenVault::open(&path, &mut Credentials::password_only(pw2), true).is_err();
    check(
        &mut log,
        all_rejected,
        "tampered and truncated files are rejected",
    )?;
    std::fs::write(&path, &good).map_err(|x| x.to_string())?;
    check(
        &mut log,
        OpenVault::open(&path, &mut Credentials::password_only(pw2), false).is_ok(),
        "the untouched file still opens",
    )?;

    // Encrypted file sharing (.kfx).
    let mut kfx = Vec::new();
    let meta = crate::kfx::Meta {
        content: crate::kfx::Content::File,
        name: "sample.bin".into(),
    };
    let none = AtomicBool::new(false);
    crate::kfx::encrypt(
        &attachment[..],
        &mut kfx,
        &secret_string(pw1),
        kdf,
        &meta,
        &none,
        |_| {},
    )
    .map_err(|x| x.to_string())?;
    let back = crate::kfx::decrypt(
        &kfx[..],
        &secret_string(pw1),
        |_| Ok(Vec::new()),
        &none,
        |_| {},
    );
    check(
        &mut log,
        matches!(&back, Ok((m, data)) if *m == meta && data[..] == attachment[..]),
        ".kfx file round-trips",
    )?;
    let cut = &kfx[..kfx.len() - 70_000];
    check(
        &mut log,
        crate::kfx::decrypt(cut, &secret_string(pw1), |_| Ok(Vec::new()), &none, |_| {}).is_err(),
        "a cut-off .kfx file is rejected",
    )?;

    // Generators.
    let generated = crate::generator::password(&Default::default(), &mut crate::generator::OsRng);
    check(
        &mut log,
        generated.chars().count() == 20,
        "password generator works",
    )?;
    Ok(log)
}

#[cfg(test)]
mod tests {
    /// The whole self-test, with the real 256 MiB key stretching.
    #[test]
    fn selftest_passes() {
        let log = super::run().unwrap_or_else(|e| panic!("{e}"));
        assert!(log.len() > 20);
    }
}
