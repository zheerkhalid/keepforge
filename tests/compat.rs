//! Vaults written by earlier versions must keep opening.
//!
//! `fixtures/vault-1.0.1.kfv` was written by KeepForge 1.0.1 itself (the
//! `make_test_vault` example built from the `v1.0.1` tag): the invented demo
//! data under an invented password. This test opens it with the current
//! code, checks what is inside, saves it and opens it again.

use keepforge::model::Kind;
use keepforge::store::{OpenError, OpenVault};
use keepforge::vaultfile::{self, Credentials, VaultError};

const FIXTURE: &[u8] = include_bytes!("fixtures/vault-1.0.1.kfv");
const PASSWORD: &str = "fixture-password-for-tests-1.0.1";

#[test]
fn a_vault_written_by_1_0_1_opens_saves_and_reopens() {
    let dir = keepforge::util::unique_temp_dir("compat");
    let path = dir.join("old.kfv");
    std::fs::write(&path, FIXTURE).unwrap();

    // The plain header is the 1.0.x layout and asks for no key file.
    let header = vaultfile::parse_header(FIXTURE).expect("header");
    assert!(!header.needs_key_file());

    // A wrong password is still refused.
    let wrong = OpenVault::open(&path, &mut Credentials::password_only("not it"), false);
    assert!(matches!(
        wrong.err(),
        Some(OpenError::Vault(VaultError::WrongKey))
    ));

    let mut v = OpenVault::open(&path, &mut Credentials::password_only(PASSWORD), false)
        .expect("the 1.0.1 vault opens");
    assert_eq!(v.vault.name, "Test vault");
    assert_eq!(v.vault.items.len(), 20);
    assert_eq!(v.vault.folders.len(), 3);
    for kind in Kind::ALL {
        assert!(v.vault.items.iter().any(|i| i.kind == kind), "{kind:?}");
    }
    let mail = v
        .vault
        .items
        .iter()
        .find(|i| i.title == "Example Mail")
        .expect("Example Mail");
    assert_eq!(mail.username, "alex.morgan@example.com");
    assert_eq!(mail.password.open_str().as_str(), "tU9#vqLr2!xWmZ6p");
    assert_eq!(mail.history.len(), 2);
    assert_eq!(
        mail.history[0].password.open_str().as_str(),
        "Summer-Mail-2022"
    );
    assert_eq!(mail.recovery_codes.len(), 4);
    assert!(mail.recovery_codes[0].used);
    assert!(mail.favourite);
    assert_eq!(mail.tags, vec!["mail".to_string(), "2fa".to_string()]);
    assert!(mail.notes.open_str().starts_with("Recovery address"));
    assert!(keepforge::totp::Totp::parse(&mail.totp.open_str()).is_ok());
    assert_eq!(
        mail.field("Security answer").unwrap().text().as_str(),
        "blue heron 1987"
    );
    let old_blog = v
        .vault
        .items
        .iter()
        .find(|i| i.title == "Old Blog")
        .unwrap();
    assert!(old_blog.in_trash());
    let mail_id = mail.id;
    let before: Vec<(String, String)> = v
        .vault
        .items
        .iter()
        .map(|i| (i.title.clone(), i.password.open_str().to_string()))
        .collect();

    // Change something with this version, save, lock, open again.
    let session = v.session.clone();
    v.vault
        .item_mut(mail_id)
        .unwrap()
        .set_password(&session, "a-new-password-1.1", 1_900_000_000);
    v.save_now(1).expect("saved by the current version");
    v.lock();

    let v = OpenVault::open(&path, &mut Credentials::password_only(PASSWORD), false)
        .expect("opens again after a save");
    let mail = v.vault.item(mail_id).unwrap();
    assert_eq!(mail.password.open_str().as_str(), "a-new-password-1.1");
    assert_eq!(mail.history.len(), 3);
    assert_eq!(
        mail.history[0].password.open_str().as_str(),
        "tU9#vqLr2!xWmZ6p"
    );
    for (item, (title, password)) in v.vault.items.iter().zip(&before) {
        assert_eq!(&item.title, title);
        if item.id != mail_id {
            assert_eq!(item.password.open_str().as_str(), password, "{title}");
        }
    }
    // The backup taken before the save is the untouched 1.0.1 file.
    let backup = std::fs::read(keepforge::store::backup_path(&path, 1)).unwrap();
    assert_eq!(backup, FIXTURE);
    v.lock();
    std::fs::remove_dir_all(&dir).unwrap();
}
