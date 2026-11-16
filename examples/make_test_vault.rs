//! Development aid: writes a vault full of invented demo data to the given
//! path, for trying the real unlock / save / lock path by hand or from a
//! script. Never point it at a folder that holds a real vault.
//!
//! `cargo run --release --example make_test_vault -- <folder> <password>`

use keepforge::store::OpenVault;
use keepforge::vaultfile::{Credentials, KdfParams};

fn main() {
    let mut args = std::env::args().skip(1);
    let (Some(folder), Some(password)) = (args.next(), args.next()) else {
        eprintln!("usage: make_test_vault <folder> <password>");
        std::process::exit(2);
    };
    let path = std::path::Path::new(&folder).join("Test vault.kfv");
    let mut creds = Credentials::password_only(&password);
    let mut vault = match OpenVault::create(&path, "Test vault", &mut creds, KdfParams::DEFAULT) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let now = keepforge::util::now();
    let demo = keepforge::demo::vault(&vault.session, now);
    vault.vault.items = demo.items;
    vault.vault.folders = demo.folders;
    if let Err(e) = vault.save_now(0) {
        eprintln!("{e:?}");
        std::process::exit(1);
    }
    println!("{}", path.display());
}
