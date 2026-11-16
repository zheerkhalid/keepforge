//! Sets up the invented screens used by `--demo` and `--screenshot`.

use super::app::{Screen, Shared};
use super::edit::EditForm;
use super::main_view::{Main, Nav};
use super::start::{CreateState, UnlockState, WelcomeState};
use super::tools::Tab;
use crate::settings::RecentVault;
use crate::store::OpenVault;

fn demo_main(sh: &Shared) -> Main {
    let now = sh.now;
    let vault = OpenVault::in_memory(|s| crate::demo::vault(s, now));
    Main::new(vault, Some(0.7))
}

fn select(main: &mut Main, title: &str) {
    main.selected = main
        .v
        .vault
        .items
        .iter()
        .find(|i| i.title == title)
        .map(|i| i.id);
}

/// The first screen for a view name given on the command line.
pub fn initial_screen(view: &str, sh: &mut Shared) -> Screen {
    sh.settings.recent = vec![
        RecentVault {
            path: crate::demo::DEMO_PATH.into(),
            name: "Personal".into(),
            last_opened: sh.now - 3600,
            key_file: None,
        },
        RecentVault {
            path: "D:\\Shared\\Family.kfv".into(),
            name: "Family".into(),
            last_opened: sh.now - 6 * 86_400,
            key_file: None,
        },
    ];
    match view {
        "welcome" => return Screen::Welcome(WelcomeState::default()),
        "unlock" => return Screen::Unlock(Box::new(UnlockState::demo("Personal"))),
        "create" => {
            let mut c = CreateState::new(sh, false);
            c.password.set("stoop-unrated-blizzard-ferret");
            c.confirm.set("stoop-unrated-blizzard-ferret");
            return Screen::Create(Box::new(c));
        }
        _ => {}
    }
    let mut main = demo_main(sh);
    match view {
        "edit" => {
            select(&mut main, "Sample Bank");
            if let Some(item) = main.selected.and_then(|id| main.v.vault.item(id)) {
                let mut form = EditForm::from_item(item, &main.v.vault, sh);
                form.demo_generator();
                main.edit = Some(Box::new(form));
            }
        }
        "generator" => {
            main.nav = Nav::Generator;
            main.pages.gen_value.set("m7#Qv2!xLp9@Wz4&Tr6k");
        }
        "health" => {
            main.nav = Nav::Health;
            main.demo_online_results();
        }
        "breach" => {
            main.nav = Nav::Breach;
            main.demo_online_results();
            main.pages.email_input = crate::demo::DEMO_EMAIL.into();
        }
        "dialog-online" => {
            main.nav = Nav::Breach;
            main.dialog = Some(super::dialogs::Dialog::Online(
                super::dialogs::Online::Emails(vec![crate::demo::DEMO_EMAIL.into()]),
                false,
            ));
        }
        "dialog-password" => {
            main.nav = Nav::Settings;
            main.dialog = Some(super::dialogs::Dialog::change_password(main.v.sealer.kdf));
        }
        "authenticator" => main.nav = Nav::Authenticator,
        "settings" => main.nav = Nav::Settings,
        "trash" => main.nav = Nav::Trash,
        v if v.starts_with("tools") => {
            main.nav = Nav::Tools;
            main.tools.demo_fill();
            main.tools.tab = match v {
                "tools-names" => Tab::Names,
                "tools-encrypt" => Tab::Encrypt,
                "tools-checksum" => Tab::Checksum,
                "tools-qr" => Tab::Qr,
                "tools-shred" => Tab::Shred,
                "tools-torrent" => {
                    main.pages.ip_input = "93.184.216.34".into();
                    main.pages.peer = Some(Ok(crate::demo::peer_report()));
                    Tab::Torrent
                }
                _ => Tab::Strength,
            };
        }
        "card" => select(&mut main, "Sample Bank debit card"),
        "wifi" => select(&mut main, "Home Wi-Fi"),
        _ => select(&mut main, "Example Mail"),
    }
    Screen::Main(Box::new(main))
}
