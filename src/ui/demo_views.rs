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
    // The demo has some online sources switched on (it never goes online).
    for code in crate::demo::DEMO_SOURCES {
        sh.settings.set_source(code, true);
    }
    sh.settings.breach_check = true;
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
        "breach" | "exposure" => {
            main.nav = Nav::Exposure;
            main.demo_online_results();
            main.exp.input = crate::demo::DEMO_EMAIL.into();
            main.exp.selected = Some((
                crate::exposure::QueryKind::Email,
                crate::demo::DEMO_EMAIL.into(),
            ));
        }
        "exposure-results" => {
            main.nav = Nav::Exposure;
            main.demo_online_results();
            main.exp.selected = Some((
                crate::exposure::QueryKind::Email,
                crate::demo::DEMO_EMAIL.into(),
            ));
            main.exp.scroll_to_results = true;
        }
        "exposure-username" => {
            main.nav = Nav::Exposure;
            main.demo_online_results();
            main.exp.tab = super::exposure::Tab::Lookup(crate::exposure::QueryKind::Username);
            main.exp.input = "alex_m".into();
            main.exp.own_username = true;
            main.exp.selected = Some((crate::exposure::QueryKind::Username, "alex_m".into()));
            main.exp.scroll_to_results = true;
        }
        "exposure-domain" => {
            main.nav = Nav::Exposure;
            main.demo_online_results();
            main.exp.tab = super::exposure::Tab::Lookup(crate::exposure::QueryKind::Domain);
        }
        "exposure-password" => {
            main.nav = Nav::Exposure;
            main.exp.tab = super::exposure::Tab::Password;
            main.exp.pw_results = vec![
                (
                    crate::exposure::password::PwSource::PwnedPasswords,
                    Ok(10_434_004),
                ),
                (
                    crate::exposure::password::PwSource::XposedOrNot,
                    Ok(9_545_824),
                ),
            ];
        }
        "dialog-online" => {
            // As on first use: nothing switched on yet.
            sh.settings.exposure_sources.clear();
            main.nav = Nav::Exposure;
            let what = super::exposure::Pending::Lookup(
                vec![crate::exposure::Task {
                    kind: crate::exposure::QueryKind::Email,
                    value: crate::demo::DEMO_EMAIL.into(),
                }],
                false,
            );
            let picks = what
                .candidates()
                .iter()
                .map(|(code, _, _)| (*code, matches!(*code, "xposedornot" | "leakcheck")))
                .collect();
            main.dialog = Some(super::dialogs::Dialog::Online(
                super::dialogs::Online::Sources(what, picks),
                false,
            ));
        }
        "dialog-password" => {
            main.nav = Nav::Settings;
            main.dialog = Some(super::dialogs::Dialog::change_password(main.v.sealer.kdf));
        }
        "authenticator" => main.nav = Nav::Authenticator,
        "settings" => main.nav = Nav::Settings,
        "settings-online" => {
            main.nav = Nav::Settings;
            main.pages.scroll_online = true;
        }
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
        "kurdish" => {
            select(&mut main, crate::demo::DEMO_KURDISH_TITLE);
            main.reveal.insert("notes".into(), f64::MAX);
            main.scroll_to_selected = true;
        }
        "recent" => {
            sh.settings.list_sort = crate::settings::SortOrder::Changed;
            select(&mut main, "Example Mail");
        }
        "generator-history" => {
            main.nav = Nav::Generator;
            main.pages.gen_value.set("m7#Qv2!xLp9@Wz4&Tr6k");
            let session = main.v.session.clone();
            for pw in ["harbor-plank-violet-otter", "T4w!nB8z#Rk2@Lq6"] {
                main.pages.remember_generated(&session, pw);
            }
            main.reveal.insert("gen0".into(), f64::MAX);
        }
        "card" => select(&mut main, "Sample Bank debit card"),
        "wifi" => select(&mut main, "Home Wi-Fi"),
        _ => select(&mut main, "Example Mail"),
    }
    Screen::Main(Box::new(main))
}
