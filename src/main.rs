#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use keepforge::ui::{self, Options};
use keepforge::{harden, settings};
use std::path::PathBuf;

const USAGE: &str = "KeepForge

  KeepForge.exe                    open the program
  KeepForge.exe <vault.kfv>        open that vault
  KeepForge.exe --demo             an invented vault held in memory; nothing is read,
                                   written or sent
  KeepForge.exe --screenshot <png> render the window to a PNG and exit (implies --demo)
        [--view welcome|create|unlock|main|card|wifi|edit|generator|health|breach|
                authenticator|tools|tools-names|tools-encrypt|tools-checksum|tools-qr|
                tools-shred|tools-torrent|settings|trash|about] [--light]
  KeepForge.exe --selftest         create a vault in a temporary folder, exercise it end
                                   to end, check the results, clean up
  KeepForge.exe --selftest-clipboard
                                   a live check of the clipboard code; the text on the
                                   clipboard is saved first and restored afterwards
  KeepForge.exe --hardening-report apply the process protections and print how each went
  KeepForge.exe --selftest-online  the only command that uses the network: one Pwned Passwords
                                   range query for the test password \"password\" and one
                                   XposedOrNot lookup of test@example.com
  KeepForge.exe --idle-lock-secs N with --demo: auto-lock after N idle seconds (testing)
  KeepForge.exe --block-dynamic-code
                                   with --demo: try the optional dynamic-code policy (testing)";

/// A windowed program has no console; borrow the one it was started from so
/// that command-line output is visible.
fn attach_console() {
    use windows::Win32::System::Console::{AttachConsole, ATTACH_PARENT_PROCESS};
    // SAFETY: plain Win32 call; failure only means there is no parent console.
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let has = |flag: &str| args.iter().any(|a| a == flag);
    let value = |flag: &str| {
        args.iter()
            .position(|a| a == flag)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let screenshot = value("--screenshot").map(PathBuf::from);
    let demo = has("--demo") || screenshot.is_some();
    let cli = has("--selftest")
        || has("--selftest-clipboard")
        || has("--selftest-online")
        || has("--hardening-report")
        || has("--help")
        || has("-h");
    let real = !demo && !cli;

    // A start that did not get as far as drawing the window leaves this
    // marker behind; the next start then runs in compatibility mode.
    let data_dir = settings::data_dir();
    let marker = data_dir.join("startup.pending");
    let strict = !(real && marker.exists());

    // First: restrict where libraries are loaded from, before anything else
    // (the window, the graphics driver) loads one.
    let mut steps = harden::early(strict);

    if cli {
        attach_console();
    }
    if has("--help") || has("-h") {
        println!("{USAGE}");
        return Ok(());
    }
    if has("--selftest") {
        match keepforge::selftest::run() {
            Ok(log) => {
                for line in log {
                    println!("{line}");
                }
                println!("SELFTEST PASSED");
                std::process::exit(0);
            }
            Err(e) => {
                println!("{e}");
                println!("SELFTEST FAILED");
                std::process::exit(1);
            }
        }
    }
    if has("--selftest-clipboard") {
        match keepforge::clipboard::live_check() {
            Ok(log) => {
                for line in log {
                    println!("{line}");
                }
                println!("CLIPBOARD CHECK PASSED");
                std::process::exit(0);
            }
            Err(e) => {
                println!("{e}");
                println!("CLIPBOARD CHECK FAILED OR SKIPPED");
                std::process::exit(1);
            }
        }
    }

    if has("--hardening-report") {
        steps.extend(harden::apply(harden::Options {
            block_dynamic_code: has("--block-dynamic-code"),
            exclude_from_error_reporting: false,
            strict,
        }));
        for line in harden::log_lines(&steps) {
            println!("{line}");
        }
        return Ok(());
    }
    if has("--selftest-online") {
        let ok = online_check();
        println!(
            "{}",
            if ok {
                "ONLINE CHECK PASSED"
            } else {
                "ONLINE CHECK FAILED"
            }
        );
        std::process::exit(if ok { 0 } else { 1 });
    }

    let mut user_settings = if demo {
        settings::Settings::default()
    } else {
        settings::Settings::load(&data_dir)
    };
    if !strict && user_settings.block_dynamic_code {
        // The last start failed: do not try the riskiest protection again.
        user_settings.block_dynamic_code = false;
        let _ = user_settings.save(&data_dir);
    }
    steps.extend(harden::apply(harden::Options {
        block_dynamic_code: user_settings.block_dynamic_code
            || (demo && has("--block-dynamic-code")),
        exclude_from_error_reporting: real,
        strict,
    }));
    if real {
        let _ = std::fs::create_dir_all(&data_dir);
        let _ = std::fs::write(&marker, b"");
        let mut log = vec![format!(
            "KeepForge {} started{}",
            env!("CARGO_PKG_VERSION"),
            if strict { "" } else { " in compatibility mode" }
        )];
        log.extend(harden::log_lines(&steps));
        let _ = std::fs::write(data_dir.join("keepforge.log"), log.join("\r\n"));
    }

    // A vault file given on the command line (or by double-clicking a .kfv).
    let vault = args
        .iter()
        .find(|a| !a.starts_with("--") && a.to_lowercase().ends_with(".kfv"))
        .map(PathBuf::from)
        .filter(|p| p.is_file());

    let options = Options {
        demo,
        screenshot,
        view: value("--view").or_else(|| std::env::var("KEEPFORGE_VIEW").ok()),
        light: has("--light"),
        vault,
        idle_lock_secs: demo
            .then(|| value("--idle-lock-secs").and_then(|v| v.parse().ok()))
            .flatten(),
        steps,
        strict,
        start_marker: real.then(|| marker.clone()),
    };
    // Lets the installer and uninstaller see that KeepForge is running.
    let _running = real.then(|| keepforge::sys::app_mutex("KeepForge-app-running"));
    let result = ui::run(options, window_icon());
    if result.is_err() && real {
        keepforge::sys::message_box(
            "KeepForge",
            "KeepForge could not open its window. Start it again: it will then use compatibility mode.",
        );
    }
    result
}

/// The two optional online services, each asked once with neutral test data.
fn online_check() -> bool {
    println!(
        "Asking api.pwnedpasswords.com for hash range 5BAA6 (the test password \"password\")..."
    );
    let (prefix, suffix) = keepforge::hibp::hash_parts("password");
    let pwned = match keepforge::hibp::fetch_range(&prefix) {
        Ok(body) => {
            let lines = body.lines().count();
            let count = keepforge::hibp::parse_range(&body, &suffix);
            println!("  {lines} lines received (padded); \"password\" seen {count} times");
            count > 1_000_000
        }
        Err(e) => {
            println!("  failed: {e}");
            false
        }
    };
    println!("Asking api.xposedornot.com about test@example.com...");
    let email = match keepforge::breach::lookup("test@example.com") {
        Ok(keepforge::breach::EmailResult::Found(list)) => {
            println!(
                "  found in {} breaches; first: {}",
                list.len(),
                list[0].name
            );
            true
        }
        Ok(keepforge::breach::EmailResult::NotFound) => {
            println!("  not found");
            true
        }
        Err(e) => {
            println!("  failed: {e}");
            false
        }
    };
    pwned && email
}

fn window_icon() -> egui::IconData {
    let bytes = include_bytes!(concat!(env!("OUT_DIR"), "/icon-256.png"));
    match image::load_from_memory(bytes) {
        Ok(img) => {
            let rgba = img.into_rgba8();
            let (width, height) = rgba.dimensions();
            egui::IconData {
                rgba: rgba.into_raw(),
                width,
                height,
            }
        }
        Err(_) => egui::IconData::default(),
    }
}
