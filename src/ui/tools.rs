//! The Tools page: strength tester, name / PIN / token generators, file
//! encryption, checksums, QR codes, secure shred and the torrent exposure
//! check. Everything is offline unless a tool says otherwise.

use super::app::{Msg, Shared};
use super::dialogs::{ConfirmAction, Dialog};
use super::main_view::Main;
use super::start::{strength_block, StrengthCache};
use super::theme::{pal, semibold, Icon};
use super::widgets;
use crate::filetools::HashAlgo;
use crate::generator::{self, OsRng, TokenFormat, UsernameOptions};
use crate::kfx;
use crate::secret::{Protected, SecretInput, SecretString};
use crate::torrent::ContentClass;
use crate::util;
use eframe::egui::{self, vec2, Align, Layout, RichText, Ui};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Strength,
    Names,
    Encrypt,
    Checksum,
    Qr,
    Shred,
    Torrent,
}

pub enum ToolMsg {
    SinglePwned(Result<u64, String>),
    TesterPwned(Result<u64, String>),
    Checksum(Result<Option<String>, String>),
    Kfx(Result<String, String>),
    KfxText(SecretString),
    Shred(Result<(), String>),
}

/// A running file job: progress and a way to cancel.
struct Job {
    done: Arc<AtomicU64>,
    total: u64,
    cancel: Arc<AtomicBool>,
}

impl Job {
    fn new(total: u64) -> Job {
        Job {
            done: Arc::new(AtomicU64::new(0)),
            total,
            cancel: Arc::new(AtomicBool::new(false)),
        }
    }

    fn fraction(&self) -> f32 {
        if self.total == 0 {
            0.0
        } else {
            self.done.load(Ordering::Relaxed) as f32 / self.total as f32
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum EncMode {
    Text,
    File,
    Decrypt,
}

pub struct Tools {
    pub tab: Tab,
    // Strength tester
    pub test_pw: SecretInput,
    test_show: bool,
    test_cache: StrengthCache,
    test_pwned: Option<Result<u64, String>>,
    test_busy: bool,
    // Names, PINs, tokens
    uname_opts: UsernameOptions,
    uname: String,
    pin_len: usize,
    pin: SecretInput,
    token_bytes: usize,
    token_format: TokenFormat,
    token: SecretInput,
    // Encrypt
    enc_mode: EncMode,
    enc_text: SecretInput,
    enc_file: Option<PathBuf>,
    enc_pw: SecretInput,
    enc_pw2: SecretInput,
    enc_show: bool,
    enc_job: Option<Job>,
    enc_result: Option<Result<String, String>>,
    dec_text: Option<SecretInput>,
    // Checksum
    sum_file: Option<PathBuf>,
    sum_algo: HashAlgo,
    sum_result: Option<Result<String, String>>,
    sum_expected: String,
    sum_job: Option<Job>,
    // QR
    qr_text: SecretInput,
    // Shred
    shred_file: Option<PathBuf>,
    shred_job: Option<Job>,
    shred_result: Option<Result<(), String>>,
}

impl Default for Tools {
    fn default() -> Self {
        Tools {
            tab: Tab::Strength,
            test_pw: SecretInput::new(),
            test_show: false,
            test_cache: StrengthCache::default(),
            test_pwned: None,
            test_busy: false,
            uname_opts: UsernameOptions::default(),
            uname: String::new(),
            pin_len: 6,
            pin: SecretInput::new(),
            token_bytes: 32,
            token_format: TokenFormat::Hex,
            token: SecretInput::new(),
            enc_mode: EncMode::Text,
            enc_text: SecretInput::with_capacity(64 * 1024),
            enc_file: None,
            enc_pw: SecretInput::new(),
            enc_pw2: SecretInput::new(),
            enc_show: false,
            enc_job: None,
            enc_result: None,
            dec_text: None,
            sum_file: None,
            sum_algo: HashAlgo::Sha256,
            sum_result: None,
            sum_expected: String::new(),
            sum_job: None,
            qr_text: SecretInput::new(),
            shred_file: None,
            shred_job: None,
            shred_result: None,
        }
    }
}

impl Tools {
    /// Leaving the page wipes what was typed into the tools.
    pub fn leave(&mut self, _sh: &mut Shared) {
        self.test_pw.wipe();
        self.test_cache.clear();
        self.test_pwned = None;
        self.pin.wipe();
        self.token.wipe();
        self.enc_text.wipe();
        self.enc_pw.wipe();
        self.enc_pw2.wipe();
        self.dec_text = None;
        self.qr_text.wipe();
    }

    pub fn message(&mut self, sh: &mut Shared, msg: ToolMsg) {
        match msg {
            ToolMsg::TesterPwned(r) => {
                self.test_busy = false;
                self.test_pwned = Some(r);
            }
            ToolMsg::SinglePwned(_) => {}
            ToolMsg::Checksum(r) => {
                self.sum_job = None;
                self.sum_result = match r {
                    Ok(Some(hash)) => Some(Ok(hash)),
                    Ok(None) => None,
                    Err(e) => Some(Err(e)),
                };
            }
            ToolMsg::Kfx(r) => {
                self.enc_job = None;
                self.enc_result = Some(r);
            }
            ToolMsg::KfxText(text) => {
                self.enc_job = None;
                let mut buf = SecretInput::with_capacity(text.len().max(16) + 16);
                buf.set(&text);
                self.dec_text = Some(buf);
                self.enc_result = None;
            }
            ToolMsg::Shred(r) => {
                self.shred_job = None;
                match &r {
                    Ok(()) => {
                        self.shred_file = None;
                        sh.toast("The file was overwritten and deleted.", false);
                    }
                    Err(e) => sh.toast(e.clone(), true),
                }
                self.shred_result = Some(r);
            }
        }
    }

    /// For screenshots: a typed example in the strength tester.
    pub fn demo_fill(&mut self) {
        self.test_pw.set("Summer2024!");
        self.test_show = true;
        self.uname = "CalmOtter42".into();
    }
}

/// Where decrypted content goes: a file being written, or memory (text).
enum Sink {
    File(std::fs::File),
    Memory(zeroize::Zeroizing<Vec<u8>>),
}

impl std::io::Write for Sink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Sink::File(f) => f.write(buf),
            Sink::Memory(m) => {
                if m.len() + buf.len() > m.capacity() {
                    return Err(std::io::Error::other("the text is too long to show"));
                }
                m.extend_from_slice(buf);
                Ok(buf.len())
            }
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Sink::File(f) => f.flush(),
            Sink::Memory(_) => Ok(()),
        }
    }
}

/// A file name in `dir` that does not exist yet: `name`, `name (2)`, ...
fn free_name(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    let (stem, ext) = match name.rsplit_once('.') {
        Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
        _ => (name.to_string(), String::new()),
    };
    (2..1000)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .unwrap_or(first)
}

fn pick_row(ui: &mut Ui, file: &mut Option<PathBuf>, button: &str, title: &str) -> bool {
    let p = pal(ui);
    let mut changed = false;
    ui.horizontal(|ui| {
        if widgets::ghost_button(ui, &Icon::OPEN_FILE.with(button)).clicked() {
            if let Some(path) = rfd::FileDialog::new().set_title(title).pick_file() {
                *file = Some(path);
                changed = true;
            }
        }
        match file {
            Some(path) => {
                let size = std::fs::metadata(&*path).map(|m| m.len()).unwrap_or(0);
                ui.add(
                    egui::Label::new(format!(
                        "{}  ({})",
                        path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default(),
                        util::human_size(size)
                    ))
                    .truncate(),
                );
            }
            None => {
                ui.label(RichText::new("or drop a file on this window").color(p.faint));
            }
        }
    });
    // A file dropped onto the window.
    let dropped = ui
        .ctx()
        .input(|i| i.raw.dropped_files.first().and_then(|f| f.path.clone()));
    if let Some(path) = dropped {
        if path.is_file() {
            *file = Some(path);
            changed = true;
        }
    }
    changed
}

fn job_row(ui: &mut Ui, job: &Job, label: &str) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        ui.add(egui::Spinner::new().size(16.0).color(p.accent));
        ui.label(label);
        if widgets::ghost_button(ui, "Cancel").clicked() {
            job.cancel.store(true, Ordering::Relaxed);
        }
    });
    let w = ui.available_width();
    widgets::progress_bar(ui, job.fraction(), w, p.accent);
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(120));
}

impl Main {
    pub(super) fn tools_ui(&mut self, ui: &mut Ui, sh: &mut Shared) {
        super::pages::page_header(
            ui,
            "Tools",
            "Small helpers that work on this PC. Only the last one goes online.",
            |_| {},
        );
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
            let tabs: [(Tab, Icon, &str); 7] = [
                (Tab::Strength, Icon::HEALTH, "Strength tester"),
                (Tab::Names, Icon::SHUFFLE, "User names, PINs, tokens"),
                (Tab::Encrypt, Icon::LOCK, "Encrypt text or file"),
                (Tab::Checksum, Icon::CALCULATOR, "File checksum"),
                (Tab::Qr, Icon::QR, "QR code"),
                (Tab::Shred, Icon::ERASE, "Secure shred"),
                (Tab::Torrent, Icon::GLOBE, "Torrent exposure check"),
            ];
            for (tab, icon, label) in tabs {
                if widgets::chip(ui, &icon.with(label), None, self.tools.tab == tab).clicked()
                    && self.tools.tab != tab
                {
                    self.tools.leave(sh);
                    self.tools.tab = tab;
                }
            }
        });
        ui.add_space(6.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_max_width((ui.available_width() - 12.0).min(860.0));
                ui.spacing_mut().item_spacing.y = 12.0;
                match self.tools.tab {
                    Tab::Strength => self.tool_strength(ui, sh),
                    Tab::Names => self.tool_names(ui, sh),
                    Tab::Encrypt => self.tool_encrypt(ui, sh),
                    Tab::Checksum => self.tool_checksum(ui, sh),
                    Tab::Qr => self.tool_qr(ui, sh),
                    Tab::Shred => self.tool_shred(ui, sh),
                    Tab::Torrent => self.tool_torrent(ui, sh),
                }
                ui.add_space(8.0);
            });
    }

    fn tool_strength(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let t = &mut self.tools;
        let mut check = false;
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "Password strength tester");
            widgets::note(ui, "Type or paste any password. Nothing is saved, and the box is wiped when you leave this page.");
            let w = ui.available_width();
            ui.horizontal(|ui| {
                let before = t.test_pw.as_str().len();
                widgets::secret_input(
                    ui,
                    &mut t.test_pw,
                    t.test_show,
                    "A password to test",
                    w - 44.0,
                );
                if t.test_pw.as_str().len() != before {
                    t.test_pwned = None;
                }
                let icon = if t.test_show { Icon::HIDE } else { Icon::VIEW };
                if widgets::icon_button(ui, icon, "Show or hide").clicked() {
                    t.test_show = !t.test_show;
                }
            });
            let empty = t.test_pw.is_empty();
            let s = t.test_cache.get(t.test_pw.as_str()).clone();
            strength_block(ui, &s, empty, w);
            if !empty {
                ui.add_space(4.0);
                egui::Grid::new("crack")
                    .num_columns(2)
                    .spacing(vec2(18.0, 5.0))
                    .show(ui, |ui| {
                        let rows = [
                            ("Guessing on a website that limits attempts", &s.online),
                            (
                                "A stolen database with slow, careful hashing",
                                &s.offline_slow,
                            ),
                            (
                                "A stolen database with fast, careless hashing",
                                &s.offline_fast,
                            ),
                        ];
                        for (label, time) in rows {
                            ui.label(RichText::new(label).color(p.muted));
                            ui.label(RichText::new(time).font(semibold(14.0)));
                            ui.end_row();
                        }
                        ui.label(RichText::new("Estimated strength").color(p.muted));
                        ui.label(RichText::new(s.bits_text()).font(semibold(14.0)));
                        ui.end_row();
                    });
                if !s.patterns.is_empty() {
                    ui.add_space(2.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("Found:").color(p.muted));
                        for pattern in &s.patterns {
                            widgets::badge(ui, pattern, p.warn);
                        }
                    });
                }
                let advice: &str = match s.score {
                    0 | 1 => "Do not use this. Generate a random password, or use four or more random words.",
                    2 => "Too predictable for anything that matters. Make it longer and avoid words, dates and patterns.",
                    3 => "Reasonable. A generated password or a longer passphrase would be better.",
                    _ => "Strong, as long as you have not used it anywhere else.",
                };
                widgets::banner(ui, Icon::INFO, widgets::strength_color(&p, s.score), advice);
                ui.horizontal(|ui| {
                    if widgets::ghost_button_enabled(
                        ui,
                        &Icon::GLOBE.with("Also check known breaches (online)"),
                        !t.test_busy,
                    )
                    .clicked()
                    {
                        check = true;
                    }
                    match &t.test_pwned {
                        Some(Ok(0)) => {
                            ui.colored_label(p.accent, "Not found in known breaches.");
                        }
                        Some(Ok(n)) => {
                            ui.colored_label(
                                p.danger,
                                format!("Seen {} times in breaches.", util::thousands(*n)),
                            );
                        }
                        Some(Err(e)) => {
                            ui.colored_label(p.warn, e);
                        }
                        None => {}
                    }
                });
                widgets::note(ui, "The online check sends only the first 5 characters of the password's SHA-1 hash.");
            }
        });
        if check {
            if sh.demo {
                self.tools.test_pwned = Some(Ok(0));
            } else {
                let password = self.tools.test_pw.to_secret();
                self.tools.test_busy = true;
                let ranges = self.ranges.clone();
                sh.spawn(&ctx, move || {
                    let result = match ranges.lock() {
                        Ok(mut cache) => cache.check(&password),
                        Err(_) => Err("Internal error.".to_string()),
                    };
                    Msg::Tool(ToolMsg::TesterPwned(result))
                });
            }
        }
    }

    fn tool_names(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let t = &mut self.tools;
        if t.uname.is_empty() {
            t.uname = generator::username(&t.uname_opts, &mut OsRng);
        }
        if t.pin.is_empty() {
            t.pin.set(&generator::pin(t.pin_len, &mut OsRng));
        }
        if t.token.is_empty() {
            t.token
                .set(&generator::token(t.token_bytes, t.token_format, &mut OsRng));
        }
        let mono = |ui: &mut Ui, text: &str| {
            egui::Frame::new()
                .fill(p.bg)
                .stroke(egui::Stroke::new(1.0_f32, p.border))
                .corner_radius(10)
                .inner_margin(12)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.add(
                        egui::Label::new(RichText::new(text).monospace().size(17.0).color(p.text))
                            .wrap(),
                    );
                });
        };
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "User name");
            widgets::note(ui, "A readable name that is not connected to your real one. Use a different one per site if you like.");
            mono(ui, &t.uname);
            let before = t.uname_opts.clone();
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("Words").color(p.muted));
                ui.add(egui::Slider::new(&mut t.uname_opts.words, 1..=3));
                widgets::checkbox(ui, &mut t.uname_opts.capitalise, "Capitals");
                widgets::checkbox(ui, &mut t.uname_opts.add_number, "Number");
                let mut dash = t.uname_opts.separator == "-";
                if widgets::checkbox(ui, &mut dash, "Dashes").changed() {
                    t.uname_opts.separator = if dash { "-".into() } else { String::new() };
                }
            });
            let mut again = t.uname_opts != before;
            let mut copy = false;
            ui.horizontal(|ui| {
                copy = widgets::primary_button(ui, &Icon::COPY.with("Copy"), true).clicked();
                again |= widgets::ghost_button(ui, &Icon::REFRESH.with("Another")).clicked();
            });
            if again {
                t.uname = generator::username(&t.uname_opts, &mut OsRng);
            }
            if copy {
                sh.copy_plain(&t.uname, "User name");
            }
        });
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "PIN");
            widgets::note(
                ui,
                "Random digits. Obvious PINs (1234, 0000, repeats, years) are never produced.",
            );
            mono(ui, t.pin.as_str());
            let before = t.pin_len;
            ui.horizontal(|ui| {
                ui.label(RichText::new("Digits").color(p.muted));
                ui.add(egui::Slider::new(
                    &mut t.pin_len,
                    generator::PIN_MIN..=generator::PIN_MAX,
                ));
                ui.label(
                    RichText::new(format!(
                        "up to {:.0} bits",
                        generator::pin_entropy_bits(t.pin_len)
                    ))
                    .size(12.5)
                    .color(p.faint),
                );
            });
            let mut again = before != t.pin_len;
            let mut copy = false;
            ui.horizontal(|ui| {
                copy = widgets::primary_button(ui, &Icon::COPY.with("Copy"), true).clicked();
                again |= widgets::ghost_button(ui, &Icon::REFRESH.with("Another")).clicked();
            });
            if again {
                t.pin.set(&generator::pin(t.pin_len, &mut OsRng));
            }
            if copy {
                sh.copy_secret(t.pin.as_str(), "PIN");
            }
        });
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "Random token");
            widgets::note(
                ui,
                "Random bytes for API keys and secrets, as hex or base64.",
            );
            mono(ui, t.token.as_str());
            let before = (t.token_bytes, t.token_format);
            ui.horizontal(|ui| {
                ui.label(RichText::new("Bytes").color(p.muted));
                ui.add(egui::Slider::new(&mut t.token_bytes, 16..=64));
                if let Some(i) = widgets::segmented(
                    ui,
                    &["Hex", "Base64"],
                    usize::from(t.token_format == TokenFormat::Base64),
                ) {
                    t.token_format = if i == 1 {
                        TokenFormat::Base64
                    } else {
                        TokenFormat::Hex
                    };
                }
                ui.label(
                    RichText::new(format!("{} bits", t.token_bytes * 8))
                        .size(12.5)
                        .color(p.faint),
                );
            });
            let mut again = before != (t.token_bytes, t.token_format);
            let mut copy = false;
            ui.horizontal(|ui| {
                copy = widgets::primary_button(ui, &Icon::COPY.with("Copy"), true).clicked();
                again |= widgets::ghost_button(ui, &Icon::REFRESH.with("Another")).clicked();
            });
            if again {
                t.token
                    .set(&generator::token(t.token_bytes, t.token_format, &mut OsRng));
            }
            if copy {
                sh.copy_secret(t.token.as_str(), "Token");
            }
        });
    }

    fn tool_encrypt(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let kdf = sh
            .calibration
            .map(|c| c.params)
            .unwrap_or(crate::vaultfile::KdfParams::DEFAULT);
        let t = &mut self.tools;
        let mut start = false;
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "Encrypt text or a file");
            widgets::note(ui, "Makes a self-contained .kfx file that only the password opens. Send the file one way and tell the other person the password another way (in person, or by phone). They need KeepForge to open it.");
            let modes = [EncMode::Text, EncMode::File, EncMode::Decrypt];
            let current = modes.iter().position(|m| *m == t.enc_mode).unwrap_or(0);
            if let Some(i) = widgets::segmented(
                ui,
                &["Encrypt text", "Encrypt a file", "Decrypt a .kfx file"],
                current,
            ) {
                t.enc_mode = modes[i];
                t.enc_file = None;
                t.enc_result = None;
                t.dec_text = None;
            }
            let w = ui.available_width();
            match t.enc_mode {
                EncMode::Text => {
                    widgets::text_area(ui, &mut t.enc_text, "The text to protect", w, 5);
                }
                EncMode::File => {
                    pick_row(
                        ui,
                        &mut t.enc_file,
                        "Choose a file",
                        "Choose the file to encrypt",
                    );
                }
                EncMode::Decrypt => {
                    pick_row(
                        ui,
                        &mut t.enc_file,
                        "Choose a .kfx file",
                        "Choose the .kfx file to decrypt",
                    );
                }
            }
            widgets::caption(ui, "Password");
            ui.horizontal(|ui| {
                widgets::secret_input(ui, &mut t.enc_pw, t.enc_show, "", (w - 52.0) / 2.0);
                if t.enc_mode != EncMode::Decrypt {
                    widgets::secret_input(
                        ui,
                        &mut t.enc_pw2,
                        t.enc_show,
                        "Again",
                        (w - 52.0) / 2.0,
                    );
                }
                let icon = if t.enc_show { Icon::HIDE } else { Icon::VIEW };
                if widgets::icon_button(ui, icon, "Show or hide").clicked() {
                    t.enc_show = !t.enc_show;
                }
            });
            let encrypting = t.enc_mode != EncMode::Decrypt;
            let same = !encrypting || t.enc_pw.as_str() == t.enc_pw2.as_str();
            let long_enough = !encrypting || t.enc_pw.as_str().chars().count() >= 8;
            if !t.enc_pw.is_empty() && !same {
                ui.colored_label(p.danger, "The two passwords are different.");
            } else if !t.enc_pw.is_empty() && !long_enough {
                ui.colored_label(
                    p.danger,
                    "Use at least 8 characters. The password is all that protects the file.",
                );
            }
            let has_input = match t.enc_mode {
                EncMode::Text => !t.enc_text.is_empty(),
                _ => t.enc_file.is_some(),
            };
            let ready =
                has_input && !t.enc_pw.is_empty() && same && long_enough && t.enc_job.is_none();
            match &t.enc_job {
                Some(job) => job_row(
                    ui,
                    job,
                    if encrypting {
                        "Encrypting…"
                    } else {
                        "Decrypting…"
                    },
                ),
                None => {
                    let label = if encrypting {
                        "Encrypt and save…"
                    } else {
                        "Decrypt"
                    };
                    if widgets::primary_button(ui, label, ready).clicked() {
                        start = true;
                    }
                }
            }
            match &t.enc_result {
                Some(Ok(message)) => widgets::banner(ui, Icon::DONE, p.accent, message),
                Some(Err(e)) => widgets::banner(ui, Icon::ERROR, p.danger, e),
                None => {}
            }
            if let Some(text) = &mut t.dec_text {
                widgets::caption(ui, "Decrypted text");
                widgets::text_area(ui, text, "", w, 5);
                let mut copy = false;
                let mut clear = false;
                ui.horizontal(|ui| {
                    copy = widgets::ghost_button(ui, &Icon::COPY.with("Copy")).clicked();
                    clear = widgets::ghost_button(ui, "Wipe").clicked();
                });
                if copy {
                    sh.copy_secret(text.as_str(), "Text");
                }
                if clear {
                    t.dec_text = None;
                }
            }
        });
        if !start {
            return;
        }
        if sh.demo {
            sh.toast("File tools are switched off in the demo.", false);
            return;
        }
        let t = &mut self.tools;
        let password = t.enc_pw.to_secret();
        t.enc_pw.wipe();
        t.enc_pw2.wipe();
        t.enc_result = None;
        t.dec_text = None;
        let tx = sh.tx.clone();
        let send = move |m: ToolMsg| {
            let _ = tx.send(Msg::Tool(m));
            ctx.request_repaint();
        };
        match t.enc_mode {
            EncMode::Text | EncMode::File => {
                let is_text = t.enc_mode == EncMode::Text;
                let source = t.enc_file.clone();
                let default_name = match &source {
                    Some(path) if !is_text => format!(
                        "{}.kfx",
                        path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default()
                    ),
                    _ => "secret message.kfx".to_string(),
                };
                let Some(mut out_path) = rfd::FileDialog::new()
                    .set_title("Save the encrypted file")
                    .set_file_name(default_name)
                    .add_filter("KeepForge encrypted file", &["kfx"])
                    .save_file()
                else {
                    return;
                };
                if out_path.extension().is_none() {
                    out_path.set_extension("kfx");
                }
                let text = is_text.then(|| t.enc_text.to_secret());
                if is_text {
                    t.enc_text.wipe();
                }
                let total = match &source {
                    Some(path) if !is_text => std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
                    _ => text.as_ref().map(|s| s.len() as u64).unwrap_or(0),
                };
                let job = Job::new(total);
                let (done, cancel) = (job.done.clone(), job.cancel.clone());
                t.enc_job = Some(job);
                std::thread::spawn(move || {
                    let result = (|| -> Result<String, String> {
                        let out = std::fs::File::create(&out_path)
                            .map_err(|e| format!("Could not create the file: {e}"))?;
                        let out = std::io::BufWriter::new(out);
                        let outcome = match (&text, &source) {
                            (Some(text), _) => kfx::encrypt(
                                text.as_bytes(),
                                out,
                                &password,
                                kdf,
                                &kfx::Meta {
                                    content: kfx::Content::Text,
                                    name: String::new(),
                                },
                                &cancel,
                                |n| done.store(n, Ordering::Relaxed),
                            ),
                            (None, Some(path)) => {
                                let input = std::fs::File::open(path)
                                    .map_err(|e| format!("Could not open the file: {e}"))?;
                                let name = path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_default();
                                kfx::encrypt(
                                    std::io::BufReader::new(input),
                                    out,
                                    &password,
                                    kdf,
                                    &kfx::Meta {
                                        content: kfx::Content::File,
                                        name,
                                    },
                                    &cancel,
                                    |n| done.store(n, Ordering::Relaxed),
                                )
                            }
                            (None, None) => return Err("Nothing to encrypt.".into()),
                        };
                        match outcome {
                            Ok(()) => Ok(format!(
                                "Saved as {}. The original is unchanged.",
                                out_path
                                    .file_name()
                                    .map(|n| n.to_string_lossy().to_string())
                                    .unwrap_or_default()
                            )),
                            Err(e) => {
                                let _ = std::fs::remove_file(&out_path);
                                Err(e.to_string())
                            }
                        }
                    })();
                    send(ToolMsg::Kfx(result));
                });
            }
            EncMode::Decrypt => {
                let Some(source) = t.enc_file.clone() else {
                    return;
                };
                let total = std::fs::metadata(&source).map(|m| m.len()).unwrap_or(0);
                let job = Job::new(total);
                let (done, cancel) = (job.done.clone(), job.cancel.clone());
                t.enc_job = Some(job);
                std::thread::spawn(move || {
                    let dir = source.parent().map(Path::to_path_buf).unwrap_or_default();
                    let partial = dir.join(format!(
                        "{}.partial",
                        util::hex(&crate::secret::random_array::<6>())
                    ));
                    let result = (|| -> Result<ToolMsg, String> {
                        let input = std::fs::File::open(&source)
                            .map_err(|e| format!("Could not open the file: {e}"))?;
                        let partial_for_open = partial.clone();
                        let (meta, sink) = kfx::decrypt(
                            std::io::BufReader::new(input),
                            &password,
                            move |meta| match meta.content {
                                kfx::Content::Text => Ok(Sink::Memory(zeroize::Zeroizing::new(
                                    Vec::with_capacity(1024 * 1024),
                                ))),
                                kfx::Content::File => {
                                    std::fs::File::create(&partial_for_open).map(Sink::File)
                                }
                            },
                            &cancel,
                            |n| done.store(n, Ordering::Relaxed),
                        )
                        .map_err(|e| e.to_string())?;
                        match sink {
                            Sink::Memory(bytes) => {
                                let text = String::from_utf8_lossy(&bytes).into_owned();
                                Ok(ToolMsg::KfxText(zeroize::Zeroizing::new(text)))
                            }
                            Sink::File(file) => {
                                file.sync_all().map_err(|e| e.to_string())?;
                                drop(file);
                                let target = free_name(&dir, &meta.name);
                                std::fs::rename(&partial, &target).map_err(|e| {
                                    format!("Could not save the decrypted file: {e}")
                                })?;
                                Ok(ToolMsg::Kfx(Ok(format!(
                                    "Decrypted and saved as {} next to the .kfx file.",
                                    target
                                        .file_name()
                                        .map(|n| n.to_string_lossy().to_string())
                                        .unwrap_or_default()
                                ))))
                            }
                        }
                    })();
                    match result {
                        Ok(msg) => send(msg),
                        Err(e) => {
                            // Never leave unauthenticated plaintext behind.
                            let _ = std::fs::remove_file(&partial);
                            send(ToolMsg::Kfx(Err(e)));
                        }
                    }
                });
            }
        }
    }

    fn tool_checksum(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let t = &mut self.tools;
        let mut start = false;
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "File checksum");
            widgets::note(ui, "Check that a download is exactly the file its publisher released: compute its checksum and compare it with the one on their website.");
            if pick_row(
                ui,
                &mut t.sum_file,
                "Choose a file",
                "Choose the file to check",
            ) {
                t.sum_result = None;
                start = true;
            }
            let current = HashAlgo::ALL
                .iter()
                .position(|a| *a == t.sum_algo)
                .unwrap_or(0);
            let labels: Vec<&str> = HashAlgo::ALL.iter().map(|a| a.label()).collect();
            if let Some(i) = widgets::segmented(ui, &labels, current) {
                t.sum_algo = HashAlgo::ALL[i];
                t.sum_result = None;
                start = t.sum_file.is_some();
            }
            if t.sum_algo == HashAlgo::Sha1 {
                widgets::note(ui, "SHA-1 is only good for spotting accidental damage; it does not protect against deliberate tampering.");
            }
            if let Some(job) = &t.sum_job {
                job_row(ui, job, "Reading the file…");
            }
            let w = ui.available_width();
            match &t.sum_result {
                Some(Ok(hash)) => {
                    egui::Frame::new()
                        .fill(p.bg)
                        .stroke(egui::Stroke::new(1.0_f32, p.border))
                        .corner_radius(10)
                        .inner_margin(12)
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            ui.add(
                                egui::Label::new(RichText::new(hash).monospace().size(14.0)).wrap(),
                            );
                        });
                    let mut copy = false;
                    ui.horizontal(|ui| {
                        copy = widgets::ghost_button(ui, &Icon::COPY.with("Copy")).clicked();
                    });
                    if copy {
                        sh.copy_plain(hash, "Checksum");
                    }
                    widgets::caption(ui, "Compare with the expected checksum");
                    widgets::text_input(
                        ui,
                        &mut t.sum_expected,
                        "Paste the checksum from the publisher's site",
                        w,
                    );
                    match crate::filetools::hashes_match(hash, &t.sum_expected) {
                        Some(true) => widgets::banner(ui, Icon::DONE, p.accent, "They match. The file is exactly the one this checksum was made from."),
                        Some(false) => widgets::banner(ui, Icon::ERROR, p.danger, "They do NOT match. The file is damaged, incomplete or not the original. (Also check that you picked the same algorithm.)"),
                        None => {}
                    }
                }
                Some(Err(e)) => widgets::banner(ui, Icon::ERROR, p.danger, e),
                None => {}
            }
        });
        if start && self.tools.sum_job.is_none() {
            let Some(path) = self.tools.sum_file.clone() else {
                return;
            };
            let algo = self.tools.sum_algo;
            let job = Job::new(std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0));
            let (done, cancel) = (job.done.clone(), job.cancel.clone());
            self.tools.sum_job = Some(job);
            sh.spawn(&ctx, move || {
                let result = std::fs::File::open(&path)
                    .and_then(|f| {
                        crate::filetools::hash_reader(f, algo, &cancel, |n| {
                            done.store(n, Ordering::Relaxed)
                        })
                    })
                    .map_err(|e| format!("Could not read the file: {e}"));
                Msg::Tool(ToolMsg::Checksum(result))
            });
        }
    }

    fn tool_qr(&mut self, ui: &mut Ui, _sh: &mut Shared) {
        let p = pal(ui);
        let mut show = false;
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "QR code");
            widgets::note(ui, "Turn any text into a QR code to move it to a phone without typing. For a Wi-Fi network or a one-time code, open the item and choose \"Show QR code\" from its ⋯ menu.");
            let w = ui.available_width();
            widgets::secret_input(ui, &mut self.tools.qr_text, true, "Text for the code", w);
            if widgets::primary_button(
                ui,
                &Icon::QR.with("Make QR code"),
                !self.tools.qr_text.is_empty(),
            )
            .clicked()
            {
                show = true;
            }
            ui.label(
                RichText::new(
                    "The code stays hidden until you click it and hides again after 30 seconds.",
                )
                .size(12.5)
                .color(p.faint),
            );
        });
        if show {
            let sealed = Protected::seal_str(&self.v.session, self.tools.qr_text.as_str());
            self.tools.qr_text.wipe();
            self.dialog = Some(Dialog::qr(
                "QR code",
                "Scan it with a phone camera.",
                sealed,
            ));
        }
    }

    /// Overwrites and deletes a file on a worker thread (after the user
    /// confirmed it in a dialog).
    pub(super) fn start_shred(&mut self, ctx: &egui::Context, sh: &mut Shared, path: PathBuf) {
        if sh.demo || self.tools.shred_job.is_some() {
            return;
        }
        let job = Job::new(std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0));
        let (done, cancel) = (job.done.clone(), job.cancel.clone());
        self.tools.shred_job = Some(job);
        self.tools.shred_result = None;
        sh.spawn(ctx, move || {
            let result =
                crate::filetools::shred(&path, &cancel, |n, _| done.store(n, Ordering::Relaxed))
                    .map_err(|e| e.to_string());
            Msg::Tool(ToolMsg::Shred(result))
        });
    }

    fn tool_shred(&mut self, ui: &mut Ui, _sh: &mut Shared) {
        let p = pal(ui);
        let mut go = false;
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "Secure shred");
            widgets::note(ui, "Overwrites one file with random data, renames it and deletes it, so it cannot be brought back from the Recycle Bin or with a simple undelete tool. Useful for a plaintext export after importing it.");
            widgets::banner(
                ui,
                Icon::WARNING,
                p.warn,
                "Be realistic about what this can do. On SSDs, and in cloud-synced, backed-up or copy-on-write folders, old copies of the data can survive where no program can reach them. Overwriting cannot guarantee the data is gone; full-disk encryption (BitLocker) is the dependable protection.",
            );
            if pick_row(
                ui,
                &mut self.tools.shred_file,
                "Choose a file",
                "Choose the file to shred",
            ) {
                self.tools.shred_result = None;
            }
            if let Some(job) = &self.tools.shred_job {
                job_row(ui, job, "Overwriting…");
            } else if let Some(path) = &self.tools.shred_file {
                match crate::filetools::shred_check(path) {
                    Ok(_) => {
                        if widgets::danger_button(ui, "Shred this file…", true).clicked() {
                            go = true;
                        }
                    }
                    Err(e) => widgets::banner(ui, Icon::ERROR, p.danger, &e.to_string()),
                }
            }
            match &self.tools.shred_result {
                Some(Ok(())) => widgets::banner(
                    ui,
                    Icon::DONE,
                    p.accent,
                    "The file was overwritten and deleted.",
                ),
                Some(Err(e)) => widgets::banner(ui, Icon::ERROR, p.danger, e),
                None => {}
            }
        });
        if go {
            if let Some(path) = self.tools.shred_file.clone() {
                // Confirmed in a dialog; the dialog's action runs the shred.
                self.dialog = Some(Dialog::confirm(
                    "Shred this file?",
                    &format!(
                        "\"{}\" will be overwritten and deleted. This cannot be undone.",
                        path.to_string_lossy()
                    ),
                    "Shred",
                    ConfirmAction::ShredFile(path),
                ));
            }
        }
    }

    fn tool_torrent(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let has_key = sh.demo
            || self
                .v
                .vault
                .service_key(crate::torrent::SERVICE_KEY)
                .is_some();
        let mut lookup = false;
        let mut save_key = false;
        let mut remove_key = false;
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "Torrent exposure check");
            widgets::note(ui, "See what BitTorrent activity is publicly associated with an IP address. Meant for checking your own connection: your home address, or the exit address of your VPN.");
            widgets::note(ui, "The data is collected from the public torrent network (DHT and peer exchange) by iknowwhatyoudownload.com. It is unconfirmed, and shared or changing addresses and VPNs mean results may belong to other people.");
            if !has_key || self.pages.peer_setup {
                ui.add_space(2.0);
                widgets::section(ui, "Set up (once)");
                ui.label("1. Ask the service for a free demo key on its API page (they send it by email).");
                if widgets::ghost_button(ui, &Icon::GLOBE.with("Open the API page in the browser"))
                    .clicked()
                {
                    if let Err(e) = crate::sys::open_url(crate::torrent::API_PAGE) {
                        sh.toast(e, true);
                    }
                }
                ui.label("2. Paste the key here. It is stored only inside this encrypted vault.");
                let w = ui.available_width();
                widgets::secret_input(ui, &mut self.pages.peer_key, false, "API key", w.min(460.0));
                widgets::caption(
                    ui,
                    "API host (leave as it is unless the service gave you another one)",
                );
                if self.pages.peer_host.is_empty() {
                    self.pages.peer_host = crate::torrent::DEFAULT_HOST.to_string();
                }
                widgets::text_input(
                    ui,
                    &mut self.pages.peer_host,
                    crate::torrent::DEFAULT_HOST,
                    w.min(460.0),
                );
                let host_ok = crate::torrent::valid_host(&self.pages.peer_host);
                if !host_ok {
                    ui.colored_label(p.danger, "That is not a valid host name.");
                }
                ui.horizontal(|ui| {
                    if widgets::primary_button(
                        ui,
                        "Save key",
                        !self.pages.peer_key.is_empty() && host_ok,
                    )
                    .clicked()
                    {
                        save_key = true;
                    }
                    if has_key && widgets::ghost_button(ui, "Remove the stored key").clicked() {
                        remove_key = true;
                    }
                    if has_key && widgets::ghost_button(ui, "Cancel").clicked() {
                        self.pages.peer_setup = false;
                    }
                });
            } else {
                ui.horizontal(|ui| {
                    let resp = widgets::text_input(
                        ui,
                        &mut self.pages.ip_input,
                        "Public IP address, for example 93.184.216.34",
                        380.0,
                    );
                    let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (widgets::primary_button(ui, "Check", !self.pages.peer_busy).clicked()
                        || enter)
                        && !self.pages.peer_busy
                    {
                        lookup = true;
                    }
                    if self.pages.peer_busy {
                        ui.add(egui::Spinner::new().size(16.0).color(p.accent));
                    }
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if !sh.demo && widgets::link(ui, "Change API key").clicked() {
                            self.pages.peer_setup = true;
                        }
                    });
                });
                widgets::note(ui, "Not sure what your public address is? Search the web for \"what is my IP\". KeepForge does not look it up for you, so that no further service is contacted. Private addresses (192.168…, 10…) are refused.");
            }
        });
        match &self.pages.peer {
            Some(Err(e)) => widgets::banner(ui, Icon::ERROR, p.warn, e),
            Some(Ok(report)) => {
                widgets::card(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 6.0;
                    ui.label(RichText::new(&report.ip).font(semibold(18.0)));
                    let place = [report.city.as_str(), report.country.as_str()]
                        .iter()
                        .filter(|s| !s.is_empty())
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", ");
                    let mut facts = Vec::new();
                    if !report.isp.is_empty() {
                        facts.push(format!("Provider: {}", report.isp));
                    }
                    if !place.is_empty() {
                        facts.push(place);
                    }
                    if !facts.is_empty() {
                        ui.label(RichText::new(facts.join(" · ")).color(p.muted));
                    }
                    ui.label(
                        RichText::new(match report.items.len() {
                            0 => "Nothing seen for this address in the last 14 days.".to_string(),
                            1 => "1 item seen in the last 14 days.".to_string(),
                            n => format!("{n} items seen in the last 14 days."),
                        })
                        .font(semibold(15.0)),
                    );
                    let adult = report
                        .items
                        .iter()
                        .filter(|i| i.class == ContentClass::Adult)
                        .count();
                    for item in &report.items {
                        match item.class {
                            ContentClass::Flagged => {
                                widgets::divider(ui);
                                ui.label(
                                    RichText::new("Flagged content (details hidden)")
                                        .color(p.danger),
                                );
                            }
                            ContentClass::Adult if !self.pages.show_adult => {}
                            _ => {
                                widgets::divider(ui);
                                ui.add(
                                    egui::Label::new(RichText::new(&item.name).size(14.5)).wrap(),
                                );
                                let mut facts = Vec::new();
                                if !item.category.is_empty() {
                                    facts.push(item.category.clone());
                                }
                                if !item.first_seen.is_empty() {
                                    facts.push(format!("first seen {}", item.first_seen));
                                }
                                if !item.last_seen.is_empty() {
                                    facts.push(format!("last seen {}", item.last_seen));
                                }
                                if let Some(size) = item.size {
                                    facts.push(util::human_size(size));
                                }
                                ui.label(
                                    RichText::new(facts.join(" · ")).size(12.5).color(p.muted),
                                );
                            }
                        }
                    }
                    if adult > 0 {
                        widgets::divider(ui);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("{adult} adult item(s)")).color(p.muted),
                            );
                            let label = if self.pages.show_adult {
                                "Hide"
                            } else {
                                "Show"
                            };
                            if widgets::link(ui, label).clicked() {
                                self.pages.show_adult = !self.pages.show_adult;
                            }
                        });
                    }
                });
            }
            None => {}
        }
        ui.label(
            RichText::new("Data: iknowwhatyoudownload.com Peer API. Results are kept in memory until you lock the vault.")
                .size(12.0)
                .color(p.faint),
        );
        if save_key {
            let session = self.v.session.clone();
            let key = Protected::seal_str(&session, self.pages.peer_key.as_str().trim());
            self.pages.peer_key.wipe();
            self.v
                .vault
                .set_service_key(crate::torrent::SERVICE_KEY, key);
            let host = self.pages.peer_host.trim().to_string();
            let host_value = if host == crate::torrent::DEFAULT_HOST {
                Protected::default()
            } else {
                Protected::seal_str(&session, &host)
            };
            self.v
                .vault
                .set_service_key(crate::torrent::SERVICE_HOST, host_value);
            self.pages.peer_setup = false;
            sh.toast("The key is saved inside the vault.", false);
            self.changed(&ctx, sh);
        }
        if remove_key {
            self.v
                .vault
                .set_service_key(crate::torrent::SERVICE_KEY, Protected::default());
            self.v
                .vault
                .set_service_key(crate::torrent::SERVICE_HOST, Protected::default());
            self.pages.peer_setup = false;
            self.pages.peer = None;
            sh.toast("The key was removed from the vault.", false);
            self.changed(&ctx, sh);
        }
        if lookup {
            self.request_peer_lookup(&ctx, sh);
        }
    }
}
