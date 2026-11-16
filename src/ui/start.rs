//! The screens before a vault is open: welcome, create, unlock.

use super::app::{Go, Msg, Opened, Shared};
use super::theme::{pal, pal_ctx, regular, semibold, Icon};
use super::widgets;
use crate::secret::SecretInput;
use crate::settings::Settings;
use crate::store::{OpenError, OpenVault};
use crate::strength::{self, Strength};
use crate::vaultfile::{self, Credentials, VaultError};
use eframe::egui::{
    self, vec2, Align, Color32, CornerRadius, Frame, Key, Layout, Margin, Rect, RichText, Sense,
    Stroke, TextureHandle, Ui,
};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::Instant;

pub(super) fn paint_logo(ui: &mut Ui, logo: Option<&TextureHandle>, size: f32) {
    let (rect, _) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    if let Some(logo) = logo {
        ui.painter().image(
            logo.id(),
            rect,
            Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
            Color32::WHITE,
        );
    }
}

fn page(ctx: &egui::Context, add: impl FnOnce(&mut Ui)) {
    let p = pal_ctx(ctx);
    egui::CentralPanel::default()
        .frame(
            Frame::new()
                .fill(p.bg)
                .inner_margin(Margin::symmetric(24, 18)),
        )
        .show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, add);
        });
}

fn hash_of(text: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

/// A strength estimate that is only recomputed when the text changes.
#[derive(Default)]
pub struct StrengthCache {
    key: Option<u64>,
    pub value: Option<Strength>,
}

impl StrengthCache {
    pub fn get(&mut self, password: &str) -> &Strength {
        let key = hash_of(password);
        if self.key != Some(key) || self.value.is_none() {
            self.value = Some(strength::estimate(password, &[]));
            self.key = Some(key);
        }
        self.value.as_ref().expect("set above")
    }

    pub fn clear(&mut self) {
        self.key = None;
        self.value = None;
    }
}

/// The strength meter with plain-language feedback.
pub(super) fn strength_block(ui: &mut Ui, s: &Strength, empty: bool, width: f32) {
    let p = pal(ui);
    widgets::strength_bar(ui, s.score, empty, width);
    if empty {
        return;
    }
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(strength::score_label(s.score))
                .font(semibold(13.5))
                .color(widgets::strength_color(&p, s.score)),
        );
        ui.label(
            RichText::new(format!(
                "{} · offline cracking: {}",
                s.bits_text(),
                s.offline_slow
            ))
            .size(12.5)
            .color(p.muted),
        );
    });
    if let Some(w) = &s.warning {
        ui.add(egui::Label::new(RichText::new(w).size(12.5).color(p.warn)).wrap());
    }
    for tip in s.suggestions.iter().take(2) {
        ui.add(egui::Label::new(RichText::new(tip).size(12.5).color(p.muted)).wrap());
    }
}

// --------------------------------------------------------------------------------------
// Welcome
// --------------------------------------------------------------------------------------

#[derive(Default)]
pub struct WelcomeState {
    error: Option<String>,
}

fn pick_vault_file() -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_title("Open a KeepForge vault")
        .add_filter("KeepForge vault", &["kfv"])
        .add_filter("All files", &["*"])
        .pick_file()
}

impl WelcomeState {
    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        logo: Option<&TextureHandle>,
    ) -> Option<Go> {
        let mut go = None;
        let p = pal_ctx(ctx);
        page(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space((ui.available_height() * 0.07).clamp(8.0, 60.0));
                paint_logo(ui, logo, 76.0);
                ui.add_space(8.0);
                ui.label(RichText::new("Welcome to KeepForge").font(semibold(28.0)));
                ui.label(
                    RichText::new(
                        "Your passwords in one encrypted file on this PC. No account, no cloud.",
                    )
                    .size(15.0)
                    .color(p.muted),
                );
                ui.add_space(22.0);
            });
            let total = ui.available_width().min(900.0);
            let pad = (ui.available_width() - total) / 2.0;
            let card_w = (total - 32.0) / 3.0;
            ui.horizontal(|ui| {
                ui.add_space(pad);
                ui.spacing_mut().item_spacing.x = 16.0;
                let cards: [(Icon, &str, &str, &str, u8); 3] = [
                    (
                        Icon::ADD,
                        "Create a new vault",
                        "Start fresh. You choose a master password; KeepForge makes the encrypted file.",
                        "Create a vault",
                        0,
                    ),
                    (
                        Icon::FOLDER_OPEN,
                        "Open an existing vault",
                        "Already have a .kfv file, perhaps from another PC? Open it here.",
                        "Open a vault",
                        1,
                    ),
                    (
                        Icon::IMPORT,
                        "Import from another manager",
                        "Bring your passwords over from a browser or another password manager's export file.",
                        "Create and import",
                        2,
                    ),
                ];
                for (icon, title, text, button, action) in cards {
                    Frame::new()
                        .fill(p.card)
                        .stroke(Stroke::new(1.0_f32, p.border))
                        .corner_radius(CornerRadius::same(14))
                        .inner_margin(Margin::same(20))
                        .show(ui, |ui| {
                            ui.set_width(card_w - 40.0);
                            ui.set_min_height(210.0);
                            ui.vertical(|ui| {
                                let (rect, _) =
                                    ui.allocate_exact_size(vec2(48.0, 48.0), Sense::hover());
                                ui.painter().circle_filled(
                                    rect.center(),
                                    24.0,
                                    p.accent.gamma_multiply(0.15),
                                );
                                ui.painter().text(
                                    rect.center(),
                                    egui::Align2::CENTER_CENTER,
                                    icon.glyph(),
                                    regular(22.0),
                                    p.accent,
                                );
                                ui.add_space(6.0);
                                ui.label(RichText::new(title).font(semibold(17.0)));
                                ui.add(
                                    egui::Label::new(RichText::new(text).color(p.muted)).wrap(),
                                );
                                ui.add_space(8.0);
                                let clicked = if action == 0 {
                                    widgets::primary_button(ui, button, true).clicked()
                                } else {
                                    widgets::ghost_button(ui, button).clicked()
                                };
                                if clicked {
                                    match action {
                                        0 => go = Some(Go::Create { then_import: false }),
                                        1 => {
                                            if let Some(path) = pick_vault_file() {
                                                go = Some(Go::Unlock(path));
                                            }
                                        }
                                        _ => go = Some(Go::Create { then_import: true }),
                                    }
                                }
                            });
                        });
                }
            });
            if let Some(e) = &self.error {
                ui.add_space(10.0);
                ui.vertical_centered(|ui| ui.colored_label(p.danger, e));
            }

            // Recent vaults.
            if !sh.settings.recent.is_empty() {
                ui.add_space(22.0);
                let mut forget = None;
                ui.horizontal(|ui| {
                    ui.add_space(pad);
                    ui.vertical(|ui| {
                        ui.set_width(total);
                        widgets::section(ui, "Recent vaults");
                        ui.add_space(2.0);
                        for recent in &sh.settings.recent {
                            let exists = sh.demo || Path::new(&recent.path).exists();
                            let (rect, resp) =
                                ui.allocate_exact_size(vec2(total, 52.0), Sense::click());
                            let fill = if resp.hovered() { p.hover } else { p.card };
                            ui.painter().rect_filled(rect, CornerRadius::same(10), fill);
                            ui.painter().rect_stroke(
                                rect,
                                CornerRadius::same(10),
                                Stroke::new(1.0_f32, p.border),
                                egui::StrokeKind::Inside,
                            );
                            let tile =
                                Rect::from_min_size(rect.min + vec2(12.0, 9.0), vec2(34.0, 34.0));
                            widgets::letter_tile(ui, tile, &recent.name);
                            let text_rect = Rect::from_min_max(
                                rect.min + vec2(58.0, 6.0),
                                rect.max - vec2(150.0, 26.0),
                            );
                            widgets::text_in(ui, text_rect, &recent.name, semibold(15.0), p.text);
                            let path_rect = Rect::from_min_max(
                                rect.min + vec2(58.0, 27.0),
                                rect.max - vec2(150.0, 6.0),
                            );
                            widgets::text_in(
                                ui,
                                path_rect,
                                &if exists {
                                    recent.path.clone()
                                } else {
                                    format!("{} (not found)", recent.path)
                                },
                                regular(12.5),
                                p.faint,
                            );
                            widgets::text_in_right(
                                ui,
                                Rect::from_min_max(
                                    rect.max - vec2(146.0, 52.0),
                                    rect.max - vec2(14.0, 0.0),
                                ),
                                &format!("opened {}", crate::util::ago(recent.last_opened, sh.now)),
                                regular(12.5),
                                p.faint,
                            );
                            if resp.clicked() {
                                if exists {
                                    go = Some(Go::Unlock(PathBuf::from(&recent.path)));
                                } else {
                                    forget = Some(recent.path.clone());
                                }
                            }
                            ui.add_space(2.0);
                        }
                    });
                });
                if let Some(path) = forget {
                    sh.settings.forget(&path);
                    self.error = Some(
                        "That vault file is no longer there, so it was removed from the list."
                            .into(),
                    );
                }
            }

            ui.add_space(18.0);
            ui.vertical_centered(|ui| {
                ui.horizontal(|ui| {
                    ui.add_space((ui.available_width() - 250.0).max(0.0) / 2.0);
                    if widgets::link(ui, "About KeepForge").clicked() {
                        sh.about_open = true;
                    }
                    ui.label(RichText::new("·").color(p.faint));
                    ui.label(
                        RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                            .color(p.faint),
                    );
                });
            });
        });
        go
    }
}

// --------------------------------------------------------------------------------------
// Create
// --------------------------------------------------------------------------------------

pub struct CreateState {
    pub name: String,
    pub file: PathBuf,
    file_chosen: bool,
    pub password: SecretInput,
    pub confirm: SecretInput,
    show: bool,
    strength: StrengthCache,
    use_key_file: bool,
    key_file: Option<PathBuf>,
    busy: bool,
    error: Option<String>,
    then_import: bool,
}

fn documents_dir(demo: bool) -> PathBuf {
    if demo {
        return PathBuf::from("C:\\Users\\Alex\\Documents");
    }
    let home = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_default();
    let docs = home.join("Documents");
    if docs.is_dir() {
        docs
    } else {
        home
    }
}

fn file_name_for(name: &str) -> String {
    let clean = crate::kfx::safe_name(name.trim());
    let clean = if clean == "decrypted file" {
        "Vault".to_string()
    } else {
        clean
    };
    format!("{clean}.kfv")
}

impl CreateState {
    pub fn new(sh: &Shared, then_import: bool) -> Self {
        let name = "Personal".to_string();
        CreateState {
            file: documents_dir(sh.demo).join(file_name_for(&name)),
            name,
            file_chosen: false,
            password: SecretInput::new(),
            confirm: SecretInput::new(),
            show: false,
            strength: StrengthCache::default(),
            use_key_file: false,
            key_file: None,
            busy: false,
            error: None,
            then_import,
        }
    }

    pub fn created(
        &mut self,
        result: Result<Box<OpenVault>, OpenError>,
        secs: f64,
        sh: &mut Shared,
    ) -> Option<Go> {
        self.busy = false;
        match result {
            Ok(vault) => {
                if let (Some(path), Some(key)) = (&vault.path, &self.key_file) {
                    sh.settings
                        .remember(path, &vault.vault.name, Some(key), sh.now);
                }
                Some(Go::Opened(Box::new(Opened {
                    vault: *vault,
                    kdf_secs: Some(secs),
                    then_import: self.then_import,
                    fresh: true,
                })))
            }
            Err(e) => {
                self.error = Some(e.to_string());
                None
            }
        }
    }

    fn submit(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        if sh.demo {
            self.error = Some(
                "This is the demo: nothing is created. Start KeepForge normally to make a vault."
                    .into(),
            );
            return;
        }
        let Some(calibration) = sh.calibration else {
            return;
        };
        let mut creds = Credentials {
            password: self.password.to_secret(),
            key_file: None,
        };
        // The fields are wiped as soon as the password has been handed over.
        self.password.wipe();
        self.confirm.wipe();
        self.strength.clear();
        let (path, name) = (self.file.clone(), self.name.trim().to_string());
        let key_path = self.use_key_file.then(|| self.key_file.clone()).flatten();
        self.busy = true;
        self.error = None;
        sh.spawn(ctx, move || {
            let start = Instant::now();
            if let Some(key_path) = key_path {
                let text = vaultfile::new_key_file();
                if let Err(e) = std::fs::write(&key_path, text.as_bytes()) {
                    creds.wipe();
                    return Msg::Created(
                        Err(OpenError::Io(format!("Could not write the key file: {e}"))),
                        0.0,
                    );
                }
                creds.key_file = Some(vaultfile::key_file_digest(text.as_bytes()));
            }
            let result = OpenVault::create(&path, &name, &mut creds, calibration.params);
            Msg::Created(result.map(Box::new), start.elapsed().as_secs_f64())
        });
    }

    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        logo: Option<&TextureHandle>,
    ) -> Option<Go> {
        let mut go = None;
        let p = pal_ctx(ctx);
        sh.ensure_calibration(ctx);
        let mut submit = false;
        page(ctx, |ui| {
            let total = ui.available_width().min(980.0);
            let pad = (ui.available_width() - total) / 2.0;
            ui.horizontal(|ui| {
                ui.add_space(pad);
                paint_logo(ui, logo, 40.0);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 0.0;
                    ui.label(RichText::new("Create a new vault").font(semibold(24.0)));
                    ui.label(
                        RichText::new(if self.then_import {
                            "First make a vault to import into. The import starts right after."
                        } else {
                            "One encrypted file that holds everything."
                        })
                        .color(p.muted),
                    );
                });
            });
            ui.add_space(10.0);
            ui.horizontal_top(|ui| {
                ui.add_space(pad);
                ui.spacing_mut().item_spacing.x = 18.0;
                let left_w = (total * 0.6).floor();
                ui.vertical(|ui| {
                    ui.set_width(left_w);
                    widgets::card(ui, |ui| {
                        let w = ui.available_width();
                        ui.spacing_mut().item_spacing.y = 6.0;
                        widgets::caption(ui, "Vault name");
                        let before = self.name.clone();
                        widgets::text_input(ui, &mut self.name, "For example: Personal", w);
                        if self.name != before && !self.file_chosen {
                            self.file = documents_dir(sh.demo).join(file_name_for(&self.name));
                        }
                        ui.add_space(4.0);
                        widgets::caption(ui, "Vault file");
                        ui.horizontal(|ui| {
                            let label = self.file.to_string_lossy().to_string();
                            ui.scope(|ui| {
                                ui.set_width(w - 110.0);
                                ui.add(
                                    egui::Label::new(RichText::new(label).color(p.text))
                                        .truncate(),
                                );
                            });
                            if widgets::ghost_button(ui, "Change…").clicked() {
                                let picked = rfd::FileDialog::new()
                                    .set_title("Where to keep the vault")
                                    .set_file_name(file_name_for(&self.name))
                                    .add_filter("KeepForge vault", &["kfv"])
                                    .save_file();
                                if let Some(mut path) = picked {
                                    if path.extension().is_none() {
                                        path.set_extension("kfv");
                                    }
                                    self.file = path;
                                    self.file_chosen = true;
                                }
                            }
                        });

                        ui.add_space(6.0);
                        widgets::caption(ui, "Master password");
                        ui.horizontal(|ui| {
                            widgets::secret_input(
                                ui,
                                &mut self.password,
                                self.show,
                                "The one password you have to remember",
                                w - 44.0,
                            );
                            let icon = if self.show { Icon::HIDE } else { Icon::VIEW };
                            if widgets::icon_button(ui, icon, "Show or hide").clicked() {
                                self.show = !self.show;
                            }
                        });
                        let empty = self.password.is_empty();
                        let s = self.strength.get(self.password.as_str()).clone();
                        strength_block(ui, &s, empty, w);
                        if crate::sys::caps_lock_on() && !sh.shot {
                            ui.colored_label(p.warn, Icon::WARNING.with("Caps Lock is on"));
                        }

                        ui.add_space(4.0);
                        widgets::caption(ui, "Type it again");
                        widgets::secret_input(ui, &mut self.confirm, self.show, "", w);
                        let matches = self.password.as_str() == self.confirm.as_str();
                        if !self.confirm.is_empty() && !matches {
                            ui.colored_label(p.danger, "The two passwords are different.");
                        }

                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            if widgets::toggle(ui, self.use_key_file, true).clicked() {
                                self.use_key_file = !self.use_key_file;
                            }
                            ui.label("Also require a key file (optional second factor)");
                        });
                        if self.use_key_file {
                            widgets::note(
                                ui,
                                "KeepForge writes a small file with a random key. Opening the vault then needs both the password and that file. Keep it somewhere else than the vault (a USB stick), and keep a backup: without it the vault cannot be opened.",
                            );
                            ui.horizontal(|ui| {
                                let label = match &self.key_file {
                                    Some(k) => k.to_string_lossy().to_string(),
                                    None => "No place chosen yet".to_string(),
                                };
                                ui.add_sized(
                                    vec2(w - 190.0, 22.0),
                                    egui::Label::new(RichText::new(label).color(p.muted)).truncate(),
                                );
                                if widgets::ghost_button(ui, "Save key file as…").clicked() {
                                    let picked = rfd::FileDialog::new()
                                        .set_title("Where to save the new key file")
                                        .set_file_name(format!("{}.kfkey", self.name.trim()))
                                        .add_filter("KeepForge key file", &["kfkey"])
                                        .save_file();
                                    if let Some(path) = picked {
                                        self.key_file = Some(path);
                                    }
                                }
                            });
                        }

                        ui.add_space(8.0);
                        let refusal = strength::master_refusal(self.password.as_str(), &s);
                        let ready = !self.name.trim().is_empty()
                            && refusal.is_none()
                            && matches
                            && !self.busy
                            && (sh.calibration.is_some() || sh.shot)
                            && (!self.use_key_file || self.key_file.is_some());
                        if !empty {
                            if let Some(reason) = refusal {
                                ui.colored_label(p.danger, reason);
                            }
                        }
                        if let Some(e) = &self.error {
                            widgets::banner(ui, Icon::ERROR, p.danger, e);
                        }
                        ui.horizontal(|ui| {
                            if self.busy {
                                ui.add(egui::Spinner::new().size(20.0).color(p.accent));
                                ui.label("Creating the vault…");
                            } else {
                                if widgets::primary_button(ui, "Create vault", ready).clicked() {
                                    submit = true;
                                }
                                if widgets::ghost_button(ui, "Back").clicked() {
                                    go = Some(Go::Welcome);
                                }
                            }
                        });
                    });
                });
                ui.vertical(|ui| {
                    ui.set_width(total - left_w - 18.0);
                    widgets::card(ui, |ui| {
                        widgets::section(ui, "Good to know");
                        ui.add_space(2.0);
                        for (icon, text) in [
                            (Icon::KEY, "The master password is never stored anywhere. There is no reset: if you forget it, the vault cannot be opened by anyone."),
                            (Icon::NOTE, "A few random words (\"stoop unrated blizzard ferret\") are easier to remember and harder to guess than a short, complicated password."),
                            (Icon::DOCUMENT, "After creating the vault you can print an emergency sheet to write the password on and lock away."),
                            (Icon::SAVE, "The vault is one file. Copy it to back it up; KeepForge also keeps rolling backups next to it."),
                        ] {
                            ui.horizontal_top(|ui| {
                                ui.label(RichText::new(icon.glyph()).color(p.accent));
                                ui.add(egui::Label::new(RichText::new(text).size(13.5).color(p.muted)).wrap());
                            });
                            ui.add_space(4.0);
                        }
                    });
                    ui.add_space(4.0);
                    widgets::card(ui, |ui| {
                        widgets::section(ui, "Protection");
                        ui.add_space(2.0);
                        match (&sh.calibration, sh.shot || sh.demo) {
                            (Some(c), _) => {
                                widgets::note(
                                    ui,
                                    &format!(
                                        "Key stretching: {}. Each guess at your password costs an attacker about {:.1} s of work on a PC like this one.",
                                        c.params.describe(),
                                        c.took.as_secs_f64()
                                    ),
                                );
                            }
                            (None, true) => widgets::note(
                                ui,
                                "Key stretching: Argon2id, 256 MiB memory, 3 passes, 4 lanes. Each guess at your password costs an attacker about 0.7 s of work on a PC like this one.",
                            ),
                            (None, false) => {
                                ui.horizontal(|ui| {
                                    ui.add(egui::Spinner::new().size(16.0).color(p.accent));
                                    widgets::note(ui, "Measuring how strong the key stretching can be on this PC…");
                                });
                            }
                        }
                        widgets::note(ui, "Encryption: XChaCha20-Poly1305. You can raise the key stretching later in Settings.");
                    });
                });
            });
        });
        if submit || (ctx.input(|i| i.key_pressed(Key::Enter)) && self.can_submit(sh)) {
            self.submit(ctx, sh);
        }
        go
    }

    fn can_submit(&mut self, sh: &Shared) -> bool {
        let s = self.strength.get(self.password.as_str()).clone();
        !self.busy
            && (sh.calibration.is_some() || sh.shot)
            && !self.name.trim().is_empty()
            && strength::master_refusal(self.password.as_str(), &s).is_none()
            && self.password.as_str() == self.confirm.as_str()
            && (!self.use_key_file || self.key_file.is_some())
    }
}

// --------------------------------------------------------------------------------------
// Unlock
// --------------------------------------------------------------------------------------

pub struct UnlockState {
    pub path: PathBuf,
    pub name: String,
    password: SecretInput,
    show: bool,
    key_file: Option<PathBuf>,
    needs_key_file: bool,
    busy: bool,
    error: Option<String>,
    failures: u32,
    retry_at: Option<Instant>,
    /// The user agreed to open a file with unusual key-stretching settings.
    allow_unusual: bool,
    ask_unusual: Option<String>,
    attempt: u64,
    file_problem: Option<String>,
    demo: bool,
    focus: bool,
}

/// The pause after `failures` wrong attempts. This only slows down someone
/// typing guesses at this window; a stolen file is protected by Argon2id.
pub fn retry_delay(failures: u32) -> f32 {
    match failures {
        0 | 1 => 0.0,
        n => (0.5 * 2f32.powi(n as i32 - 2)).min(8.0),
    }
}

impl UnlockState {
    pub fn new(path: PathBuf, settings: &Settings) -> Self {
        let recent = settings
            .recent
            .iter()
            .find(|r| r.path.eq_ignore_ascii_case(&path.to_string_lossy()));
        let name = recent
            .map(|r| r.name.clone())
            .filter(|n| !n.is_empty())
            .or_else(|| path.file_stem().map(|s| s.to_string_lossy().to_string()))
            .unwrap_or_else(|| "Vault".into());
        // Read only the plaintext header, to learn whether a key file is needed.
        let (needs_key_file, file_problem) = match crate::store::read_file(&path) {
            Ok(bytes) => match vaultfile::parse_header(&bytes) {
                Ok(h) => (h.needs_key_file(), None),
                Err(e) => (false, Some(e.to_string())),
            },
            Err(e) => (false, Some(e)),
        };
        UnlockState {
            key_file: recent
                .and_then(|r| r.key_file.clone())
                .map(PathBuf::from)
                .filter(|k| needs_key_file && k.exists()),
            path,
            name,
            password: SecretInput::new(),
            show: false,
            needs_key_file,
            busy: false,
            error: None,
            failures: 0,
            retry_at: None,
            allow_unusual: false,
            ask_unusual: None,
            attempt: 0,
            file_problem,
            demo: false,
            focus: true,
        }
    }

    /// The lock screen of the in-memory demo vault.
    pub fn demo(name: &str) -> Self {
        UnlockState {
            path: PathBuf::from(crate::demo::DEMO_PATH),
            name: name.to_string(),
            password: SecretInput::new(),
            show: false,
            key_file: None,
            needs_key_file: false,
            busy: false,
            error: None,
            failures: 0,
            retry_at: None,
            allow_unusual: false,
            ask_unusual: None,
            attempt: 0,
            file_problem: None,
            demo: true,
            focus: true,
        }
    }

    pub fn unlocked(
        &mut self,
        result: Result<Box<OpenVault>, OpenError>,
        secs: f64,
        attempt: u64,
        sh: &mut Shared,
    ) -> Option<Go> {
        if attempt != self.attempt {
            return None;
        }
        self.busy = false;
        match result {
            Ok(vault) => {
                if let Some(key) = &self.key_file {
                    sh.settings
                        .remember(&self.path, &vault.vault.name, Some(key), sh.now);
                }
                Some(Go::Opened(Box::new(Opened {
                    vault: *vault,
                    kdf_secs: Some(secs),
                    then_import: false,
                    fresh: false,
                })))
            }
            Err(OpenError::Vault(e @ (VaultError::WeakKdf(_) | VaultError::HeavyKdf(_)))) => {
                self.ask_unusual = Some(e.to_string());
                None
            }
            Err(e) => {
                if matches!(e, OpenError::Vault(VaultError::WrongKey)) {
                    self.failures += 1;
                    let delay = retry_delay(self.failures);
                    if delay > 0.0 {
                        self.retry_at =
                            Some(Instant::now() + std::time::Duration::from_secs_f32(delay));
                    }
                }
                self.error = Some(e.to_string());
                self.focus = true;
                None
            }
        }
    }

    fn submit(&mut self, ctx: &egui::Context, sh: &mut Shared) -> Option<Go> {
        if self.demo {
            self.password.wipe();
            let now = sh.now;
            return Some(Go::Opened(Box::new(Opened {
                vault: OpenVault::in_memory(|s| crate::demo::vault(s, now)),
                kdf_secs: Some(0.7),
                then_import: false,
                fresh: false,
            })));
        }
        let mut creds = Credentials {
            password: self.password.to_secret(),
            key_file: None,
        };
        // The field is wiped as soon as the password has been handed over.
        self.password.wipe();
        self.busy = true;
        self.error = None;
        self.attempt += 1;
        let (path, key_path, allow, attempt) = (
            self.path.clone(),
            self.key_file.clone(),
            self.allow_unusual,
            self.attempt,
        );
        sh.spawn(ctx, move || {
            let start = Instant::now();
            if let Some(key_path) = key_path {
                match read_key_file(&key_path) {
                    Ok(digest) => creds.key_file = Some(digest),
                    Err(e) => {
                        creds.wipe();
                        return Msg::Unlocked(Err(OpenError::Io(e)), 0.0, attempt);
                    }
                }
            }
            let result = OpenVault::open(&path, &mut creds, allow);
            Msg::Unlocked(result.map(Box::new), start.elapsed().as_secs_f64(), attempt)
        });
        None
    }

    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        logo: Option<&TextureHandle>,
    ) -> Option<Go> {
        let mut go = None;
        let p = pal_ctx(ctx);
        let wait = self
            .retry_at
            .map(|t| t.saturating_duration_since(Instant::now()).as_secs_f32())
            .filter(|s| *s > 0.0);
        if wait.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        let mut submit = false;
        page(ctx, |ui| {
            ui.add_space((ui.available_height() * 0.16).clamp(10.0, 150.0));
            let w = 400.0;
            ui.horizontal(|ui| {
                ui.add_space((ui.available_width() - w - 56.0).max(0.0) / 2.0);
                Frame::new()
                    .fill(p.card)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .corner_radius(CornerRadius::same(16))
                    .inner_margin(Margin::same(28))
                    .show(ui, |ui| {
                        ui.set_width(w);
                        ui.vertical(|ui| {
                        ui.vertical_centered(|ui| {
                            paint_logo(ui, logo, 64.0);
                            ui.add_space(6.0);
                            ui.label(RichText::new(&self.name).font(semibold(22.0)));
                            ui.label(RichText::new(Icon::LOCK.with("Locked")).color(p.muted));
                        });
                        ui.add_space(12.0);
                        if let Some(problem) = &self.file_problem {
                            widgets::banner(ui, Icon::ERROR, p.danger, problem);
                            ui.add_space(8.0);
                        } else {
                            widgets::caption(ui, "Master password");
                            ui.horizontal(|ui| {
                                let enabled = !self.busy;
                                ui.add_enabled_ui(enabled, |ui| {
                                    let resp = widgets::secret_input(
                                        ui,
                                        &mut self.password,
                                        self.show,
                                        "",
                                        w - 44.0,
                                    );
                                    if self.focus && enabled {
                                        resp.request_focus();
                                        self.focus = false;
                                    }
                                });
                                let icon = if self.show { Icon::HIDE } else { Icon::VIEW };
                                if widgets::icon_button(ui, icon, "Show or hide").clicked() {
                                    self.show = !self.show;
                                }
                            });
                            if crate::sys::caps_lock_on() && !sh.shot {
                                ui.colored_label(p.warn, Icon::WARNING.with("Caps Lock is on"));
                            }
                            if self.needs_key_file {
                                ui.add_space(4.0);
                                widgets::caption(ui, "Key file");
                                ui.horizontal(|ui| {
                                    let label = match &self.key_file {
                                        Some(k) => k
                                            .file_name()
                                            .map(|n| n.to_string_lossy().to_string())
                                            .unwrap_or_default(),
                                        None => "Not chosen".to_string(),
                                    };
                                    ui.add_sized(
                                        vec2(w - 110.0, 22.0),
                                        egui::Label::new(RichText::new(label).color(p.text)).truncate(),
                                    );
                                    if widgets::ghost_button(ui, "Choose…").clicked() {
                                        if let Some(path) = rfd::FileDialog::new()
                                            .set_title("Choose this vault's key file")
                                            .pick_file()
                                        {
                                            self.key_file = Some(path);
                                        }
                                    }
                                });
                            }
                            ui.add_space(10.0);
                            if let Some(e) = &self.error {
                                ui.add(egui::Label::new(RichText::new(e).color(p.danger)).wrap());
                                ui.add_space(4.0);
                            }
                            if let Some(text) = &self.ask_unusual {
                                widgets::banner(ui, Icon::WARNING, p.warn, &format!(
                                    "{text} That is unusual for a vault made by KeepForge. Only continue if you trust where this file came from."
                                ));
                                ui.horizontal(|ui| {
                                    if widgets::ghost_button(ui, "Open anyway").clicked() {
                                        self.allow_unusual = true;
                                        self.ask_unusual = None;
                                        self.error = Some("Type the master password again to continue.".into());
                                        self.focus = true;
                                    }
                                    if widgets::ghost_button(ui, "Cancel").clicked() {
                                        self.ask_unusual = None;
                                    }
                                });
                                ui.add_space(4.0);
                            }
                            let ready = !self.busy
                                && wait.is_none()
                                && !self.password.is_empty()
                                && (!self.needs_key_file || self.key_file.is_some());
                            if self.busy {
                                ui.horizontal(|ui| {
                                    ui.add(egui::Spinner::new().size(20.0).color(p.accent));
                                    ui.label("Unlocking…");
                                });
                            } else {
                                let label = match wait {
                                    Some(s) => format!("Wait {s:.0} s"),
                                    None => "Unlock".to_string(),
                                };
                                ui.horizontal(|ui| {
                                    if widgets::primary_button(ui, &label, ready).clicked() {
                                        submit = true;
                                    }
                                });
                                if ready && ui.input(|i| i.key_pressed(Key::Enter)) {
                                    submit = true;
                                }
                            }
                        }
                        ui.add_space(6.0);
                        ui.with_layout(Layout::top_down(Align::Center), |ui| {
                            if !self.busy && widgets::link(ui, "Open another vault").clicked() {
                                go = Some(Go::Welcome);
                            }
                        });
                        });
                    });
            });
            ui.add_space(14.0);
            ui.vertical_centered(|ui| {
                ui.label(
                    RichText::new("KeepForge works offline. Nothing leaves this PC.")
                        .size(12.5)
                        .color(p.faint),
                );
            });
        });
        if submit {
            if let Some(g) = self.submit(ctx, sh) {
                go = Some(g);
            }
        }
        go
    }
}

/// Reads a key file (at most 16 MiB) and returns its SHA-256.
pub fn read_key_file(path: &Path) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("Could not open the key file: {e}"))?;
    if meta.len() > 16 * 1024 * 1024 {
        return Err("That file is too large to be a key file (the limit is 16 MB).".into());
    }
    let bytes = zeroize::Zeroizing::new(
        std::fs::read(path).map_err(|e| format!("Could not read the key file: {e}"))?,
    );
    Ok(vaultfile::key_file_digest(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_delay_grows_and_is_capped() {
        assert_eq!(retry_delay(0), 0.0);
        assert_eq!(retry_delay(1), 0.0);
        assert_eq!(retry_delay(2), 0.5);
        assert_eq!(retry_delay(3), 1.0);
        assert_eq!(retry_delay(5), 4.0);
        assert_eq!(retry_delay(6), 8.0);
        assert_eq!(retry_delay(60), 8.0);
        assert_eq!(file_name_for("My: Vault?"), "My_ Vault_.kfv");
        assert_eq!(file_name_for("  "), "Vault.kfv");
    }
}
