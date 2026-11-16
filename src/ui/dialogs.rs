//! Modal dialogs of the unlocked window: confirmations, import and export,
//! changing the master password, the emergency sheet, sync conflicts, QR
//! codes, the auto-type picker and the "this goes online" explanations.

use super::app::{Go, Msg, Shared};
use super::main_view::Main;
use super::start::{strength_block, StrengthCache};
use super::theme::{pal, pal_ctx, regular, semibold, Icon};
use super::widgets;
use crate::import::{self, Format, Loaded};
use crate::model::{Id, Item, Kind};
use crate::secret::{Protected, SecretInput};
use crate::store::OpenError;
use crate::vaultfile::{self, Credentials, KdfParams, Sealer, VaultError};
use eframe::egui::{self, vec2, Align, Color32, Layout, RichText, Sense, Ui};
use std::path::PathBuf;

pub enum ConfirmAction {
    DeleteForever(Id),
    EmptyTrash,
    DeleteFolder(Id),
    DeleteAttachment(Id, usize),
    RestoreHistory(Id, usize),
    /// Plaintext export: `true` for JSON, `false` for CSV.
    ExportPlain(bool),
    /// Shred an import file after it has been imported.
    ShredFile(PathBuf),
}

/// What the user is about to send to an online service.
pub enum Online {
    Emails(Vec<String>),
    Ip(String),
    Passwords,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyFileChoice {
    None,
    New,
    Existing,
}

pub struct ChangePw {
    password: SecretInput,
    confirm: SecretInput,
    show: bool,
    strength: StrengthCache,
    memory_mib: u32,
    key_choice: KeyFileChoice,
    key_path: Option<PathBuf>,
    busy: bool,
    error: Option<String>,
}

pub struct ExportDlg {
    password: SecretInput,
    confirm: SecretInput,
    show: bool,
    busy: bool,
}

pub struct ImportDlg {
    path: PathBuf,
    loaded: Option<Loaded>,
    duplicates: Vec<bool>,
    skip_duplicates: bool,
    error: Option<String>,
}

pub struct QrDlg {
    title: String,
    hint: String,
    payload: Protected,
    shown_until: Option<f64>,
    matrix: Option<crate::qr::Matrix>,
}

pub enum Dialog {
    Confirm {
        title: String,
        text: String,
        button: String,
        danger: bool,
        action: ConfirmAction,
    },
    Emergency,
    Folder {
        id: Option<Id>,
        name: String,
    },
    Conflict,
    AutoType {
        target: isize,
        title: String,
        candidates: Vec<Id>,
    },
    Qr(Box<QrDlg>),
    ChangePassword(Box<ChangePw>),
    Export(Box<ExportDlg>),
    Import(Box<ImportDlg>),
    Online(Online, bool),
}

impl Dialog {
    pub fn confirm(title: &str, text: &str, button: &str, action: ConfirmAction) -> Dialog {
        Dialog::Confirm {
            title: title.into(),
            text: text.into(),
            button: button.into(),
            danger: true,
            action,
        }
    }

    pub fn confirm_plain(title: &str, text: &str, button: &str, action: ConfirmAction) -> Dialog {
        Dialog::Confirm {
            title: title.into(),
            text: text.into(),
            button: button.into(),
            danger: false,
            action,
        }
    }

    pub fn change_password(current: KdfParams) -> Dialog {
        Dialog::ChangePassword(Box::new(ChangePw {
            password: SecretInput::new(),
            confirm: SecretInput::new(),
            show: false,
            strength: StrengthCache::default(),
            memory_mib: current.mib().clamp(64, 1024),
            key_choice: KeyFileChoice::None,
            key_path: None,
            busy: false,
            error: None,
        }))
    }

    pub fn export() -> Dialog {
        Dialog::Export(Box::new(ExportDlg {
            password: SecretInput::new(),
            confirm: SecretInput::new(),
            show: false,
            busy: false,
        }))
    }

    pub fn qr(title: &str, hint: &str, payload: Protected) -> Dialog {
        Dialog::Qr(Box::new(QrDlg {
            title: title.into(),
            hint: hint.into(),
            payload,
            shown_until: None,
            matrix: None,
        }))
    }

    pub fn qr_wifi(item: &Item) -> Dialog {
        let security = item
            .field("Security")
            .map(|f| f.value.clone())
            .unwrap_or_default();
        let password = item.password.open_str();
        let payload = crate::qr::wifi_payload(&item.username, &password, &security);
        let sealed = seal_like(&item.password, &payload);
        Dialog::qr(
            &format!("Wi-Fi: {}", item.username),
            "Point a phone's camera at the code to join the network.",
            sealed,
        )
    }

    pub fn qr_totp(item: &Item) -> Dialog {
        let seed = item.totp.open_str();
        let payload = match crate::totp::Totp::parse(&seed) {
            Ok(t) => t.to_uri(if item.username.is_empty() {
                &item.title
            } else {
                &item.username
            }),
            Err(_) => zeroize::Zeroizing::new(String::new()),
        };
        Dialog::qr(
            &format!("One-time code: {}", item.title),
            "Scan with an authenticator app to move this code to a phone. Anyone who scans it can produce your codes.",
            seal_like(&item.totp, &payload),
        )
    }
}

/// Seals `text` under the same session as `like`. If `like` is empty there is
/// no session to borrow, and the result is empty too.
fn seal_like(like: &Protected, text: &str) -> Protected {
    like.reseal(text.as_bytes())
}

pub const QR_SECONDS: f64 = 30.0;

fn title(ui: &mut Ui, text: &str) {
    ui.label(RichText::new(text).font(semibold(19.0)));
    ui.add_space(2.0);
}

fn para(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.add(egui::Label::new(RichText::new(text).color(p.muted)).wrap());
}

impl Main {
    pub fn start_import(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        if sh.demo {
            sh.toast("Importing is switched off in the demo.", false);
            return;
        }
        let Some(path) = rfd::FileDialog::new()
            .set_title("Choose the export file to import")
            .add_filter("CSV or JSON export", &["csv", "json", "txt"])
            .add_filter("All files", &["*"])
            .pick_file()
        else {
            return;
        };
        self.dialog = Some(Dialog::Import(Box::new(ImportDlg {
            path: path.clone(),
            loaded: None,
            duplicates: Vec::new(),
            skip_duplicates: true,
            error: None,
        })));
        sh.spawn(ctx, move || {
            let result = (|| {
                let size = std::fs::metadata(&path)
                    .map(|m| m.len())
                    .map_err(|e| e.to_string())?;
                if size > 64 * 1024 * 1024 {
                    return Err("That file is too large to be a password export.".to_string());
                }
                let bytes = zeroize::Zeroizing::new(
                    std::fs::read(&path).map_err(|e| format!("Could not read the file: {e}"))?,
                );
                let text = std::str::from_utf8(&bytes).map_err(|_| {
                    "This file is not plain text (UTF-8), so it cannot be read as CSV or JSON."
                        .to_string()
                })?;
                import::load(text)
            })();
            Msg::ImportLoaded(result)
        });
    }

    pub(super) fn import_loaded(&mut self, _sh: &mut Shared, result: Result<Loaded, String>) {
        let Some(Dialog::Import(dlg)) = &mut self.dialog else {
            return;
        };
        match result {
            Ok(loaded) => {
                dlg.duplicates = import::find_duplicates(&self.v.vault, &loaded.drafts);
                dlg.loaded = Some(loaded);
            }
            Err(e) => dlg.error = Some(e),
        }
    }

    pub(super) fn new_sealer(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        result: Result<Sealer, VaultError>,
        secs: f64,
    ) {
        match result {
            Ok(sealer) => match self.v.replace_sealer(sealer) {
                Ok(()) => {
                    self.kdf_secs = Some(secs);
                    self.dialog = None;
                    sh.toast(
                        "The vault's protection was changed. Backups made before now still open with the old password.",
                        false,
                    );
                    self.changed(ctx, sh);
                }
                Err(e) => {
                    if let Some(Dialog::ChangePassword(d)) = &mut self.dialog {
                        d.busy = false;
                        d.error = Some(e.to_string());
                    }
                }
            },
            Err(e) => {
                if let Some(Dialog::ChangePassword(d)) = &mut self.dialog {
                    d.busy = false;
                    d.error = Some(e.to_string());
                }
            }
        }
    }

    fn run_confirmed(&mut self, ctx: &egui::Context, sh: &mut Shared, action: ConfirmAction) {
        match action {
            ConfirmAction::DeleteForever(id) => {
                self.v.vault.delete_forever(id);
                self.selected = None;
                sh.toast("Deleted", false);
                self.changed(ctx, sh);
            }
            ConfirmAction::EmptyTrash => {
                let n = self.v.vault.empty_trash();
                self.selected = None;
                sh.toast(format!("{n} item(s) deleted"), false);
                self.changed(ctx, sh);
            }
            ConfirmAction::DeleteFolder(id) => {
                self.v.vault.folders.retain(|f| f.id != id);
                for i in &mut self.v.vault.items {
                    if i.folder == Some(id) {
                        i.folder = None;
                    }
                }
                self.nav = super::main_view::Nav::All;
                self.changed(ctx, sh);
            }
            ConfirmAction::DeleteAttachment(id, n) => {
                if let Some(item) = self.v.vault.item_mut(id) {
                    if n < item.attachments.len() {
                        item.attachments.remove(n);
                        item.modified = sh.now;
                    }
                }
                self.changed(ctx, sh);
            }
            ConfirmAction::RestoreHistory(id, n) => {
                let session = self.v.session.clone();
                if let Some(item) = self.v.vault.item_mut(id) {
                    if n < item.history.len() {
                        let old = item.history.remove(n);
                        let text = old.password.open_str();
                        item.set_password(&session, &text, sh.now);
                        item.modified = sh.now;
                    }
                }
                sh.toast("Password restored", false);
                self.changed(ctx, sh);
            }
            ConfirmAction::ExportPlain(json) => self.export_plain(sh, json),
            ConfirmAction::ShredFile(path) => self.start_shred(ctx, sh, path),
        }
    }

    fn export_plain(&mut self, sh: &mut Shared, json: bool) {
        if sh.demo {
            sh.toast("Exporting is switched off in the demo.", false);
            return;
        }
        let (ext, name) = if json {
            ("json", "JSON")
        } else {
            ("csv", "CSV")
        };
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save the unencrypted export")
            .set_file_name(format!("{} export.{ext}", self.v.vault.name))
            .add_filter(name, &[ext])
            .save_file()
        else {
            return;
        };
        let data = if json {
            crate::export::to_json(&self.v.vault)
        } else {
            crate::export::to_csv(&self.v.vault)
        };
        match std::fs::write(&path, data.as_slice()) {
            Ok(()) => sh.toast(
                "Exported. That file is NOT encrypted: delete it as soon as you are done with it.",
                true,
            ),
            Err(e) => sh.toast(format!("Could not write the file: {e}"), true),
        }
    }

    fn export_encrypted(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        new_password: Option<crate::secret::SecretString>,
    ) {
        if sh.demo {
            sh.toast("Exporting is switched off in the demo.", false);
            return;
        }
        let Some(mut path) = rfd::FileDialog::new()
            .set_title("Save an encrypted copy of the vault")
            .set_file_name(format!("{} copy.kfv", self.v.vault.name))
            .add_filter("KeepForge vault", &["kfv"])
            .save_file()
        else {
            return;
        };
        if path.extension().is_none() {
            path.set_extension("kfv");
        }
        if Some(&path) == self.v.path.as_ref() {
            sh.toast(
                "Choose another name: that is the vault you have open.",
                true,
            );
            return;
        }
        let mut vault = self.v.vault.clone();
        let current = self.v.sealer.share();
        let kdf = current.kdf;
        sh.spawn(ctx, move || {
            let result = (|| -> Result<(), String> {
                let sealer = match new_password {
                    Some(password) => {
                        let mut creds = Credentials {
                            password,
                            key_file: None,
                        };
                        let fresh = Sealer::create(&mut creds, kdf).map_err(|e| e.to_string())?;
                        vaultfile::rekey_attachments(&mut vault, &current, &fresh)
                            .map_err(|e| e.to_string())?;
                        fresh
                    }
                    None => current,
                };
                let bytes = vaultfile::encode(&vault, &sealer).map_err(|e| e.to_string())?;
                crate::store::write_atomic(&path, &bytes)
                    .map_err(|e| format!("Could not write the file: {e}"))
            })();
            match result {
                Ok(()) => Msg::Toast("Encrypted copy saved.".into(), false),
                Err(e) => Msg::Toast(e, true),
            }
        });
    }

    pub(super) fn dialogs(&mut self, ctx: &egui::Context, sh: &mut Shared) -> Option<Go> {
        let mut dialog = self.dialog.take()?;
        let p = pal_ctx(ctx);
        let mut go = None;
        let mut close = false;
        // A dialog may replace itself with another one.
        let mut next: Option<Dialog> = None;
        let mut confirmed = false;
        let modal = egui::Modal::new(egui::Id::new("dialog"))
            .frame(widgets::modal_frame(ctx))
            .show(ctx, |ui| match &mut dialog {
                Dialog::Confirm {
                    title: t,
                    text,
                    button,
                    danger,
                    ..
                } => {
                    ui.set_width(480.0);
                    title(ui, t);
                    para(ui, text);
                    ui.add_space(12.0);
                    let mut yes = false;
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        yes = if *danger {
                            widgets::danger_button(ui, button, true).clicked()
                        } else {
                            widgets::primary_button(ui, button, true).clicked()
                        };
                        if widgets::ghost_button(ui, "Cancel").clicked() {
                            close = true;
                        }
                    });
                    if yes {
                        close = true;
                        confirmed = true;
                    }
                }
                Dialog::Emergency => {
                    ui.set_width(520.0);
                    title(ui, "Make an emergency sheet");
                    para(ui, "If you ever forget the master password, nobody can open this vault for you. An emergency sheet is a page you print, write the master password on by hand, and lock away.");
                    ui.add_space(4.0);
                    para(ui, "KeepForge never writes the password into the sheet. It holds the vault's name and file location, today's date, and a blank line for you to fill in.");
                    ui.add_space(12.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::primary_button(ui, "Save the sheet…", true).clicked() {
                            self.save_emergency_sheet(sh);
                            close = true;
                        }
                        if widgets::ghost_button(ui, "Not now").clicked() {
                            close = true;
                        }
                    });
                    ui.label(RichText::new("You can also do this later in Settings.").size(12.0).color(p.faint));
                }
                Dialog::Folder { id, name } => {
                    ui.set_width(380.0);
                    title(ui, if id.is_some() { "Rename folder" } else { "New folder" });
                    let resp = widgets::text_input(ui, name, "Folder name", 380.0);
                    resp.request_focus();
                    ui.add_space(12.0);
                    let enter = ui.input(|i| i.key_pressed(egui::Key::Enter));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        let ok = widgets::primary_button(ui, "Save", !name.trim().is_empty()).clicked();
                        if (ok || enter) && !name.trim().is_empty() {
                            match id {
                                Some(id) => {
                                    if let Some(f) = self.v.vault.folders.iter_mut().find(|f| f.id == *id) {
                                        f.name = name.trim().to_string();
                                    }
                                }
                                None => {
                                    if let Some(new_id) = self.v.vault.folder_id(name) {
                                        self.nav = super::main_view::Nav::Folder(new_id);
                                    }
                                }
                            }
                            self.changed(ui.ctx(), sh);
                            close = true;
                        }
                        if widgets::ghost_button(ui, "Cancel").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::Conflict => {
                    ui.set_width(540.0);
                    title(ui, "The vault file changed on disk");
                    para(ui, "Since you opened it, the file was changed by something else, for example another PC through a synced folder. Your latest change has not been saved yet.");
                    ui.add_space(10.0);
                    if widgets::primary_button(ui, "Merge both versions (recommended)", true).clicked() {
                        match self.v.read_disk_copy() {
                            Ok(theirs) => {
                                let stats = crate::store::merge_newest(&mut self.v.vault, theirs);
                                sh.toast(
                                    format!(
                                        "Merged: {} added, {} updated from the other copy, {} of yours kept.",
                                        stats.added, stats.updated, stats.kept
                                    ),
                                    false,
                                );
                                self.rev += 1;
                                self.request_save(ui.ctx(), sh, true);
                                close = true;
                            }
                            Err(OpenError::Vault(VaultError::WrongKey)) => sh.toast(
                                "The other copy uses a different master password or key settings, so it cannot be merged. Reload it or overwrite it.",
                                true,
                            ),
                            Err(e) => sh.toast(e.to_string(), true),
                        }
                    }
                    widgets::note(ui, "Keeps every item from both; where both changed the same item, the newer one wins.");
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if widgets::ghost_button(ui, "Reload from disk").clicked() {
                            go = Some(Go::Lock);
                            close = true;
                        }
                        if widgets::ghost_button(ui, "Overwrite with mine").clicked() {
                            self.request_save(ui.ctx(), sh, true);
                            close = true;
                        }
                    });
                    widgets::note(ui, "Reload locks the vault and drops your unsaved change. Overwrite replaces what the other device wrote (a backup of it is kept next to the vault).");
                }
                Dialog::AutoType {
                    target,
                    title: window,
                    candidates,
                } => {
                    ui.set_width(460.0);
                    title(ui, "Which login?");
                    para(ui, &format!("Several logins fit the window \"{}\".", crate::util::truncate(window, 60)));
                    ui.add_space(6.0);
                    let mut pick = None;
                    egui::ScrollArea::vertical().max_height(300.0).show(ui, |ui| {
                        for id in candidates.iter() {
                            let Some(item) = self.v.vault.item(*id) else { continue };
                            let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 48.0), Sense::click());
                            if resp.hovered() {
                                ui.painter().rect_filled(rect, 8, p.hover);
                            }
                            widgets::letter_tile(ui, egui::Rect::from_min_size(rect.min + vec2(8.0, 8.0), vec2(32.0, 32.0)), &item.title);
                            widgets::text_in(ui, egui::Rect::from_min_max(rect.min + vec2(50.0, 5.0), rect.max - vec2(8.0, 24.0)), &item.title, semibold(14.5), p.text);
                            widgets::text_in(ui, egui::Rect::from_min_max(rect.min + vec2(50.0, 25.0), rect.max - vec2(8.0, 5.0)), &item.username, regular(12.5), p.muted);
                            if resp.clicked() {
                                pick = Some(*id);
                            }
                        }
                    });
                    ui.add_space(8.0);
                    if widgets::ghost_button(ui, "Cancel").clicked() {
                        close = true;
                    }
                    if let Some(id) = pick {
                        let target = *target;
                        self.autotype_into(ui.ctx(), sh, id, target);
                        close = true;
                    }
                }
                Dialog::Qr(q) => {
                    let q = &mut **q;
                    ui.set_width(380.0);
                    title(ui, &q.title);
                    para(ui, &q.hint);
                    ui.add_space(8.0);
                    let now = ui.input(|i| i.time);
                    if q.shown_until.map(|t| t <= now).unwrap_or(false) {
                        q.shown_until = None;
                        q.matrix = None;
                    }
                    ui.vertical_centered(|ui| {
                        let side = 300.0;
                        let (rect, resp) = ui.allocate_exact_size(vec2(side, side), Sense::click());
                        match (&q.matrix, q.shown_until) {
                            (Some(m), Some(until)) => {
                                ui.painter().rect_filled(rect, 8, Color32::WHITE);
                                let quiet = 4.0;
                                let cell = side / (m.width as f32 + 2.0 * quiet);
                                for y in 0..m.width {
                                    for x in 0..m.width {
                                        if m.dark[y * m.width + x] {
                                            let min = rect.min + vec2((x as f32 + quiet) * cell, (y as f32 + quiet) * cell);
                                            ui.painter().rect_filled(
                                                egui::Rect::from_min_size(min, vec2(cell + 0.3, cell + 0.3)),
                                                0,
                                                Color32::BLACK,
                                            );
                                        }
                                    }
                                }
                                ui.label(RichText::new(format!("Hides in {:.0} s", (until - now).ceil())).size(12.5).color(p.faint));
                                ui.ctx().request_repaint_after(std::time::Duration::from_millis(300));
                                if resp.clicked() {
                                    q.shown_until = None;
                                    q.matrix = None;
                                }
                            }
                            _ => {
                                ui.painter().rect_filled(rect, 8, p.bg);
                                ui.painter().rect_stroke(rect, 8, egui::Stroke::new(1.0_f32, p.border), egui::StrokeKind::Inside);
                                ui.painter().text(rect.center() - vec2(0.0, 14.0), egui::Align2::CENTER_CENTER, Icon::QR.glyph(), regular(40.0), p.muted);
                                ui.painter().text(rect.center() + vec2(0.0, 26.0), egui::Align2::CENTER_CENTER, "Click to show the code", regular(14.0), p.muted);
                                ui.label(RichText::new("Make sure nobody else can see your screen.").size(12.5).color(p.faint));
                                if resp.clicked() {
                                    let payload = q.payload.open_str();
                                    match crate::qr::matrix(payload.as_bytes()) {
                                        Some(m) if !payload.is_empty() => {
                                            q.matrix = Some(m);
                                            q.shown_until = Some(now + QR_SECONDS);
                                        }
                                        _ => sh.toast("This is too long (or empty) to fit in a QR code.", true),
                                    }
                                }
                            }
                        }
                    });
                    ui.add_space(8.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::primary_button(ui, "Close", true).clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::ChangePassword(d) => {
                    let d = &mut **d;
                    ui.set_width(520.0);
                    title(ui, "Master password and protection");
                    para(ui, "Set the master password, the key-stretching strength and the key file this vault uses from now on. The whole vault is encrypted again with new keys.");
                    ui.add_space(6.0);
                    widgets::caption(ui, "Master password (type the current one to keep it)");
                    ui.horizontal(|ui| {
                        widgets::secret_input(ui, &mut d.password, d.show, "", 476.0);
                        let icon = if d.show { Icon::HIDE } else { Icon::VIEW };
                        if widgets::icon_button(ui, icon, "Show or hide").clicked() {
                            d.show = !d.show;
                        }
                    });
                    let empty = d.password.is_empty();
                    let s = d.strength.get(d.password.as_str()).clone();
                    strength_block(ui, &s, empty, 520.0);
                    widgets::caption(ui, "Type it again");
                    widgets::secret_input(ui, &mut d.confirm, d.show, "", 520.0);
                    let matches = d.password.as_str() == d.confirm.as_str();
                    if !d.confirm.is_empty() && !matches {
                        ui.colored_label(p.danger, "The two passwords are different.");
                    }
                    ui.add_space(6.0);
                    widgets::caption(ui, "Key stretching (more memory makes every guess slower, and unlocking too)");
                    let options = [64u32, 128, 256, 512, 1024];
                    let labels = ["64 MiB", "128 MiB", "256 MiB", "512 MiB", "1 GiB"];
                    let current = options.iter().position(|m| *m == d.memory_mib).unwrap_or(2);
                    if let Some(i) = widgets::segmented(ui, &labels, current) {
                        d.memory_mib = options[i];
                    }
                    if let Some(secs) = self.kdf_secs {
                        let scale = f64::from(d.memory_mib) / f64::from(self.v.sealer.kdf.mib().max(1));
                        widgets::note(ui, &format!("Unlocking will take about {:.1} s on this PC.", secs * scale));
                    }
                    ui.add_space(6.0);
                    widgets::caption(ui, "Key file");
                    let choices = [KeyFileChoice::None, KeyFileChoice::New, KeyFileChoice::Existing];
                    let current = choices.iter().position(|c| *c == d.key_choice).unwrap_or(0);
                    if let Some(i) = widgets::segmented(ui, &["No key file", "Make a new one", "Use a file I have"], current) {
                        d.key_choice = choices[i];
                        d.key_path = None;
                    }
                    match d.key_choice {
                        KeyFileChoice::None => {
                            if self.v.sealer.key_file {
                                widgets::note(ui, "The vault will no longer need its key file.");
                            }
                        }
                        KeyFileChoice::New | KeyFileChoice::Existing => {
                            ui.horizontal(|ui| {
                                let label = d.key_path.as_ref().map(|k| k.to_string_lossy().to_string()).unwrap_or_else(|| "Not chosen".into());
                                ui.add_sized(vec2(360.0, 22.0), egui::Label::new(RichText::new(label).color(p.muted)).truncate());
                                if widgets::ghost_button(ui, "Choose…").clicked() {
                                    let picked = if d.key_choice == KeyFileChoice::New {
                                        rfd::FileDialog::new()
                                            .set_title("Where to save the new key file")
                                            .set_file_name(format!("{}.kfkey", self.v.vault.name))
                                            .save_file()
                                    } else {
                                        rfd::FileDialog::new().set_title("Choose the key file").pick_file()
                                    };
                                    if picked.is_some() {
                                        d.key_path = picked;
                                    }
                                }
                            });
                            widgets::note(ui, "Opening the vault will need this file as well as the password. Keep a backup copy of it somewhere safe.");
                        }
                    }
                    if let Some(e) = &d.error {
                        ui.add_space(4.0);
                        widgets::banner(ui, Icon::ERROR, p.danger, e);
                    }
                    let refusal = crate::strength::master_refusal(d.password.as_str(), &s);
                    if !empty {
                        if let Some(r) = refusal {
                            ui.colored_label(p.danger, r);
                        }
                    }
                    ui.add_space(10.0);
                    let ready = refusal.is_none()
                        && matches
                        && !d.busy
                        && (d.key_choice == KeyFileChoice::None || d.key_path.is_some());
                    let mut apply = false;
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if d.busy {
                            ui.label("Encrypting the vault again…");
                            ui.add(egui::Spinner::new().size(20.0).color(p.accent));
                        } else {
                            apply = widgets::primary_button(ui, "Apply", ready).clicked();
                            if widgets::ghost_button(ui, "Cancel").clicked() {
                                close = true;
                            }
                        }
                    });
                    if apply {
                        if sh.demo {
                            sh.toast("This is switched off in the demo.", false);
                            close = true;
                        } else {
                            let mut creds = Credentials {
                                password: d.password.to_secret(),
                                key_file: None,
                            };
                            d.password.wipe();
                            d.confirm.wipe();
                            d.strength.clear();
                            d.busy = true;
                            d.error = None;
                            let kdf = KdfParams {
                                m_kib: d.memory_mib * 1024,
                                t: self.v.sealer.kdf.t.max(3),
                                p: 4,
                            }
                            .clamped();
                            let (choice, key_path) = (d.key_choice, d.key_path.clone());
                            sh.spawn(ui.ctx(), move || {
                                let start = std::time::Instant::now();
                                let key = match (choice, key_path) {
                                    (KeyFileChoice::New, Some(path)) => {
                                        let text = vaultfile::new_key_file();
                                        match std::fs::write(&path, text.as_bytes()) {
                                            Ok(()) => Ok(Some(vaultfile::key_file_digest(text.as_bytes()))),
                                            Err(e) => Err(format!("Could not write the key file: {e}")),
                                        }
                                    }
                                    (KeyFileChoice::Existing, Some(path)) => {
                                        super::start::read_key_file(&path).map(Some)
                                    }
                                    _ => Ok(None),
                                };
                                match key {
                                    Ok(key) => {
                                        creds.key_file = key;
                                        Msg::NewSealer(Sealer::create(&mut creds, kdf), start.elapsed().as_secs_f64())
                                    }
                                    Err(e) => {
                                        creds.wipe();
                                        Msg::NewSealer(Err(VaultError::Internal(e)), 0.0)
                                    }
                                }
                            });
                        }
                    }
                }
                Dialog::Export(d) => {
                    let d = &mut **d;
                    ui.set_width(540.0);
                    title(ui, "Export");
                    widgets::section(ui, "Encrypted copy (recommended)");
                    para(ui, "A complete copy of the vault as a .kfv file, for a backup or another PC. Leave the password empty to keep the current master password, or set a different one for this copy.");
                    ui.horizontal(|ui| {
                        widgets::secret_input(ui, &mut d.password, d.show, "New password for the copy (optional)", 244.0);
                        widgets::secret_input(ui, &mut d.confirm, d.show, "Again", 244.0);
                        let icon = if d.show { Icon::HIDE } else { Icon::VIEW };
                        if widgets::icon_button(ui, icon, "Show or hide").clicked() {
                            d.show = !d.show;
                        }
                    });
                    let same = d.password.as_str() == d.confirm.as_str();
                    let long_enough = d.password.is_empty() || d.password.as_str().chars().count() >= 8;
                    if !same {
                        ui.colored_label(p.danger, "The two passwords are different.");
                    } else if !long_enough {
                        ui.colored_label(p.danger, "Use at least 8 characters.");
                    }
                    if self.v.sealer.key_file && d.password.is_empty() {
                        widgets::note(ui, "The copy will need the same key file as this vault.");
                    }
                    if widgets::primary_button(ui, "Save encrypted copy…", same && long_enough && !d.busy).clicked() {
                        let pw = (!d.password.is_empty()).then(|| d.password.to_secret());
                        d.password.wipe();
                        d.confirm.wipe();
                        self.export_encrypted(ui.ctx(), sh, pw);
                        close = true;
                    }
                    ui.add_space(8.0);
                    widgets::divider(ui);
                    ui.add_space(6.0);
                    widgets::section(ui, "Unencrypted file");
                    widgets::banner(ui, Icon::WARNING, p.danger, "An unencrypted export contains every password in readable form. Anyone who gets the file, and any program on this PC, can read it. Only do this to move to another program, and delete the file right after.");
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if widgets::ghost_button(ui, "Export as CSV…").clicked() {
                            next = Some(Dialog::confirm(
                                "Export everything unencrypted?",
                                "The CSV file will contain all your passwords in readable form. Keep it only as long as you need it, never in a synced or shared folder, and delete it afterwards.",
                                "Export unencrypted",
                                ConfirmAction::ExportPlain(false),
                            ));
                        }
                        if widgets::ghost_button(ui, "Export as JSON…").clicked() {
                            next = Some(Dialog::confirm(
                                "Export everything unencrypted?",
                                "The JSON file will contain all your passwords, notes and hidden fields in readable form. Keep it only as long as you need it, never in a synced or shared folder, and delete it afterwards.",
                                "Export unencrypted",
                                ConfirmAction::ExportPlain(true),
                            ));
                        }
                    });
                    widgets::note(ui, "CSV opens in spreadsheets and other managers. JSON keeps everything (custom fields, history, recovery codes). Attachments are not exported.");
                    ui.add_space(10.0);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::ghost_button(ui, "Close").clicked() {
                            close = true;
                        }
                    });
                }
                Dialog::Import(d) => {
                    let d = &mut **d;
                    ui.set_width(660.0);
                    title(ui, "Import");
                    let file_name = d.path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
                    if let Some(e) = &d.error {
                        widgets::banner(ui, Icon::ERROR, p.danger, e);
                        ui.add_space(10.0);
                        if widgets::ghost_button(ui, "Close").clicked() {
                            close = true;
                        }
                    } else if let Some(loaded) = &mut d.loaded {
                        para(ui, &format!("File: {file_name}"));
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Recognised as:").color(p.muted));
                            ui.label(RichText::new(loaded.format.label()).font(semibold(14.0)));
                        });
                        // Column mapping for files KeepForge does not recognise.
                        if loaded.format == Format::Generic {
                            if let Some(table) = &loaded.table {
                                let mut changed = false;
                                ui.add_space(4.0);
                                egui::Grid::new("mapping").num_columns(4).spacing(vec2(10.0, 6.0)).show(ui, |ui| {
                                    let m = &mut loaded.mapping;
                                    let slots: [(&str, &mut Option<usize>); 7] = [
                                        ("Title", &mut m.title),
                                        ("User name", &mut m.username),
                                        ("Password", &mut m.password),
                                        ("Web address", &mut m.url),
                                        ("Notes", &mut m.notes),
                                        ("One-time code", &mut m.totp),
                                        ("Folder", &mut m.folder),
                                    ];
                                    for (n, (label, slot)) in slots.into_iter().enumerate() {
                                        ui.label(RichText::new(label).color(p.muted));
                                        let text = slot.and_then(|i| table.header.get(i)).cloned().unwrap_or_else(|| "(not used)".into());
                                        egui::ComboBox::from_id_salt(("map", n))
                                            .selected_text(text)
                                            .width(180.0)
                                            .show_ui(ui, |ui| {
                                                if ui.selectable_label(slot.is_none(), "(not used)").clicked() {
                                                    *slot = None;
                                                    changed = true;
                                                }
                                                for (i, h) in table.header.iter().enumerate() {
                                                    if ui.selectable_label(*slot == Some(i), h).clicked() {
                                                        *slot = Some(i);
                                                        changed = true;
                                                    }
                                                }
                                            });
                                        if n % 2 == 1 {
                                            ui.end_row();
                                        }
                                    }
                                });
                                if changed {
                                    loaded.drafts = import::drafts_from_csv(table, Format::Generic, &loaded.mapping);
                                    d.duplicates = import::find_duplicates(&self.v.vault, &loaded.drafts);
                                }
                            }
                        }
                        ui.add_space(6.0);
                        let total = loaded.drafts.len();
                        let dup = d.duplicates.iter().filter(|x| **x).count();
                        ui.horizontal_wrapped(|ui| {
                            widgets::badge(ui, &format!("{total} entries"), p.accent);
                            for kind in Kind::ALL {
                                let n = loaded.drafts.iter().filter(|x| x.kind == kind).count();
                                if n > 0 {
                                    widgets::badge(ui, &format!("{n} {}", kind.plural().to_lowercase()), p.info);
                                }
                            }
                            if dup > 0 {
                                widgets::badge(ui, &format!("{dup} already in the vault"), p.warn);
                            }
                        });
                        ui.add_space(4.0);
                        // Preview: no passwords are shown.
                        egui::Frame::new().fill(p.bg).corner_radius(10).inner_margin(10).show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            egui::ScrollArea::vertical().max_height(210.0).show(ui, |ui| {
                                egui::Grid::new("preview").num_columns(4).striped(false).spacing(vec2(14.0, 4.0)).show(ui, |ui| {
                                    for head in ["Title", "User name", "Web address", "Password"] {
                                        ui.label(RichText::new(head).size(12.0).color(p.faint));
                                    }
                                    ui.end_row();
                                    for (n, draft) in loaded.drafts.iter().enumerate().take(200) {
                                        let color = if d.duplicates.get(n).copied().unwrap_or(false) && d.skip_duplicates { p.faint } else { p.text };
                                        ui.label(RichText::new(crate::util::truncate(&draft.title, 30)).color(color));
                                        ui.label(RichText::new(crate::util::truncate(&draft.username, 26)).color(color));
                                        ui.label(RichText::new(crate::util::truncate(&draft.urls.first().map(|u| crate::util::host_of(u)).unwrap_or_default(), 26)).color(color));
                                        ui.label(RichText::new(if draft.password.is_empty() { "none" } else { "••••••" }).color(p.faint));
                                        ui.end_row();
                                    }
                                });
                                if total > 200 {
                                    ui.label(RichText::new(format!("… and {} more", total - 200)).color(p.faint));
                                }
                            });
                        });
                        if dup > 0 {
                            widgets::checkbox(ui, &mut d.skip_duplicates, &format!("Skip the {dup} entries that are already in the vault"));
                        }
                        ui.add_space(10.0);
                        let count = if d.skip_duplicates { total - dup } else { total };
                        let mut do_import = false;
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            do_import = widgets::primary_button(ui, &format!("Import {count} entries"), count > 0).clicked();
                            if widgets::ghost_button(ui, "Cancel").clicked() {
                                close = true;
                            }
                        });
                        if do_import {
                            let skip: Vec<bool> = if d.skip_duplicates { d.duplicates.clone() } else { Vec::new() };
                            let session = self.v.session.clone();
                            let added = import::apply(&mut self.v.vault, &session, &loaded.drafts, &skip, sh.now);
                            sh.toast(format!("{added} entries imported"), false);
                            self.changed(ui.ctx(), sh);
                            close = true;
                            next = Some(Dialog::confirm(
                                "Delete the export file?",
                                &format!("\"{file_name}\" still contains your passwords unencrypted. KeepForge can overwrite and delete it now. (On SSDs and in synced folders, traces can survive; see Tools › Secure shred.)"),
                                "Overwrite and delete it",
                                ConfirmAction::ShredFile(d.path.clone()),
                            ));
                        }
                    } else {
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().size(20.0).color(p.accent));
                            ui.label(format!("Reading {file_name}…"));
                        });
                        ui.add_space(10.0);
                        if widgets::ghost_button(ui, "Cancel").clicked() {
                            close = true;
                        }
                    }
                }
                Dialog::Online(what, dont_ask) => {
                    ui.set_width(540.0);
                    let (heading, sent, not_sent, service) = match what {
                        Online::Emails(list) => (
                            "This lookup goes online",
                            if list.len() == 1 {
                                format!("The email address {} is sent to xposedornot.com over an encrypted (HTTPS) connection.", list[0])
                            } else {
                                format!("{} email addresses from your vault are sent, one at a time, to xposedornot.com over an encrypted (HTTPS) connection.", list.len())
                            },
                            "No passwords and nothing else from your vault are sent.",
                            "XposedOrNot is an independent breach-notification service. It will see the address and your IP address.",
                        ),
                        Online::Ip(ip) => (
                            "This lookup goes online",
                            format!("The IP address {ip} and your API key are sent to the iknowwhatyoudownload.com Peer API over an encrypted (HTTPS) connection."),
                            "Nothing from your vault is sent.",
                            "The service will see the address you ask about, your key and your own IP address.",
                        ),
                        Online::Passwords => (
                            "Check passwords against known breaches?",
                            "For each password, KeepForge computes a SHA-1 hash on this PC and sends only its first 5 characters to api.pwnedpasswords.com over an encrypted (HTTPS) connection. About a million different passwords share those 5 characters.".to_string(),
                            "Your passwords, the full hashes, user names and site names are never sent. The match is made on this PC.",
                            "The service will see the 5-character prefixes and your IP address.",
                        ),
                    };
                    title(ui, heading);
                    ui.label(RichText::new("What is sent").font(semibold(14.0)));
                    para(ui, &sent);
                    ui.add_space(4.0);
                    ui.label(RichText::new("What is not sent").font(semibold(14.0)));
                    para(ui, not_sent);
                    ui.add_space(4.0);
                    para(ui, service);
                    para(ui, "Results are kept in memory until you lock the vault; nothing is looked up in the background.");
                    ui.add_space(8.0);
                    widgets::checkbox(ui, dont_ask, "Don't ask again for this kind of lookup");
                    ui.add_space(10.0);
                    let mut proceed = false;
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        proceed = widgets::primary_button(ui, "Continue", true).clicked();
                        if widgets::ghost_button(ui, "Cancel").clicked() {
                            close = true;
                        }
                    });
                    if proceed {
                        close = true;
                        confirmed = true;
                    }
                }
            });
        if modal.should_close() {
            let busy = matches!(&dialog, Dialog::ChangePassword(d) if d.busy);
            if !busy {
                close = true;
            }
        }
        if !close {
            self.dialog = Some(dialog);
            return go;
        }
        // Closed: run what was confirmed, then show a follow-up dialog if any.
        match dialog {
            Dialog::Confirm { action, .. } if confirmed => self.run_confirmed(ctx, sh, action),
            Dialog::Online(what, dont_ask) if confirmed => {
                self.online_confirmed(ctx, sh, what, dont_ask)
            }
            _ => {}
        }
        if next.is_some() {
            self.dialog = next;
        }
        go
    }

    fn online_confirmed(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        what: Online,
        dont_ask: bool,
    ) {
        match what {
            Online::Emails(list) => {
                sh.settings.email_lookup_ack |= dont_ask;
                self.start_email_lookup(ctx, sh, list);
            }
            Online::Ip(ip) => {
                sh.settings.ip_lookup_ack |= dont_ask;
                self.start_peer_lookup(ctx, sh, &ip);
            }
            Online::Passwords => {
                sh.settings.breach_check = true;
                self.start_pwned_scan(ctx, sh);
            }
        }
    }

    pub(super) fn save_emergency_sheet(&mut self, sh: &mut Shared) {
        if sh.demo {
            sh.toast("Saving files is switched off in the demo.", false);
            return;
        }
        let Some(mut path) = rfd::FileDialog::new()
            .set_title("Save the emergency sheet")
            .set_file_name(format!("{} emergency sheet.html", self.v.vault.name))
            .add_filter("Web page", &["html"])
            .save_file()
        else {
            return;
        };
        if path.extension().is_none() {
            path.set_extension("html");
        }
        let vault_path = self
            .v
            .path
            .as_ref()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let page = crate::emergency::html(
            &self.v.vault.name,
            &vault_path,
            self.v.sealer.key_file,
            &self.v.sealer.kdf.describe(),
            sh.now,
        );
        match std::fs::write(&path, page) {
            Ok(()) => {
                sh.toast(
                    "Saved. Open the file in your browser, print it, then fill it in by hand.",
                    false,
                );
                if let Some(folder) = path.parent() {
                    let _ = crate::sys::open_folder(folder);
                }
            }
            Err(e) => sh.toast(format!("Could not save the sheet: {e}"), true),
        }
    }
}
