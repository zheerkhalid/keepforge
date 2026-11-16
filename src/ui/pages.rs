//! The full-width pages: security dashboard, breach lookup, authenticator,
//! generator and settings.

use super::app::{Go, Msg, Shared};
use super::dialogs::{Dialog, Online};
use super::edit::generator_options;
use super::main_view::{Main, Nav};
use super::start::StrengthCache;
use super::theme::{pal, regular, semibold, Icon};
use super::widgets;
use crate::breach::{Breach, BreachError, EmailResult};
use crate::generator::{self, OsRng};
use crate::model::{Id, Kind, Vault};
use crate::secret::SecretInput;
use crate::settings::ThemeChoice;
use crate::torrent::{PeerError, PeerReport};
use crate::util;
use eframe::egui::{
    self, vec2, Align, Align2, Color32, CornerRadius, Frame, Layout, Margin, Rect, RichText, Sense,
    Stroke, Ui,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub struct PageState {
    // Breach lookup
    pub email_input: String,
    pub email_results: Vec<(String, Result<EmailResult, String>)>,
    pub email_queue: Option<(usize, usize)>,
    pub email_cancel: Arc<AtomicBool>,
    flag_cache: Option<(u64, usize, Vec<Id>)>,
    pub pw_check: SecretInput,
    pub pw_check_result: Option<Result<u64, String>>,
    pub pw_check_busy: bool,
    // Torrent exposure check
    pub ip_input: String,
    pub peer: Option<Result<PeerReport, String>>,
    pub peer_busy: bool,
    pub peer_key: SecretInput,
    pub peer_host: String,
    pub peer_setup: bool,
    pub show_adult: bool,
    // Generator page
    pub gen_value: SecretInput,
    gen_strength: StrengthCache,
    // Authenticator
    pub auth_search: String,
    // Settings
    hotkey_text: Option<String>,
}

impl Default for PageState {
    fn default() -> Self {
        PageState {
            email_input: String::new(),
            email_results: Vec::new(),
            email_queue: None,
            email_cancel: Arc::new(AtomicBool::new(false)),
            flag_cache: None,
            pw_check: SecretInput::new(),
            pw_check_result: None,
            pw_check_busy: false,
            ip_input: String::new(),
            peer: None,
            peer_busy: false,
            peer_key: SecretInput::new(),
            peer_host: String::new(),
            peer_setup: false,
            show_adult: false,
            gen_value: SecretInput::new(),
            gen_strength: StrengthCache::default(),
            auth_search: String::new(),
            hotkey_text: None,
        }
    }
}

impl PageState {
    pub fn email_result(&mut self, email: String, result: Result<EmailResult, BreachError>) {
        self.email_results.retain(|(e, _)| *e != email);
        self.email_results
            .insert(0, (email, result.map_err(|e| e.to_string())));
        self.flag_cache = None;
        if let Some((done, _)) = &mut self.email_queue {
            *done += 1;
        }
    }

    pub fn email_done(&mut self) {
        self.email_queue = None;
    }

    pub fn peer_result(&mut self, result: Result<PeerReport, PeerError>) {
        self.peer_busy = false;
        self.peer = Some(result.map_err(|e| e.to_string()));
    }

    fn breaches(&self) -> impl Iterator<Item = &Breach> {
        self.email_results.iter().flat_map(|(_, r)| match r {
            Ok(EmailResult::Found(list)) => list.iter(),
            _ => [].iter(),
        })
    }

    /// Logins whose site was breached after the password was last changed.
    pub fn flagged(&mut self, vault: &Vault, rev: u64) -> Vec<Id> {
        let key = (rev, self.email_results.len());
        if let Some((r, n, ids)) = &self.flag_cache {
            if (*r, *n) == key {
                return ids.clone();
            }
        }
        let ids = crate::breach::items_to_change(vault, self.breaches());
        self.flag_cache = Some((key.0, key.1, ids.clone()));
        ids
    }
}

pub(super) fn page_header(ui: &mut Ui, title: &str, subtitle: &str, actions: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            ui.label(RichText::new(title).font(semibold(24.0)));
            ui.label(RichText::new(subtitle).color(p.muted));
        });
        ui.with_layout(Layout::right_to_left(Align::Center), actions);
    });
    ui.add_space(6.0);
}

/// A settings-style row: title and explanation on the left, control on the right.
fn setting(ui: &mut Ui, title: &str, text: &str, control: impl FnOnce(&mut Ui)) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_width((ui.available_width() - 340.0).max(200.0));
            ui.spacing_mut().item_spacing.y = 1.0;
            ui.label(RichText::new(title).font(regular(14.5)));
            if !text.is_empty() {
                ui.add(egui::Label::new(RichText::new(text).size(12.5).color(p.muted)).wrap());
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), control);
    });
}

fn toggle_row(ui: &mut Ui, title: &str, text: &str, value: &mut bool) {
    let mut v = *value;
    setting(ui, title, text, |ui| {
        if widgets::toggle(ui, v, true).clicked() {
            v = !v;
        }
    });
    *value = v;
}

fn choice_row<T: Copy + PartialEq>(
    ui: &mut Ui,
    title: &str,
    text: &str,
    value: &mut T,
    options: &[(T, &str)],
) {
    let labels: Vec<&str> = options.iter().map(|(_, l)| *l).collect();
    let current = options.iter().position(|(v, _)| v == value);
    let mut picked = None;
    setting(ui, title, text, |ui| {
        picked = widgets::segmented(ui, &labels, current.unwrap_or(usize::MAX));
    });
    if let Some(i) = picked {
        *value = options[i].0;
    }
}

fn stat_tile(ui: &mut Ui, width: f32, value: &str, label: &str, color: Color32) {
    let p = pal(ui);
    Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0_f32, p.border))
        .corner_radius(CornerRadius::same(12))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.set_width(width - 28.0);
            ui.set_min_height(104.0);
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.add_space(18.0);
                ui.label(RichText::new(value).font(semibold(30.0)).color(color));
                ui.label(RichText::new(label).size(12.5).color(p.muted));
            });
        });
}

impl Main {
    // ----------------------------------------------------------------------------------
    // Online checks
    // ----------------------------------------------------------------------------------

    /// Asks (unless the user said not to) and then looks the addresses up.
    pub(super) fn request_email_lookup(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        emails: Vec<String>,
    ) {
        let emails: Vec<String> = emails
            .into_iter()
            .map(|e| e.trim().to_lowercase())
            .filter(|e| crate::model::looks_like_email(e))
            .collect();
        if emails.is_empty() {
            sh.toast("Type an email address first.", true);
            return;
        }
        if sh.demo || sh.settings.email_lookup_ack {
            self.start_email_lookup(ctx, sh, emails);
        } else {
            self.dialog = Some(Dialog::Online(Online::Emails(emails), false));
        }
    }

    pub(super) fn start_email_lookup(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        emails: Vec<String>,
    ) {
        if self.pages.email_queue.is_some() {
            return;
        }
        if sh.demo {
            // The demo never goes online: invented results.
            for email in emails {
                let result = if email == crate::demo::DEMO_EMAIL {
                    EmailResult::Found(crate::demo::breaches())
                } else {
                    EmailResult::NotFound
                };
                self.pages.email_result(email, Ok(result));
            }
            return;
        }
        self.pages.email_cancel = Arc::new(AtomicBool::new(false));
        self.pages.email_queue = Some((0, emails.len()));
        let (tx, cancel, ctx) = (sh.tx.clone(), self.pages.email_cancel.clone(), ctx.clone());
        std::thread::spawn(move || {
            let mut throttle =
                crate::net::Throttle::new(std::time::Duration::from_millis(crate::breach::GAP_MS));
            for email in emails {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                throttle.pace();
                let result = crate::breach::lookup(&email);
                let stop = matches!(result, Err(BreachError::RateLimited));
                let _ = tx.send(Msg::Email(email, result));
                ctx.request_repaint();
                if stop {
                    break;
                }
            }
            let _ = tx.send(Msg::EmailDone);
            ctx.request_repaint();
        });
    }

    pub(super) fn request_pwned_scan(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        if sh.demo || sh.settings.breach_check {
            self.start_pwned_scan(ctx, sh);
        } else {
            self.dialog = Some(Dialog::Online(Online::Passwords, false));
        }
    }

    pub(super) fn start_pwned_scan(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        if self.pwned_progress.is_some() {
            return;
        }
        self.pwned.clear();
        self.pwned_error = None;
        self.pwned_done = false;
        let items: Vec<(Id, crate::secret::Protected)> = self
            .v
            .vault
            .items
            .iter()
            .filter(|i| {
                !i.in_trash()
                    && matches!(i.kind, Kind::Login | Kind::Wifi)
                    && !i.password.is_empty()
            })
            .map(|i| (i.id, i.password.clone()))
            .collect();
        if sh.demo {
            for i in &self.v.vault.items {
                match i.title.as_str() {
                    "Pixel Forum" => drop(self.pwned.insert(i.id, 184_320)),
                    "Photo Cloud" => drop(self.pwned.insert(i.id, 37)),
                    _ => {}
                }
            }
            self.pwned_done = true;
            return;
        }
        self.pwned_cancel = Arc::new(AtomicBool::new(false));
        self.pwned_progress = Some((0, items.len()));
        let (tx, cancel, ranges, ctx) = (
            sh.tx.clone(),
            self.pwned_cancel.clone(),
            self.ranges.clone(),
            ctx.clone(),
        );
        std::thread::spawn(move || {
            for (id, secret) in items {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let Ok(password) = secret.open() else { break };
                let text = String::from_utf8_lossy(&password).into_owned();
                let text = zeroize::Zeroizing::new(text);
                let result = match ranges.lock() {
                    Ok(mut cache) => cache.check(&text),
                    Err(_) => Err("Internal error.".to_string()),
                };
                let failed = result.is_err();
                let _ = tx.send(Msg::Pwned(id, result));
                ctx.request_repaint();
                if failed {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(120));
            }
            let _ = tx.send(Msg::PwnedDone);
            ctx.request_repaint();
        });
    }

    pub(super) fn request_peer_lookup(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        let ip = self.pages.ip_input.trim().to_string();
        match crate::torrent::validate_ip(&ip) {
            Err(problem) => {
                self.pages.peer = Some(Err(problem.to_string()));
            }
            Ok(_) => {
                if sh.demo || sh.settings.ip_lookup_ack {
                    self.start_peer_lookup(ctx, sh, &ip);
                } else {
                    self.dialog = Some(Dialog::Online(Online::Ip(ip), false));
                }
            }
        }
    }

    pub(super) fn start_peer_lookup(&mut self, ctx: &egui::Context, sh: &mut Shared, ip: &str) {
        if self.pages.peer_busy {
            return;
        }
        let Ok(addr) = crate::torrent::validate_ip(ip) else {
            return;
        };
        if sh.demo {
            let mut report = crate::demo::peer_report();
            report.ip = addr.to_string();
            self.pages.peer = Some(Ok(report));
            return;
        }
        let Some(key) = self.v.vault.service_key(crate::torrent::SERVICE_KEY) else {
            self.pages.peer = Some(Err(PeerError::NoKey.to_string()));
            return;
        };
        let key = key.open_str();
        let host = self
            .v
            .vault
            .service_key(crate::torrent::SERVICE_HOST)
            .map(|h| h.open_str().to_string())
            .unwrap_or_else(|| crate::torrent::DEFAULT_HOST.to_string());
        self.pages.peer_busy = true;
        self.pages.peer = None;
        sh.spawn(ctx, move || {
            // At most one request every two seconds.
            static LAST: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
            if let Ok(mut last) = LAST.lock() {
                if let Some(t) = *last {
                    let gap = std::time::Duration::from_millis(crate::torrent::GAP_MS);
                    let since = t.elapsed();
                    if since < gap {
                        std::thread::sleep(gap - since);
                    }
                }
                *last = Some(std::time::Instant::now());
            }
            Msg::Peer(crate::torrent::lookup(&host, addr, 14, &key))
        });
    }

    // ----------------------------------------------------------------------------------
    // Security dashboard
    // ----------------------------------------------------------------------------------

    fn item_line(&mut self, ui: &mut Ui, id: Id, reason: &str, color: Color32) {
        let p = pal(ui);
        let Some(item) = self.v.vault.item(id) else {
            return;
        };
        let title = item.title.clone();
        let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 40.0), Sense::click());
        if resp.hovered() {
            ui.painter()
                .rect_filled(rect, CornerRadius::same(8), p.hover);
        }
        widgets::letter_tile(
            ui,
            Rect::from_min_size(rect.min + vec2(6.0, 6.0), vec2(28.0, 28.0)),
            &title,
        );
        widgets::text_in(
            ui,
            Rect::from_min_max(
                rect.min + vec2(44.0, 0.0),
                egui::pos2(rect.left() + 300.0, rect.bottom()),
            ),
            &title,
            regular(14.5),
            p.text,
        );
        widgets::text_in(
            ui,
            Rect::from_min_max(
                egui::pos2(rect.left() + 310.0, rect.top()),
                rect.max - vec2(70.0, 0.0),
            ),
            reason,
            regular(13.0),
            color,
        );
        ui.painter().text(
            rect.right_center() - vec2(12.0, 0.0),
            Align2::RIGHT_CENTER,
            format!("Open {}", Icon::CHEVRON_RIGHT.glyph()),
            regular(12.5),
            p.accent,
        );
        if resp
            .on_hover_cursor(egui::CursorIcon::PointingHand)
            .clicked()
        {
            self.go_to_item(id);
        }
    }

    pub(super) fn health_ui(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        self.ensure_health(&ctx, sh);
        let mut scan = false;
        let scanning = self.pwned_progress;
        page_header(
            ui,
            "Security dashboard",
            "How your passwords are doing, worked out on this PC",
            |ui| {
                if scanning.is_none()
                    && widgets::ghost_button(
                        ui,
                        &Icon::GLOBE.with("Check passwords against known breaches"),
                    )
                    .clicked()
                {
                    scan = true;
                }
            },
        );
        if scan {
            self.request_pwned_scan(&ctx, sh);
        }
        let Some((_, report)) = self.health.clone() else {
            widgets::busy_state(ui, "Looking through your passwords…", "");
            return;
        };
        let flagged = self.pages.flagged(&self.v.vault, self.rev);
        let mut breached: Vec<Id> = self.pwned.keys().copied().collect();
        for id in &flagged {
            if !breached.contains(id) {
                breached.push(*id);
            }
        }
        let score = report.score(breached.len());
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width((ui.available_width() - 12.0).min(940.0));
            ui.spacing_mut().item_spacing.y = 12.0;
            let full = ui.available_width();

            // Summary: score ring and counts.
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = 12.0;
                Frame::new()
                    .fill(p.card)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .corner_radius(CornerRadius::same(12))
                    .inner_margin(Margin::same(16))
                    .show(ui, |ui| {
                        ui.set_width(268.0);
                        ui.horizontal(|ui| {
                            let color = match score {
                                90..=100 => p.accent,
                                75..=89 => p.info,
                                50..=74 => p.warn,
                                _ => p.danger,
                            };
                            let (rect, _) = ui.allocate_exact_size(vec2(92.0, 92.0), Sense::hover());
                            widgets::paint_ring(ui, rect.center(), 40.0, 8.0, score as f32 / 100.0, color);
                            ui.painter().text(rect.center(), Align2::CENTER_CENTER, score.to_string(), semibold(28.0), p.text);
                            ui.vertical(|ui| {
                                ui.add_space(14.0);
                                ui.spacing_mut().item_spacing.y = 2.0;
                                ui.label(RichText::new(crate::health::score_label(score)).font(semibold(18.0)).color(color));
                                ui.label(RichText::new("Overall score").color(p.muted));
                                ui.label(RichText::new(format!("{} passwords checked", report.checked)).size(12.5).color(p.faint));
                            });
                        });
                    });
                let tile_w = ((full - 302.0 - 12.0 * 5.0) / 5.0).floor();
                let tiles: [(usize, &str, Color32); 5] = [
                    (report.weak.len(), "Weak", p.danger),
                    (report.reused_count(), "Reused", p.warn),
                    (report.old.len(), "Old", p.info),
                    (breached.len(), "Breached", p.danger),
                    (report.expiring.len() + report.expired.len(), "Expiring", p.warn),
                ];
                for (n, label, color) in tiles {
                    stat_tile(ui, tile_w, &n.to_string(), label, if n == 0 { p.muted } else { color });
                }
            });

            if let Some((done, total)) = self.pwned_progress {
                widgets::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(18.0).color(p.accent));
                        ui.label(format!("Checking passwords against known breaches: {done} of {total}"));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if widgets::ghost_button(ui, "Cancel").clicked() {
                                self.pwned_cancel.store(true, Ordering::Relaxed);
                            }
                        });
                    });
                    let w = ui.available_width();
                    widgets::progress_bar(ui, done as f32 / total.max(1) as f32, w, p.accent);
                });
            }
            if let Some(e) = &self.pwned_error {
                widgets::banner(ui, Icon::ERROR, p.danger, e);
            }

            // Protection status with one-click fixes.
            widgets::card(ui, |ui| {
                widgets::section(ui, "Protection");
                ui.add_space(2.0);
                let status = |ui: &mut Ui, ok: bool, title: &str, text: &str, fix: Option<&str>| -> bool {
                    let mut clicked = false;
                    ui.horizontal(|ui| {
                        let (icon, color) = if ok { (Icon::DONE, p.accent) } else { (Icon::WARNING, p.warn) };
                        ui.label(RichText::new(icon.glyph()).color(color));
                        ui.vertical(|ui| {
                            ui.set_width(ui.available_width() - 150.0);
                            ui.spacing_mut().item_spacing.y = 0.0;
                            ui.label(RichText::new(title).size(14.5));
                            ui.add(egui::Label::new(RichText::new(text).size(12.5).color(p.muted)).wrap());
                        });
                        if let Some(label) = fix {
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                clicked = widgets::ghost_button(ui, label).clicked();
                            });
                        }
                    });
                    clicked
                };
                let kdf = self.v.sealer.kdf;
                let secs = self.kdf_secs.unwrap_or(0.0);
                status(
                    ui,
                    secs >= 0.1 || self.kdf_secs.is_none(),
                    "Key stretching",
                    &match self.kdf_secs {
                        Some(s) => format!("{} ({})", crate::health::kdf_words(s), kdf.describe()),
                        None => kdf.describe(),
                    },
                    None,
                );
                if status(
                    ui,
                    sh.settings.auto_lock_minutes > 0,
                    "Auto-lock",
                    &match sh.settings.auto_lock_minutes {
                        0 => "Off: the vault stays open until you lock it.".to_string(),
                        m => format!("Locks after {m} minutes without activity."),
                    },
                    (sh.settings.auto_lock_minutes == 0).then_some("Turn on (5 min)"),
                ) {
                    sh.settings.auto_lock_minutes = 5;
                }
                if status(
                    ui,
                    sh.settings.clipboard_seconds > 0,
                    "Clipboard",
                    &match sh.settings.clipboard_seconds {
                        0 => "Copied passwords stay on the clipboard until something replaces them.".to_string(),
                        s => format!("Copied secrets are cleared after {s} seconds and kept out of clipboard history."),
                    },
                    (sh.settings.clipboard_seconds == 0).then_some("Turn on (20 s)"),
                ) {
                    sh.settings.clipboard_seconds = 20;
                }
                if status(
                    ui,
                    sh.settings.hide_from_capture,
                    "Screen capture",
                    if sh.settings.hide_from_capture {
                        "The window is hidden from screenshots, recordings and screen sharing."
                    } else {
                        "The window can be captured by screenshots and screen sharing."
                    },
                    (!sh.settings.hide_from_capture).then_some("Hide the window"),
                ) {
                    sh.settings.hide_from_capture = true;
                }
                let backup_text = if sh.demo {
                    "5 rolling backups are kept next to the vault file. Last backup: today.".to_string()
                } else if sh.settings.backups == 0 {
                    "No backups are kept. A damaged or wrongly synced file could not be recovered.".to_string()
                } else {
                    let last = (1..=sh.settings.backups)
                        .filter_map(|n| self.v.path.as_ref().map(|p| crate::store::backup_path(p, n)))
                        .filter_map(|b| std::fs::metadata(b).ok()?.modified().ok())
                        .max()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs() as i64);
                    match last {
                        Some(t) => format!("{} rolling backups are kept next to the vault file. Last backup: {}.", sh.settings.backups, util::fmt_datetime(t)),
                        None => format!("{} rolling backups will be kept next to the vault file. None has been made yet.", sh.settings.backups),
                    }
                };
                if status(ui, sh.settings.backups > 0, "Backups", &backup_text, (sh.settings.backups == 0).then_some("Keep 5 backups")) {
                    sh.settings.backups = 5;
                }
            });

            // Problem lists.
            let mut any = false;
            if !breached.is_empty() {
                any = true;
                widgets::card(ui, |ui| {
                    widgets::section(ui, "Breached");
                    widgets::note(ui, "These passwords are known to attackers, or the site was breached after you last changed the password. Change them first.");
                    for id in &breached {
                        let reason = match self.pwned.get(id) {
                            Some(n) => format!("Password seen {} times in breaches", util::thousands(*n)),
                            None => "Site breached since the last password change".to_string(),
                        };
                        self.item_line(ui, *id, &reason, p.danger);
                    }
                });
            }
            if !report.weak.is_empty() {
                any = true;
                widgets::card(ui, |ui| {
                    widgets::section(ui, "Weak passwords");
                    widgets::note(ui, "Easy to guess. Replace them with generated ones.");
                    for (id, score) in &report.weak {
                        self.item_line(ui, *id, crate::strength::score_label(*score), p.warn);
                    }
                });
            }
            if !report.reused.is_empty() {
                any = true;
                widgets::card(ui, |ui| {
                    widgets::section(ui, "Reused passwords");
                    widgets::note(ui, "If one of these sites leaks, the others are open too. Give each its own password.");
                    for (n, group) in report.reused.iter().enumerate() {
                        if n > 0 {
                            widgets::divider(ui);
                        }
                        for id in group {
                            self.item_line(ui, *id, &format!("Same password as {} other(s)", group.len() - 1), p.warn);
                        }
                    }
                });
            }
            if !report.expired.is_empty() || !report.expiring.is_empty() {
                any = true;
                widgets::card(ui, |ui| {
                    widgets::section(ui, "Expiring");
                    for (id, when) in &report.expired {
                        self.item_line(ui, *id, &format!("Expired on {}", util::fmt_date(*when - 1)), p.danger);
                    }
                    for (id, when) in &report.expiring {
                        self.item_line(ui, *id, &format!("Expires on {}", util::fmt_date(*when - 1)), p.warn);
                    }
                });
            }
            if !report.old.is_empty() {
                any = true;
                widgets::card(ui, |ui| {
                    widgets::section(ui, "Old passwords");
                    widgets::note(ui, &format!("Not changed in over {} months. Worth renewing for important accounts.", sh.settings.old_password_months));
                    for id in &report.old {
                        let changed = self.v.vault.item(*id).map(|i| i.password_changed).unwrap_or(0);
                        self.item_line(ui, *id, &format!("Changed {}", util::ago(changed, sh.now)), p.info);
                    }
                });
            }
            if !report.empty.is_empty() || !report.no_url.is_empty() {
                widgets::card(ui, |ui| {
                    widgets::section(ui, "Housekeeping");
                    for id in &report.empty {
                        self.item_line(ui, *id, "No password saved", p.muted);
                    }
                    for id in report.no_url.iter().filter(|id| !report.empty.contains(id)) {
                        self.item_line(ui, *id, "No web address", p.muted);
                    }
                });
            }
            if !any {
                widgets::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(Icon::DONE.glyph()).size(20.0).color(p.accent));
                        ui.label(RichText::new("No weak, reused, old or expiring passwords found.").size(15.0));
                    });
                });
            }
            if !self.pwned_done && self.pwned_progress.is_none() {
                widgets::note(ui, "\"Breached\" counts what the two optional online checks have found in this session: the password check above (which sends only a 5-character hash prefix) and the Breach lookup page.");
            }
            ui.add_space(8.0);
        });
    }

    // ----------------------------------------------------------------------------------
    // Breach lookup
    // ----------------------------------------------------------------------------------

    pub(super) fn breach_ui(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        page_header(
            ui,
            "Breach lookup",
            "See which known data breaches include your email address",
            |_| {},
        );
        let mut lookup: Option<Vec<String>> = None;
        let mut check_pw = false;
        let vault_emails = self.v.vault.emails();
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width((ui.available_width() - 12.0).min(940.0));
            ui.spacing_mut().item_spacing.y = 12.0;
            widgets::card(ui, |ui| {
                widgets::section(ui, "Check an email address");
                ui.add_space(2.0);
                let busy = self.pages.email_queue.is_some();
                ui.horizontal(|ui| {
                    let resp = widgets::text_input(ui, &mut self.pages.email_input, "name@example.com", 420.0);
                    let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if (widgets::primary_button(ui, "Check", !busy).clicked() || enter) && !busy {
                        lookup = Some(vec![self.pages.email_input.clone()]);
                    }
                    if vault_emails.len() > 1 && widgets::ghost_button_enabled(ui, "Check all my emails", !busy).clicked() {
                        lookup = Some(vault_emails.clone());
                    }
                });
                if !vault_emails.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("From your vault:").size(12.5).color(p.faint));
                        for e in vault_emails.iter().take(12) {
                            if widgets::chip(ui, e, None, false).clicked() && !busy {
                                self.pages.email_input = e.clone();
                                lookup = Some(vec![e.clone()]);
                            }
                        }
                    });
                }
                if let Some((done, total)) = self.pages.email_queue {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(16.0).color(p.accent));
                        ui.label(format!("Looking up {} of {total} (one every 1.5 seconds)", (done + 1).min(total)));
                        if widgets::ghost_button(ui, "Cancel").clicked() {
                            self.pages.email_cancel.store(true, Ordering::Relaxed);
                        }
                    });
                    let w = ui.available_width();
                    widgets::progress_bar(ui, done as f32 / total.max(1) as f32, w, p.accent);
                }
                widgets::note(ui, "This sends the email address to xposedornot.com over HTTPS, and nothing else. KeepForge asks before the first lookup and never looks anything up in the background.");
            });

            // Results.
            let flagged_all = self.pages.flagged(&self.v.vault, self.rev);
            let results = self.pages.email_results.clone();
            let found: usize = results
                .iter()
                .map(|(_, r)| match r {
                    Ok(EmailResult::Found(list)) => list.len(),
                    _ => 0,
                })
                .sum();
            if !results.is_empty() {
                let text = if found == 0 {
                    "No breaches found for the addresses checked.".to_string()
                } else {
                    format!(
                        "Found in {found} breach{}; {} of your saved logins should be changed.",
                        if found == 1 { "" } else { "es" },
                        flagged_all.len()
                    )
                };
                ui.label(RichText::new(text).font(semibold(16.0)).color(if flagged_all.is_empty() { p.text } else { p.danger }));
            }
            for (email, result) in &results {
                match result {
                    Err(e) => {
                        widgets::card(ui, |ui| {
                            ui.label(RichText::new(email).font(semibold(15.0)));
                            widgets::banner(ui, Icon::ERROR, p.warn, e);
                        });
                    }
                    Ok(EmailResult::NotFound) => {
                        widgets::card(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(Icon::DONE.glyph()).size(18.0).color(p.accent));
                                ui.vertical(|ui| {
                                    ui.spacing_mut().item_spacing.y = 1.0;
                                    ui.label(RichText::new(email).font(semibold(15.0)));
                                    ui.label(RichText::new("No breaches found. This address is not in any breach the service knows about.").color(p.muted));
                                });
                            });
                        });
                    }
                    Ok(EmailResult::Found(list)) => {
                        ui.label(RichText::new(format!("{email}: {} breach{}", list.len(), if list.len() == 1 { "" } else { "es" })).font(semibold(15.0)));
                        for breach in list.iter().take(60) {
                            let flags = crate::breach::matching_items(&self.v.vault, breach);
                            widgets::card(ui, |ui| {
                                ui.spacing_mut().item_spacing.y = 6.0;
                                ui.horizontal(|ui| {
                                    let (tile, _) = ui.allocate_exact_size(vec2(36.0, 36.0), Sense::hover());
                                    widgets::letter_tile(ui, tile, &breach.name);
                                    ui.vertical(|ui| {
                                        ui.spacing_mut().item_spacing.y = 1.0;
                                        ui.label(RichText::new(&breach.name).font(semibold(16.0)));
                                        let mut facts: Vec<String> = Vec::new();
                                        if let Some(y) = breach.year {
                                            facts.push(format!("Breached in {y}"));
                                        }
                                        if breach.records > 0 {
                                            facts.push(format!("{} records", util::thousands(breach.records)));
                                        }
                                        if !breach.domain.is_empty() {
                                            facts.push(breach.domain.clone());
                                        }
                                        if !breach.industry.is_empty() {
                                            facts.push(breach.industry.clone());
                                        }
                                        ui.label(RichText::new(facts.join(" · ")).size(12.5).color(p.muted));
                                    });
                                });
                                ui.horizontal_wrapped(|ui| {
                                    ui.spacing_mut().item_spacing = vec2(6.0, 4.0);
                                    for kind in &breach.exposed {
                                        let color = if kind.to_lowercase().contains("password") { p.danger } else { p.info };
                                        widgets::badge(ui, kind, color);
                                    }
                                });
                                if !breach.description.is_empty() {
                                    ui.add(egui::Label::new(RichText::new(&breach.description).size(13.0).color(p.muted)).wrap());
                                }
                                if !flags.is_empty() {
                                    widgets::divider(ui);
                                    for flag in &flags {
                                        let mut open = false;
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new(Icon::KEY.glyph()).color(p.muted));
                                            ui.label(RichText::new(&flag.title).size(14.0));
                                            if flag.change_password {
                                                widgets::badge(ui, "Change this password", p.danger);
                                            } else {
                                                widgets::badge(ui, "Password changed since", p.accent);
                                            }
                                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                                open = widgets::ghost_button(ui, "Go to item").clicked();
                                            });
                                        });
                                        if open {
                                            self.go_to_item(flag.item);
                                        }
                                    }
                                }
                            });
                        }
                        if list.len() > 60 {
                            widgets::note(ui, &format!("… and {} more breaches for this address.", list.len() - 60));
                        }
                    }
                }
            }
            if results.is_empty() && self.pages.email_queue.is_none() {
                widgets::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(Icon::MAIL.glyph()).size(20.0).color(p.muted));
                        ui.add(egui::Label::new(RichText::new("Nothing checked yet. Results show which sites lost data, what was exposed, and which of your saved logins use a password older than the breach.").color(p.muted)).wrap());
                    });
                });
            }

            // Password check (k-anonymity).
            widgets::card(ui, |ui| {
                widgets::section(ui, "Check a password");
                ui.add_space(2.0);
                ui.horizontal(|ui| {
                    widgets::secret_input(ui, &mut self.pages.pw_check, false, "Type or paste a password", 420.0);
                    let ready = !self.pages.pw_check.is_empty() && !self.pages.pw_check_busy;
                    if widgets::primary_button(ui, "Check", ready).clicked() {
                        check_pw = true;
                    }
                });
                match &self.pages.pw_check_result {
                    Some(Ok(0)) => {
                        ui.colored_label(p.accent, Icon::DONE.with("Not found in known breaches. That alone does not make it strong."));
                    }
                    Some(Ok(n)) => {
                        ui.colored_label(p.danger, Icon::WARNING.with(&format!("Seen {} times in known breaches. Do not use this password.", util::thousands(*n))));
                    }
                    Some(Err(e)) => {
                        ui.colored_label(p.warn, e);
                    }
                    None => {}
                }
                widgets::note(ui, "The password is hashed on this PC and only the first 5 characters of the hash are sent to api.pwnedpasswords.com. The password itself never leaves this PC.");
            });
            ui.label(
                RichText::new("Email breach data: XposedOrNot (xposedornot.com). Password breach data: Pwned Passwords (haveibeenpwned.com).")
                    .size(12.0)
                    .color(p.faint),
            );
            ui.add_space(8.0);
        });
        if let Some(list) = lookup {
            self.request_email_lookup(&ctx, sh, list);
        }
        if check_pw {
            self.check_single_password(&ctx, sh);
        }
    }

    fn check_single_password(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        if sh.demo {
            self.pages.pw_check_result = Some(Ok(if self.pages.pw_check.as_str() == "password" {
                10_434_004
            } else {
                0
            }));
            self.pages.pw_check.wipe();
            return;
        }
        let password = self.pages.pw_check.to_secret();
        self.pages.pw_check.wipe();
        self.pages.pw_check_busy = true;
        self.pages.pw_check_result = None;
        let ranges = self.ranges.clone();
        sh.spawn(ctx, move || {
            let result = match ranges.lock() {
                Ok(mut cache) => cache.check(&password),
                Err(_) => Err("Internal error.".to_string()),
            };
            Msg::Tool(super::tools::ToolMsg::SinglePwned(result))
        });
    }

    // ----------------------------------------------------------------------------------
    // Authenticator
    // ----------------------------------------------------------------------------------

    pub(super) fn authenticator_ui(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        page_header(
            ui,
            "Authenticator",
            "All your one-time codes in one place. Click a code to copy it.",
            |_| {},
        );
        ui.horizontal(|ui| {
            widgets::text_input(ui, &mut self.pages.auth_search, "Filter by name", 320.0);
        });
        ui.add_space(4.0);
        let filter = self.pages.auth_search.to_lowercase();
        let mut entries: Vec<(Id, String, String)> = self
            .v
            .vault
            .items
            .iter()
            .filter(|i| !i.in_trash() && !i.totp.is_empty())
            .filter(|i| {
                filter.is_empty()
                    || i.title.to_lowercase().contains(&filter)
                    || i.username.to_lowercase().contains(&filter)
            })
            .map(|i| (i.id, i.title.clone(), i.username.clone()))
            .collect();
        entries.sort_by_key(|(_, title, _)| title.to_lowercase());
        if entries.is_empty() {
            widgets::empty_state(
                ui,
                Icon::PHONE,
                p.muted,
                "No one-time codes yet",
                "Edit a login and paste the site's authenticator setup key (or its otpauth:// link) to see its codes here.",
            );
            return;
        }
        let now = sh.now as u64;
        let mut copy = None;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_max_width((ui.available_width() - 12.0).min(760.0));
                ui.spacing_mut().item_spacing.y = 8.0;
                for (id, title, user) in &entries {
                    let Some(item) = self.v.vault.item(*id) else {
                        continue;
                    };
                    let seed = item.totp.open_str();
                    let parsed = crate::totp::Totp::parse(&seed);
                    let (rect, resp) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 64.0), Sense::click());
                    ui.painter().rect_filled(
                        rect,
                        CornerRadius::same(12),
                        if resp.hovered() { p.hover } else { p.card },
                    );
                    ui.painter().rect_stroke(
                        rect,
                        CornerRadius::same(12),
                        Stroke::new(1.0_f32, p.border),
                        egui::StrokeKind::Inside,
                    );
                    widgets::letter_tile(
                        ui,
                        Rect::from_min_size(rect.min + vec2(14.0, 14.0), vec2(36.0, 36.0)),
                        title,
                    );
                    widgets::text_in(
                        ui,
                        Rect::from_min_max(
                            rect.min + vec2(62.0, 11.0),
                            egui::pos2(rect.right() - 260.0, rect.top() + 33.0),
                        ),
                        title,
                        semibold(15.0),
                        p.text,
                    );
                    widgets::text_in(
                        ui,
                        Rect::from_min_max(
                            rect.min + vec2(62.0, 33.0),
                            egui::pos2(rect.right() - 260.0, rect.bottom() - 9.0),
                        ),
                        user,
                        regular(12.5),
                        p.muted,
                    );
                    match parsed {
                        Ok(t) => {
                            let code = zeroize::Zeroizing::new(t.code_at(now));
                            let left = t.remaining(now);
                            let warn = left <= 5;
                            ui.painter().text(
                                egui::pos2(rect.right() - 64.0, rect.center().y),
                                Align2::RIGHT_CENTER,
                                crate::totp::spaced(&code),
                                egui::FontId::new(24.0, egui::FontFamily::Monospace),
                                if warn { p.warn } else { p.text },
                            );
                            let c = egui::pos2(rect.right() - 32.0, rect.center().y);
                            widgets::paint_ring(
                                ui,
                                c,
                                13.0,
                                3.0,
                                left as f32 / t.period as f32,
                                if warn { p.warn } else { p.accent },
                            );
                            ui.painter().text(
                                c,
                                Align2::CENTER_CENTER,
                                left.to_string(),
                                regular(10.5),
                                p.muted,
                            );
                        }
                        Err(_) => {
                            ui.painter().text(
                                egui::pos2(rect.right() - 20.0, rect.center().y),
                                Align2::RIGHT_CENTER,
                                "Setup key not valid",
                                regular(13.0),
                                p.danger,
                            );
                        }
                    }
                    if resp
                        .on_hover_cursor(egui::CursorIcon::PointingHand)
                        .clicked()
                    {
                        copy = Some(*id);
                    }
                }
                ui.add_space(8.0);
            });
        if let Some(id) = copy {
            self.copy_totp(sh, id);
        }
    }

    // ----------------------------------------------------------------------------------
    // Generator
    // ----------------------------------------------------------------------------------

    pub(super) fn regenerate(&mut self, sh: &Shared) {
        let fresh = if sh.settings.generator_phrase {
            generator::passphrase(&sh.settings.phrase, &mut OsRng)
        } else {
            generator::password(&sh.settings.generator, &mut OsRng)
        };
        self.pages.gen_value.set(&fresh);
    }

    pub(super) fn generator_ui(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        page_header(
            ui,
            "Generator",
            "Random passwords and passphrases, made on this PC",
            |_| {},
        );
        if self.pages.gen_value.is_empty() {
            self.regenerate(sh);
        }
        let mut again = false;
        let mut copy = false;
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width((ui.available_width() - 12.0).min(820.0));
            ui.spacing_mut().item_spacing.y = 12.0;
            widgets::card(ui, |ui| {
                ui.spacing_mut().item_spacing.y = 8.0;
                Frame::new()
                    .fill(p.bg)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .corner_radius(CornerRadius::same(10))
                    .inner_margin(Margin::same(16))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.add(
                            egui::Label::new(
                                RichText::new(self.pages.gen_value.as_str())
                                    .monospace()
                                    .size(20.0)
                                    .color(p.text),
                            )
                            .wrap(),
                        );
                    });
                let bits = if sh.settings.generator_phrase {
                    sh.settings.phrase.entropy_bits()
                } else {
                    sh.settings.generator.entropy_bits()
                };
                let s = self.pages.gen_strength.get(self.pages.gen_value.as_str()).clone();
                ui.horizontal(|ui| {
                    widgets::strength_bar(ui, s.score, false, 160.0);
                    ui.label(
                        RichText::new(crate::strength::score_label(s.score))
                            .font(semibold(13.5))
                            .color(widgets::strength_color(&p, s.score)),
                    );
                });
                ui.horizontal_wrapped(|ui| {
                    widgets::badge(ui, &format!("{bits:.0} bits of entropy"), p.accent);
                    widgets::badge(ui, &format!("pattern estimate: {}", s.bits_text()), p.info);
                    if !s.capped() {
                        widgets::badge(ui, &format!("offline cracking: {}", s.offline_fast), p.muted);
                    }
                });
                widgets::note(ui, "Entropy is exact for how the password was made. The pattern estimate is how a cracking program that knows common words and patterns would see it; it can be lower for passphrases, which is expected.");
                ui.horizontal(|ui| {
                    if widgets::primary_button(ui, &Icon::COPY.with("Copy"), true).clicked() {
                        copy = true;
                    }
                    if widgets::ghost_button(ui, &Icon::REFRESH.with("Another")).clicked() {
                        again = true;
                    }
                });
            });
            widgets::card(ui, |ui| {
                widgets::section(ui, "Options");
                ui.add_space(2.0);
                ui.spacing_mut().item_spacing.y = 8.0;
                let mut phrase_mode = sh.settings.generator_phrase;
                let mut opts = sh.settings.generator.clone();
                let mut phrase = sh.settings.phrase.clone();
                if generator_options(ui, &mut phrase_mode, &mut opts, &mut phrase) {
                    sh.settings.generator_phrase = phrase_mode;
                    sh.settings.generator = opts;
                    sh.settings.phrase = phrase;
                    again = true;
                }
                widgets::note(ui, "These are also the defaults for the generator inside the item editor. Passphrases use the EFF large wordlist (7,776 words).");
            });
            ui.add_space(8.0);
        });
        if again {
            self.regenerate(sh);
        }
        if copy {
            let text = self.pages.gen_value.to_secret();
            sh.copy_secret(&text, "Password");
        }
    }

    // ----------------------------------------------------------------------------------
    // Settings
    // ----------------------------------------------------------------------------------

    pub(super) fn settings_ui(&mut self, ui: &mut Ui, sh: &mut Shared) -> Option<Go> {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let mut go = None;
        page_header(ui, "Settings", "Saved automatically", |_| {});
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.set_max_width((ui.available_width() - 12.0).min(860.0));
            ui.spacing_mut().item_spacing.y = 12.0;

            widgets::card(ui, |ui| {
                widgets::section(ui, "Appearance");
                ui.add_space(2.0);
                choice_row(
                    ui,
                    "Theme",
                    "\"System\" follows the Windows light or dark setting.",
                    &mut sh.settings.theme,
                    &[(ThemeChoice::Dark, "Dark"), (ThemeChoice::Light, "Light"), (ThemeChoice::System, "System")],
                );
            });

            widgets::card(ui, |ui| {
                widgets::section(ui, "Locking");
                ui.add_space(2.0);
                choice_row(
                    ui,
                    "Lock when I am away",
                    "After this long without keyboard or mouse activity anywhere on the PC.",
                    &mut sh.settings.auto_lock_minutes,
                    &[(1, "1 min"), (5, "5 min"), (15, "15 min"), (30, "30 min"), (60, "1 hour"), (0, "Never")],
                );
                widgets::divider(ui);
                toggle_row(ui, "Lock when Windows locks, sleeps or switches user", "Also when a remote session disconnects.", &mut sh.settings.lock_on_session);
                widgets::divider(ui);
                toggle_row(ui, "Lock when the window is minimised", "", &mut sh.settings.lock_on_minimize);
                widgets::divider(ui);
                choice_row(
                    ui,
                    "Hide revealed secrets again after",
                    "Passwords and notes you reveal are masked again by themselves.",
                    &mut sh.settings.reveal_seconds,
                    &[(10, "10 s"), (20, "20 s"), (60, "1 min"), (300, "5 min")],
                );
            });

            widgets::card(ui, |ui| {
                widgets::section(ui, "Clipboard and screen");
                ui.add_space(2.0);
                choice_row(
                    ui,
                    "Clear copied secrets after",
                    "Only if the clipboard still holds what KeepForge put there. Copied secrets are also kept out of Windows clipboard history and cloud clipboard.",
                    &mut sh.settings.clipboard_seconds,
                    &[(10, "10 s"), (20, "20 s"), (30, "30 s"), (60, "1 min"), (0, "Never")],
                );
                widgets::divider(ui);
                toggle_row(
                    ui,
                    "Hide the window from screen capture",
                    "Screenshots, screen recordings and screen sharing show a blank area instead of KeepForge. A camera pointed at the screen is not stopped.",
                    &mut sh.settings.hide_from_capture,
                );
            });

            widgets::card(ui, |ui| {
                widgets::section(ui, "This vault");
                ui.add_space(2.0);
                let location = if sh.demo {
                    crate::demo::DEMO_PATH.to_string()
                } else {
                    self.v.path.as_ref().map(|p| p.to_string_lossy().to_string()).unwrap_or_default()
                };
                let mut name = self.v.vault.name.clone();
                setting(ui, "Name", &location, |ui| {
                    widgets::text_input(ui, &mut name, "Vault name", 260.0);
                });
                if name != self.v.vault.name && !name.trim().is_empty() {
                    self.v.vault.name = name;
                    if let Some(path) = &self.v.path {
                        sh.settings.remember(path, &self.v.vault.name, None, sh.now);
                    }
                    self.changed(&ctx, sh);
                }
                widgets::divider(ui);
                let protection = format!(
                    "{}{}",
                    self.v.sealer.kdf.describe(),
                    if self.v.sealer.key_file { ", plus a key file" } else { "" }
                );
                setting(ui, "Master password, key stretching and key file", &protection, |ui| {
                    if widgets::ghost_button(ui, "Change…").clicked() {
                        self.dialog = Some(Dialog::change_password(self.v.sealer.kdf));
                    }
                });
                widgets::divider(ui);
                setting(ui, "Emergency sheet", "A page to print and write the master password on by hand.", |ui| {
                    if widgets::ghost_button(ui, "Save the sheet…").clicked() {
                        self.save_emergency_sheet(sh);
                    }
                });
                widgets::divider(ui);
                setting(ui, "Import", "Bring in entries from a browser or another manager's CSV or JSON export.", |ui| {
                    if widgets::ghost_button(ui, &Icon::IMPORT.with("Import…")).clicked() {
                        self.start_import(&ctx, sh);
                    }
                });
                widgets::divider(ui);
                setting(ui, "Export", "An encrypted copy for backup, or an unencrypted file to move elsewhere.", |ui| {
                    if widgets::ghost_button(ui, &Icon::EXPORT.with("Export…")).clicked() {
                        self.dialog = Some(Dialog::export());
                    }
                });
                widgets::divider(ui);
                choice_row(
                    ui,
                    "Rolling backups",
                    "Older copies kept next to the vault as .bak1, .bak2 … A backup is made when you first change something after unlocking, then at most once an hour.",
                    &mut sh.settings.backups,
                    &[(0, "None"), (3, "3"), (5, "5"), (10, "10"), (20, "20")],
                );
                widgets::divider(ui);
                choice_row(
                    ui,
                    "Largest attachment",
                    "Attachments live inside the vault file and make it bigger.",
                    &mut sh.settings.attachment_limit_mb,
                    &[(5, "5 MB"), (10, "10 MB"), (25, "25 MB"), (50, "50 MB"), (100, "100 MB")],
                );
                widgets::divider(ui);
                setting(ui, "Close this vault", "Lock it and go back to the start screen to open or create another.", |ui| {
                    if widgets::ghost_button(ui, "Lock and close").clicked() {
                        go = Some(Go::LockAndClose);
                    }
                });
            });

            widgets::card(ui, |ui| {
                widgets::section(ui, "Auto-type");
                ui.add_space(2.0);
                toggle_row(
                    ui,
                    "Global hotkey",
                    "Press it in a login window: KeepForge finds the matching login and types the user name and password. It never types into windows that run as administrator.",
                    &mut sh.settings.autotype_enabled,
                );
                widgets::divider(ui);
                let mut text = self.pages.hotkey_text.clone().unwrap_or_else(|| sh.settings.autotype_hotkey.clone());
                let valid = crate::sys::parse_hotkey(&text).is_some();
                setting(
                    ui,
                    "Hotkey",
                    if valid { "For example Ctrl+Alt+A or Ctrl+Shift+F9." } else { "Not a usable hotkey. It needs Ctrl, Alt or Win plus one letter, digit or F-key." },
                    |ui| {
                        widgets::text_input(ui, &mut text, "Ctrl+Alt+A", 200.0);
                    },
                );
                if valid && text != sh.settings.autotype_hotkey {
                    sh.settings.autotype_hotkey = text.clone();
                }
                self.pages.hotkey_text = Some(text);
            });

            widgets::card(ui, |ui| {
                widgets::section(ui, "Search and health");
                ui.add_space(2.0);
                toggle_row(
                    ui,
                    "Search inside hidden fields",
                    "Off: search looks at titles, user names, addresses, tags, notes and visible fields only.",
                    &mut sh.settings.search_hidden,
                );
                widgets::divider(ui);
                choice_row(
                    ui,
                    "Call a password \"old\" after",
                    "",
                    &mut sh.settings.old_password_months,
                    &[(6, "6 months"), (12, "1 year"), (24, "2 years"), (36, "3 years")],
                );
            });

            widgets::card(ui, |ui| {
                widgets::section(ui, "Online checks");
                ui.add_space(2.0);
                widgets::note(ui, "KeepForge works offline. The only things that ever use the internet are the checks below, and each one runs only when you click it.");
                toggle_row(
                    ui,
                    "Password breach check without asking each time",
                    "Sends the first 5 characters of each password's SHA-1 hash to api.pwnedpasswords.com. Passwords never leave this PC.",
                    &mut sh.settings.breach_check,
                );
                widgets::divider(ui);
                toggle_row(
                    ui,
                    "Email breach lookup without asking each time",
                    "Sends the email address you check to xposedornot.com.",
                    &mut sh.settings.email_lookup_ack,
                );
                widgets::divider(ui);
                toggle_row(
                    ui,
                    "Torrent exposure check without asking each time",
                    "Sends the IP address you check and your own API key to the iknowwhatyoudownload.com API.",
                    &mut sh.settings.ip_lookup_ack,
                );
            });

            widgets::card(ui, |ui| {
                widgets::section(ui, "Startup");
                ui.add_space(2.0);
                toggle_row(ui, "Tray icon", "An icon near the clock with Show, Lock and Exit.", &mut sh.settings.tray_icon);
                widgets::divider(ui);
                toggle_row(ui, "Start minimised", "", &mut sh.settings.start_minimised);
            });

            widgets::card(ui, |ui| {
                widgets::section(ui, "Process protection");
                ui.add_space(2.0);
                widgets::note(ui, "Best-effort measures against casual snooping by other programs. They do not stop malware that runs as you while the vault is unlocked.");
                if !sh.strict {
                    widgets::banner(ui, Icon::WARNING, p.warn, "Compatibility mode: the last start did not get as far as showing the window, so the library-loading restriction and the dynamic-code block are off for this run. Close KeepForge normally and start it again to return to full protection.");
                }
                for step in &sh.steps {
                    ui.horizontal(|ui| {
                        let (icon, color) = if step.ok { (Icon::DONE, p.accent) } else { (Icon::INFO, p.faint) };
                        ui.label(RichText::new(icon.glyph()).color(color));
                        ui.label(RichText::new(step.name).size(13.5));
                        if !step.ok {
                            ui.label(RichText::new(&step.detail).size(12.5).color(p.faint));
                        }
                    });
                }
                widgets::divider(ui);
                toggle_row(
                    ui,
                    "Block dynamically generated code (advanced)",
                    "Makes code injection harder, but some graphics drivers need it. Takes effect the next time KeepForge starts. If the window then fails to appear, KeepForge starts in compatibility mode by itself and turns this off.",
                    &mut sh.settings.block_dynamic_code,
                );
            });

            widgets::card(ui, |ui| {
                widgets::section(ui, "About");
                ui.add_space(2.0);
                let dir = sh.data_dir.to_string_lossy().to_string();
                setting(
                    ui,
                    "Settings folder",
                    &format!("{dir}{}", if crate::settings::is_portable() && !sh.demo { " (portable mode)" } else { "" }),
                    |ui| {
                        if widgets::ghost_button(ui, "About KeepForge").clicked() {
                            sh.about_open = true;
                        }
                    },
                );
                widgets::note(ui, "Settings never contain passwords, keys or anything from a vault.");
            });
            ui.add_space(8.0);
        });
        if self.nav != Nav::Settings {
            self.pages.hotkey_text = None;
        }
        go
    }
}
