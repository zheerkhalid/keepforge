//! The full-width pages: security dashboard, breach lookup, authenticator,
//! generator and settings.

use super::app::{Go, Msg, Shared};
use super::dialogs::{Dialog, Online};
use super::edit::generator_options;
use super::main_view::{Main, Nav};
use super::start::StrengthCache;
use super::theme::{pal, regular, semibold, Icon};
use super::widgets;
use crate::generator::{self, OsRng};
use crate::model::{Id, Kind};
use crate::secret::{Protected, SecretInput, SessionKey};
use crate::settings::ThemeChoice;
use crate::torrent::{PeerError, PeerReport};
use crate::util;
use eframe::egui::{
    self, vec2, Align, Align2, Color32, CornerRadius, Frame, Layout, Margin, Rect, RichText, Sense,
    Stroke, Ui,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub struct PageState {
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
    /// Passwords copied from the generator page, newest first. Encrypted in
    /// memory like every other secret and gone when the vault locks.
    pub gen_history: Vec<Protected>,
    // Authenticator
    pub auth_search: String,
    // Settings
    hotkey_text: Option<String>,
    /// Scroll Settings to the online checks (demo screenshots).
    pub scroll_online: bool,
}

/// How many copied passwords the generator page remembers.
pub const GEN_HISTORY: usize = 8;

impl PageState {
    /// Remembers a password that was just copied from the generator, so one
    /// that was pasted into a sign-up form but not saved yet is not lost.
    pub fn remember_generated(&mut self, session: &Arc<SessionKey>, text: &str) {
        if text.is_empty() {
            return;
        }
        self.gen_history
            .retain(|old| old.open_str().as_str() != text);
        self.gen_history
            .insert(0, Protected::seal_str(session, text));
        self.gen_history.truncate(GEN_HISTORY);
    }

    pub fn peer_result(&mut self, result: Result<PeerReport, PeerError>) {
        self.peer_busy = false;
        self.peer = Some(result.map_err(|e| e.to_string()));
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
        let flagged = self.exposed_items();
        let stealers = self.stealer_findings();
        let mut breached: Vec<Id> = self.pwned.keys().copied().collect();
        for (id, _) in &flagged {
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

            // Infostealer findings come first: they concern a whole computer.
            if !stealers.is_empty() {
                let mut open = false;
                widgets::card(ui, |ui| {
                    widgets::section(ui, "Malware stole saved logins");
                    for (value, e) in stealers.iter().take(6) {
                        let what = if e.kind == crate::exposure::FindingKind::StealerSite {
                            format!("Your login for {} ({value}) was in infostealer logs.", e.domain)
                        } else if e.date.is_empty() {
                            format!("{value} is linked to a computer infected by infostealer malware.")
                        } else {
                            format!("{value} is linked to a computer infected by infostealer malware on {}.", e.date)
                        };
                        widgets::banner(ui, Icon::WARNING, p.danger, &what);
                    }
                    widgets::note(ui, "Scan that computer with an up-to-date antivirus, then change the passwords that were saved on it, starting with email and banking.");
                    open = widgets::ghost_button(ui, "Open the Exposure check").clicked();
                });
                if open {
                    self.nav = Nav::Exposure;
                }
            }

            // Problem lists.
            let mut any = false;
            if !breached.is_empty() {
                any = true;
                widgets::card(ui, |ui| {
                    widgets::section(ui, "Breached and exposed");
                    widgets::note(ui, "These passwords are known to attackers, or the Exposure check found that the site lost data after you last changed the password. Change them first.");
                    for id in &breached {
                        let reason = match self.pwned.get(id) {
                            Some(n) => format!("Password seen {} times in breaches", util::thousands(*n)),
                            None => flagged
                                .iter()
                                .find(|(f, _)| f == id)
                                .map(|(_, why)| why.clone())
                                .unwrap_or_else(|| "Site breached since the last password change".to_string()),
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
            if !report.insecure.is_empty() {
                any = true;
                widgets::card(ui, |ui| {
                    widgets::section(ui, "Unencrypted web addresses");
                    widgets::note(ui, "These logins point at an address that starts with http://, so the password travels without encryption. See whether the site also works with https:// and change the saved address.");
                    for id in &report.insecure {
                        self.item_line(ui, *id, "Address starts with http://", p.warn);
                    }
                });
            }
            if !any {
                widgets::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(Icon::DONE.glyph()).size(20.0).color(p.accent));
                        ui.label(RichText::new("No weak, reused, old or expiring passwords and no unencrypted addresses found.").size(15.0));
                    });
                });
            }
            if !self.pwned_done && self.pwned_progress.is_none() {
                widgets::note(ui, "\"Breached\" counts what the optional online checks have found: the password check above (which sends only a 5-character hash prefix) and the results saved by the Exposure check page.");
            }
            ui.add_space(8.0);
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
        let mut copy_old: Option<usize> = None;
        let mut toggle: Option<String> = None;
        let mut forget = false;
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
            if !self.pages.gen_history.is_empty() {
                widgets::card(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 6.0;
                    ui.horizontal(|ui| {
                        widgets::section(ui, "Copied in this session");
                        ui.label(
                            RichText::new(format!("{} of {GEN_HISTORY} kept", self.pages.gen_history.len()))
                                .size(12.5)
                                .color(p.faint),
                        );
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if widgets::link(ui, "Forget these").clicked() {
                                forget = true;
                            }
                        });
                    });
                    for n in 0..self.pages.gen_history.len() {
                        let key = format!("gen{n}");
                        let shown = self.reveal.contains_key(&key);
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.set_width(ui.available_width() - 90.0);
                                if shown {
                                    let text = self.pages.gen_history[n].open_str();
                                    ui.add(
                                        egui::Label::new(RichText::new(text.as_str()).monospace().size(14.0))
                                            .truncate(),
                                    );
                                } else {
                                    ui.label(RichText::new("••••••••••••").color(p.muted));
                                }
                            });
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if widgets::icon_button(ui, Icon::COPY, "Copy again").clicked() {
                                    copy_old = Some(n);
                                }
                                let icon = if shown { Icon::HIDE } else { Icon::VIEW };
                                if widgets::icon_button(ui, icon, if shown { "Hide" } else { "Show for a moment" }).clicked() {
                                    toggle = Some(key);
                                }
                            });
                        });
                    }
                    widgets::note(ui, "Passwords you copied from this page, newest first, in case one went into a sign-up form before you saved it. They are kept in memory only and are gone when the vault locks.");
                });
            }
            ui.add_space(8.0);
        });
        if again {
            self.regenerate(sh);
        }
        if copy {
            let text = self.pages.gen_value.to_secret();
            sh.copy_secret(&text, "Password");
            self.pages.remember_generated(&self.v.session, &text);
            self.reveal.retain(|k, _| !k.starts_with("gen"));
        }
        if let Some(n) = copy_old {
            let text = self.pages.gen_history[n].open_str();
            sh.copy_secret(&text, "Password");
        }
        if let Some(key) = toggle {
            if self.reveal.remove(&key).is_none() {
                let until = ui.input(|i| i.time) + f64::from(sh.settings.reveal_seconds);
                self.reveal.insert(key, until);
            }
        }
        if forget {
            self.pages.gen_history.clear();
            self.reveal.retain(|k, _| !k.starts_with("gen"));
        }
        if self.reveal.keys().any(|k| k.starts_with("gen")) {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(500));
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
                choice_row(
                    ui,
                    "Empty the trash by itself",
                    "Items that have been in the trash this long are removed for good the next time a vault is unlocked.",
                    &mut sh.settings.trash_days,
                    &[(0, "Never"), (30, "30 days"), (90, "90 days"), (365, "1 year")],
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

            if self.pages.scroll_online {
                ui.scroll_to_cursor(Some(Align::TOP));
            }
            widgets::card(ui, |ui| {
                widgets::section(ui, "Online checks");
                ui.add_space(2.0);
                self.exposure_settings(ui, sh);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_history_keeps_the_newest_without_repeats() {
        let session = SessionKey::new();
        let mut pages = PageState::default();
        pages.remember_generated(&session, "");
        assert!(pages.gen_history.is_empty());
        for n in 0..12 {
            pages.remember_generated(&session, &format!("pw-{n}"));
        }
        assert_eq!(pages.gen_history.len(), GEN_HISTORY);
        assert_eq!(pages.gen_history[0].open_str().as_str(), "pw-11");
        // Copying an older one again moves it to the top instead of repeating it.
        pages.remember_generated(&session, "pw-8");
        let all: Vec<String> = pages
            .gen_history
            .iter()
            .map(|h| h.open_str().to_string())
            .collect();
        assert_eq!(all.len(), GEN_HISTORY);
        assert_eq!(all[0], "pw-8");
        assert_eq!(all.iter().filter(|t| *t == "pw-8").count(), 1);
        // Locking wipes the session key: nothing of the history can be read.
        session.wipe();
        assert!(pages.gen_history.iter().all(|h| h.open_str().is_empty()));
    }
}
