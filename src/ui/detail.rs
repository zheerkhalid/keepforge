//! The detail pane: one item, with copy / reveal / open actions.
//! Secrets are decrypted only while they are revealed or being copied.

use super::app::Shared;
use super::dialogs::{ConfirmAction, Dialog};
use super::main_view::{kind_icon, Main, Nav};
use super::theme::{pal, regular, semibold, Icon};
use super::widgets;
use crate::model::{Id, Item, Kind};
use crate::secret::Protected;
use crate::util;
use eframe::egui::{self, vec2, Align, Layout, RichText, Sense, Ui};

const MASK: &str = "••••••••••••";

impl Main {
    pub(super) fn detail_pane(&mut self, ui: &mut Ui, sh: &mut Shared) {
        if self.edit.is_some() {
            self.edit_ui(ui, sh);
            return;
        }
        let item = self.selected.and_then(|id| self.v.vault.item(id)).cloned();
        match item {
            Some(item) => self.detail_ui(ui, sh, &item),
            None => {
                let p = pal(ui);
                widgets::empty_state(
                    ui,
                    Icon::KEY,
                    p.accent,
                    "Select an item",
                    "Choose something on the left to see it here.\n\nCtrl+N new item · Ctrl+F search · Ctrl+B copy user name · Ctrl+C copy password · Ctrl+T copy one-time code · Ctrl+L lock",
                );
            }
        }
    }

    fn revealed(&self, key: &str) -> bool {
        self.reveal.contains_key(key)
    }

    fn toggle_reveal(&mut self, ui: &Ui, sh: &Shared, key: &str) {
        if self.reveal.remove(key).is_none() {
            let now = ui.input(|i| i.time);
            self.reveal
                .insert(key.to_string(), now + f64::from(sh.settings.reveal_seconds));
        }
    }

    /// One labelled value with action buttons on the right.
    fn row(ui: &mut Ui, label: &str, body: impl FnOnce(&mut Ui), actions: impl FnOnce(&mut Ui)) {
        let p = pal(ui);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 118.0);
                ui.spacing_mut().item_spacing.y = 1.0;
                widgets::line_label(ui, label, regular(12.0), p.faint);
                body(ui);
            });
            ui.with_layout(Layout::right_to_left(Align::Center), actions);
        });
    }

    /// A secret value: masked until revealed, with reveal and copy buttons.
    fn secret_row(
        &mut self,
        ui: &mut Ui,
        sh: &mut Shared,
        key: &str,
        label: &str,
        secret: &Protected,
        what: &str,
    ) {
        let p = pal(ui);
        let shown = self.revealed(key);
        let mut toggle = false;
        let mut copy = false;
        Self::row(
            ui,
            label,
            |ui| {
                if shown {
                    let text = secret.open_str();
                    if super::bidi::paragraph(ui, &text, 14.5, p.text, true).is_none() {
                        ui.add(
                            egui::Label::new(
                                RichText::new(text.as_str())
                                    .monospace()
                                    .size(14.5)
                                    .color(p.text),
                            )
                            .wrap(),
                        );
                    }
                } else {
                    ui.label(RichText::new(MASK).color(p.muted));
                }
            },
            |ui| {
                if widgets::icon_button(ui, Icon::COPY, &format!("Copy {}", what.to_lowercase()))
                    .clicked()
                {
                    copy = true;
                }
                let icon = if shown { Icon::HIDE } else { Icon::VIEW };
                if widgets::icon_button(ui, icon, if shown { "Hide" } else { "Show for a moment" })
                    .clicked()
                {
                    toggle = true;
                }
            },
        );
        if toggle {
            self.toggle_reveal(ui, sh, key);
        }
        if copy {
            let text = secret.open_str();
            sh.copy_secret(&text, what);
        }
    }

    fn plain_row(ui: &mut Ui, sh: &mut Shared, label: &str, value: &str, what: &str) {
        let p = pal(ui);
        let mut copy = false;
        Self::row(
            ui,
            label,
            |ui| {
                widgets::wrapped_label(ui, value, regular(14.5), p.text, false);
            },
            |ui| {
                if widgets::icon_button(ui, Icon::COPY, &format!("Copy {}", what.to_lowercase()))
                    .clicked()
                {
                    copy = true;
                }
            },
        );
        if copy {
            sh.copy_plain(value, what);
        }
    }

    fn password_score(&mut self, item: &Item) -> u8 {
        if let Some((id, rev, score)) = self.pw_score {
            if id == item.id && rev == self.rev {
                return score;
            }
        }
        let pw = item.password.open_str();
        let score = crate::strength::estimate(&pw, &[&item.title, &item.username]).score;
        self.pw_score = Some((item.id, self.rev, score));
        score
    }

    fn detail_ui(&mut self, ui: &mut Ui, sh: &mut Shared, item: &Item) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let id = item.id;
        let trashed = item.in_trash();
        let mut changed = false;

        // Header: tile, title, badges, actions.
        ui.horizontal(|ui| {
            let (tile, _) = ui.allocate_exact_size(vec2(52.0, 52.0), Sense::hover());
            widgets::letter_tile(ui, tile, &item.title);
            ui.add_space(4.0);
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 250.0);
                ui.spacing_mut().item_spacing.y = 3.0;
                widgets::line_label(ui, &item.title, semibold(22.0), p.text);
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 6.0;
                    widgets::badge(ui, &kind_icon(item.kind).with(item.kind.label()), p.accent);
                    if let Some(folder) = self.v.vault.folder_name(item.folder) {
                        widgets::badge(ui, &Icon::FOLDER.with(folder), p.info);
                    }
                    for tag in &item.tags {
                        widgets::badge(ui, tag, p.muted);
                    }
                    if trashed {
                        widgets::badge(ui, "In the trash", p.danger);
                    }
                });
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if trashed {
                    if widgets::danger_button(ui, "Delete for good", true).clicked() {
                        self.trash_item(&ctx, sh, id);
                    }
                    if widgets::ghost_button(ui, &Icon::UNDO.with("Restore")).clicked() {
                        self.v.vault.restore(id, sh.now);
                        sh.toast("Restored", false);
                        self.nav = Nav::All;
                        changed = true;
                    }
                    return;
                }
                let more = ui.menu_button(
                    RichText::new(Icon::MORE.glyph()).size(15.0).color(p.muted),
                    |ui| {
                        ui.set_min_width(180.0);
                        if ui.button("Duplicate").clicked() {
                            if let Some(copy) = self.v.vault.duplicate(id, sh.now) {
                                self.selected = Some(copy);
                                sh.toast("Duplicated", false);
                                changed = true;
                            }
                            ui.close_menu();
                        }
                        if item.kind == Kind::Wifi && ui.button("Show Wi-Fi QR code").clicked() {
                            self.dialog = Some(Dialog::qr_wifi(item));
                            ui.close_menu();
                        }
                        if !item.totp.is_empty() && ui.button("Show one-time code QR").clicked() {
                            self.dialog = Some(Dialog::qr_totp(item));
                            ui.close_menu();
                        }
                        if ui.button("Move to trash").clicked() {
                            self.trash_item(&ctx, sh, id);
                            ui.close_menu();
                        }
                    },
                );
                more.response.on_hover_text("More");
                if widgets::primary_button(ui, &Icon::EDIT.with("Edit"), true)
                    .on_hover_text("Edit (Ctrl+E)")
                    .clicked()
                {
                    self.start_edit(sh, id);
                }
                let star = if item.favourite {
                    Icon::STAR_FILL
                } else {
                    Icon::STAR
                };
                if widgets::icon_button(
                    ui,
                    star,
                    if item.favourite {
                        "Remove from favourites"
                    } else {
                        "Add to favourites"
                    },
                )
                .clicked()
                {
                    if let Some(i) = self.v.vault.item_mut(id) {
                        i.favourite = !i.favourite;
                        i.modified = sh.now;
                    }
                    changed = true;
                }
                if item.kind == Kind::Login
                    && widgets::icon_button(
                        ui,
                        Icon::KEYBOARD,
                        "Auto-type into the window behind KeepForge",
                    )
                    .clicked()
                {
                    self.autotype_button(&ctx, sh, id);
                }
            });
        });
        ui.add_space(8.0);

        // Files dragged onto the window are attached to the item on show.
        let can_drop = !trashed && self.dialog.is_none() && !sh.shot;
        let dropping = can_drop && ctx.input(|i| !i.raw.hovered_files.is_empty());
        if can_drop {
            let dropped: Vec<std::path::PathBuf> = ctx.input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .filter_map(|f| f.path.clone())
                    .collect()
            });
            for path in dropped {
                if self.attach_path(sh, id, &path) {
                    changed = true;
                }
            }
        }

        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_max_width((ui.available_width() - 12.0).min(760.0));
                ui.spacing_mut().item_spacing.y = 10.0;

                // Warnings that concern this item.
                if let Some(count) = self.pwned.get(&id) {
                    widgets::banner(
                        ui,
                        Icon::WARNING,
                        p.danger,
                        &format!(
                            "This password appears in known data breaches ({} times). Change it, here and on the site.",
                            util::thousands(*count)
                        ),
                    );
                }
                if self.pages.flagged(&self.v.vault, self.rev).contains(&id) {
                    widgets::banner(
                        ui,
                        Icon::WARNING,
                        p.danger,
                        "This site was in a data breach after you last changed this password. Change this password.",
                    );
                }
                if let Some(when) = item.expiry() {
                    if when <= sh.now {
                        widgets::banner(ui, Icon::CLOCK, p.danger, &format!("Expired on {}.", util::fmt_date(when - 1)));
                    } else if when <= sh.now + crate::health::EXPIRY_WINDOW_DAYS * util::DAY {
                        widgets::banner(ui, Icon::CLOCK, p.warn, &format!("Expires soon: {}.", util::fmt_date(when - 1)));
                    }
                }

                let has_main = item.kind.username_label().is_some()
                    || item.kind.password_label().is_some()
                    || !item.urls.is_empty()
                    || !item.totp.is_empty();
                if has_main {
                    widgets::card(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 10.0;
                        let mut first = true;
                        let mut sep = |ui: &mut Ui| {
                            if !first {
                                widgets::divider(ui);
                            }
                            first = false;
                        };
                        if let Some(label) = item.kind.username_label() {
                            if !item.username.is_empty() {
                                sep(ui);
                                Self::plain_row(ui, sh, label, &item.username, "User name");
                            }
                        }
                        if let Some(label) = item.kind.password_label() {
                            if !item.password.is_empty() {
                                sep(ui);
                                self.secret_row(ui, sh, "pw", label, &item.password, label);
                                if item.kind != Kind::Licence {
                                    let score = self.password_score(item);
                                    ui.horizontal(|ui| {
                                        widgets::strength_bar(ui, score, false, 120.0);
                                        ui.label(
                                            RichText::new(format!(
                                                "{} · changed {}",
                                                crate::strength::score_label(score),
                                                util::ago(item.password_changed, sh.now)
                                            ))
                                            .size(12.0)
                                            .color(p.faint),
                                        );
                                    });
                                }
                            }
                        }
                        if !item.totp.is_empty() {
                            sep(ui);
                            self.totp_row(ui, sh, item);
                        }
                        for url in item.urls.iter().filter(|u| !u.trim().is_empty()) {
                            sep(ui);
                            let mut open = false;
                            let mut copy = false;
                            Self::row(
                                ui,
                                "Web address",
                                |ui| {
                                    ui.add(egui::Label::new(RichText::new(url).size(14.5).color(p.accent)).truncate());
                                },
                                |ui| {
                                    if widgets::icon_button(ui, Icon::COPY, "Copy address").clicked() {
                                        copy = true;
                                    }
                                    if widgets::icon_button(ui, Icon::GLOBE, "Open in the browser").clicked() {
                                        open = true;
                                    }
                                },
                            );
                            if open {
                                if let Err(e) = crate::sys::open_url(url) {
                                    sh.toast(e, true);
                                }
                            }
                            if copy {
                                sh.copy_plain(url, "Address");
                            }
                        }
                        if first {
                            ui.label(RichText::new("Nothing filled in yet. Click Edit to add details.").color(p.faint));
                        }
                    });
                }

                let filled: Vec<(usize, &crate::model::CustomField)> = item
                    .fields
                    .iter()
                    .enumerate()
                    .filter(|(_, f)| !f.is_blank())
                    .collect();
                if !filled.is_empty() {
                    widgets::card(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 10.0;
                        for (n, (index, f)) in filled.iter().enumerate() {
                            if n > 0 {
                                widgets::divider(ui);
                            }
                            if f.hidden {
                                self.secret_row(ui, sh, &format!("f{index}"), &f.label, &f.secret, &f.label);
                            } else {
                                Self::plain_row(ui, sh, &f.label, &f.value, &f.label);
                            }
                        }
                    });
                }

                if !item.notes.is_empty() {
                    widgets::card(ui, |ui| {
                        let shown = self.revealed("notes");
                        let mut toggle = false;
                        let mut copy = false;
                        ui.horizontal(|ui| {
                            widgets::section(ui, "Notes");
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if widgets::icon_button(ui, Icon::COPY, "Copy notes").clicked() {
                                    copy = true;
                                }
                                let icon = if shown { Icon::HIDE } else { Icon::VIEW };
                                if widgets::icon_button(ui, icon, if shown { "Hide" } else { "Show for a moment" }).clicked() {
                                    toggle = true;
                                }
                            });
                        });
                        if shown {
                            let text = item.notes.open_str();
                            widgets::wrapped_label(ui, &text, regular(14.0), p.text, true);
                        } else {
                            ui.label(RichText::new("Hidden. Click the eye to read.").color(p.faint));
                        }
                        if toggle {
                            self.toggle_reveal(ui, sh, "notes");
                        }
                        if copy {
                            let text = item.notes.open_str();
                            sh.copy_secret(&text, "Notes");
                        }
                    });
                }

                if !item.recovery_codes.is_empty() {
                    widgets::card(ui, |ui| {
                        let shown = self.revealed("codes");
                        let mut toggle = false;
                        let left = item.recovery_codes.iter().filter(|c| !c.used).count();
                        ui.horizontal(|ui| {
                            widgets::section(ui, "Recovery codes");
                            ui.label(RichText::new(format!("{left} of {} unused", item.recovery_codes.len())).size(12.5).color(p.faint));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                let icon = if shown { Icon::HIDE } else { Icon::VIEW };
                                if widgets::icon_button(ui, icon, if shown { "Hide" } else { "Show for a moment" }).clicked() {
                                    toggle = true;
                                }
                            });
                        });
                        if shown {
                            let mut flip: Option<usize> = None;
                            let mut copy: Option<usize> = None;
                            for (n, code) in item.recovery_codes.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    let mut used = code.used;
                                    if widgets::checkbox(ui, &mut used, "").on_hover_text("Tick when this code has been used").clicked() {
                                        flip = Some(n);
                                    }
                                    let text = code.code.open_str();
                                    let mut rich = RichText::new(text.as_str()).monospace().size(14.0);
                                    if code.used {
                                        rich = rich.strikethrough().color(p.faint);
                                    }
                                    ui.label(rich);
                                    if !code.used && widgets::icon_button(ui, Icon::COPY, "Copy this code").clicked() {
                                        copy = Some(n);
                                    }
                                });
                            }
                            if let Some(n) = flip {
                                if let Some(c) = self.v.vault.item_mut(id).and_then(|i| i.recovery_codes.get_mut(n)) {
                                    c.used = !c.used;
                                    changed = true;
                                }
                            }
                            if let Some(n) = copy {
                                let text = item.recovery_codes[n].code.open_str();
                                sh.copy_secret(&text, "Recovery code");
                            }
                        } else {
                            ui.label(RichText::new("Hidden. Click the eye to see the codes and tick off used ones.").color(p.faint));
                        }
                        if toggle {
                            self.toggle_reveal(ui, sh, "codes");
                        }
                    });
                }

                // Attachments.
                if !trashed {
                    widgets::card(ui, |ui| {
                        let mut add = false;
                        ui.horizontal(|ui| {
                            widgets::section(ui, "Attachments");
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if widgets::ghost_button(ui, &Icon::ATTACH.with("Add file")).clicked() {
                                    add = true;
                                }
                            });
                        });
                        if dropping {
                            widgets::banner(ui, Icon::ATTACH, p.accent, "Drop the file here to store it in this item.");
                        } else if item.attachments.is_empty() {
                            ui.label(
                                RichText::new(format!(
                                    "Files are stored encrypted inside the vault (up to {} MB each). You can also drag a file onto this window.",
                                    sh.settings.attachment_limit_mb
                                ))
                                .color(p.faint),
                            );
                        }
                        let mut save_out = None;
                        let mut delete = None;
                        for (n, a) in item.attachments.iter().enumerate() {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(Icon::DOCUMENT.glyph()).color(p.muted));
                                widgets::line_label(ui, &a.name, regular(14.0), p.text);
                                ui.label(RichText::new(util::human_size(a.size)).size(12.5).color(p.faint));
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if widgets::icon_button(ui, Icon::DELETE, "Remove from the vault").clicked() {
                                        delete = Some(n);
                                    }
                                    if widgets::icon_button(ui, Icon::DOWNLOAD, "Save a copy to disk").clicked() {
                                        save_out = Some(n);
                                    }
                                });
                            });
                        }
                        if add && self.add_attachment(sh, id) {
                            changed = true;
                        }
                        if let Some(n) = save_out {
                            self.save_attachment(sh, &item.attachments[n]);
                        }
                        if let Some(n) = delete {
                            self.dialog = Some(Dialog::confirm(
                                "Remove this attachment?",
                                &format!("\"{}\" will be removed from the vault. Copies you saved elsewhere are not touched.", item.attachments[n].name),
                                "Remove",
                                ConfirmAction::DeleteAttachment(id, n),
                            ));
                        }
                    });
                }

                if !item.history.is_empty() {
                    widgets::card(ui, |ui| {
                        let shown = self.revealed("history");
                        let mut toggle = false;
                        ui.horizontal(|ui| {
                            widgets::section(ui, "Password history");
                            ui.label(RichText::new(format!("{} earlier", item.history.len())).size(12.5).color(p.faint));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                let icon = if shown { Icon::HIDE } else { Icon::VIEW };
                                if widgets::icon_button(ui, icon, if shown { "Hide" } else { "Show for a moment" }).clicked() {
                                    toggle = true;
                                }
                            });
                        });
                        if shown {
                            let mut restore = None;
                            let mut copy = None;
                            for (n, h) in item.history.iter().enumerate() {
                                ui.horizontal(|ui| {
                                    let text = h.password.open_str();
                                    ui.add_sized(
                                        vec2(ui.available_width() - 250.0, 20.0),
                                        egui::Label::new(RichText::new(text.as_str()).monospace().size(13.5)).truncate(),
                                    );
                                    ui.label(RichText::new(format!("until {}", util::fmt_date(h.replaced))).size(12.5).color(p.faint));
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                        if !trashed && widgets::icon_button(ui, Icon::UNDO, "Make this the current password again").clicked() {
                                            restore = Some(n);
                                        }
                                        if widgets::icon_button(ui, Icon::COPY, "Copy").clicked() {
                                            copy = Some(n);
                                        }
                                    });
                                });
                            }
                            if let Some(n) = copy {
                                let text = item.history[n].password.open_str();
                                sh.copy_secret(&text, "Old password");
                            }
                            if let Some(n) = restore {
                                self.dialog = Some(Dialog::confirm_plain(
                                    "Restore this password?",
                                    "The old password becomes the current one again. The password it replaces is kept in the history.",
                                    "Restore",
                                    ConfirmAction::RestoreHistory(id, n),
                                ));
                            }
                        } else {
                            ui.label(RichText::new("Earlier passwords are kept with the date they were replaced.").color(p.faint));
                        }
                        if toggle {
                            self.toggle_reveal(ui, sh, "history");
                        }
                    });
                }

                ui.label(
                    RichText::new(format!(
                        "Created {} · Changed {}",
                        util::fmt_datetime(item.created),
                        util::fmt_datetime(item.modified)
                    ))
                    .size(12.0)
                    .color(p.faint),
                );
                ui.add_space(8.0);
            });
        if changed {
            self.changed(&ctx, sh);
        }
        if !self.reveal.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_millis(500));
        }
    }

    /// The live one-time code with its countdown ring.
    fn totp_row(&mut self, ui: &mut Ui, sh: &mut Shared, item: &Item) {
        let p = pal(ui);
        let seed = item.totp.open_str();
        let parsed = crate::totp::Totp::parse(&seed);
        let mut copy = false;
        Self::row(
            ui,
            "One-time code",
            |ui| match &parsed {
                Ok(t) => {
                    let now = sh.now as u64;
                    let code = zeroize::Zeroizing::new(t.code_at(now));
                    let left = t.remaining(now);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(crate::totp::spaced(&code))
                                .monospace()
                                .size(20.0)
                                .color(if left <= 5 { p.warn } else { p.text }),
                        );
                        let (rect, _) = ui.allocate_exact_size(vec2(26.0, 26.0), Sense::hover());
                        widgets::paint_ring(
                            ui,
                            rect.center(),
                            10.0,
                            3.0,
                            left as f32 / t.period as f32,
                            if left <= 5 { p.warn } else { p.accent },
                        );
                        ui.label(RichText::new(format!("{left} s")).size(12.0).color(p.faint));
                    });
                }
                Err(e) => {
                    ui.colored_label(p.danger, e.to_string());
                }
            },
            |ui| {
                if widgets::icon_button(ui, Icon::COPY, "Copy the code (Ctrl+T)").clicked() {
                    copy = true;
                }
            },
        );
        if copy {
            self.copy_totp(sh, item.id);
        }
    }

    /// Asks for a file and stores it encrypted in the vault.
    fn add_attachment(&mut self, sh: &mut Shared, id: Id) -> bool {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Attach a file")
            .pick_file()
        else {
            return false;
        };
        self.attach_path(sh, id, &path)
    }

    /// Stores one file from disk in the item (the button and drag-and-drop).
    fn attach_path(&mut self, sh: &mut Shared, id: Id, path: &std::path::Path) -> bool {
        if path.is_dir() {
            sh.toast(
                "Folders cannot be attached. Drop the files themselves.",
                true,
            );
            return false;
        }
        let limit = u64::from(sh.settings.attachment_limit_mb) * 1024 * 1024;
        let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(u64::MAX);
        if size > limit {
            sh.toast(
                format!(
                    "That file is larger than the limit of {} MB (you can change the limit in Settings).",
                    sh.settings.attachment_limit_mb
                ),
                true,
            );
            return false;
        }
        match std::fs::read(path) {
            Ok(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "file".into());
                if self.v.add_attachment(id, &name, &bytes) {
                    sh.toast(format!("\"{name}\" is now stored in the vault. The original file is still on disk."), false);
                    true
                } else {
                    false
                }
            }
            Err(e) => {
                sh.toast(format!("Could not read the file: {e}"), true);
                false
            }
        }
    }

    fn save_attachment(&mut self, sh: &mut Shared, att: &crate::model::Attachment) {
        let Some(path) = rfd::FileDialog::new()
            .set_title("Save a copy of the attachment")
            .set_file_name(crate::kfx::safe_name(&att.name))
            .save_file()
        else {
            return;
        };
        match self.v.read_attachment(att) {
            Ok(bytes) => match std::fs::write(&path, &bytes[..]) {
                Ok(()) => sh.toast("Saved. That copy is not encrypted.", false),
                Err(e) => sh.toast(format!("Could not save the file: {e}"), true),
            },
            Err(e) => sh.toast(e.to_string(), true),
        }
    }
}
