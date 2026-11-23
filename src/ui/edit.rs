//! Creating and editing an item, with the inline password generator.
//! Everything secret in the form lives in wiping buffers; the form is
//! dropped (and so wiped) on save, cancel and lock.

use super::app::Shared;
use super::main_view::Main;
use super::start::{strength_block, StrengthCache};
use super::theme::{pal, semibold, Icon};
use super::widgets;
use crate::generator::{self, OsRng, PasswordOptions, PhraseOptions};
use crate::model::{CustomField, Id, Item, Kind, RecoveryCode, Vault};
use crate::secret::{Protected, SecretInput};
use eframe::egui::{self, vec2, Align, Layout, RichText, Ui};

pub struct FieldForm {
    pub label: String,
    pub hidden: bool,
    pub value: SecretInput,
    show: bool,
}

pub struct EditForm {
    pub id: Option<Id>,
    pub kind: Kind,
    pub title: String,
    pub username: String,
    pub password: SecretInput,
    show_password: bool,
    strength: StrengthCache,
    pub urls: Vec<String>,
    pub totp: SecretInput,
    show_totp: bool,
    pub notes: SecretInput,
    pub folder: String,
    pub tags: String,
    pub favourite: bool,
    pub fields: Vec<FieldForm>,
    pub autotype: String,
    pub expires: String,
    pub recovery: SecretInput,
    /// Codes already marked as used (kept when the list is edited).
    used_codes: Vec<Protected>,
    pub gen_open: bool,
    gen_phrase: bool,
    gen_opts: PasswordOptions,
    phrase_opts: PhraseOptions,
    candidate: SecretInput,
    error: Option<String>,
}

const NOTES_CAPACITY: usize = 64 * 1024;

impl EditForm {
    pub fn blank(kind: Kind, sh: &Shared) -> EditForm {
        EditForm {
            id: None,
            kind,
            title: String::new(),
            username: String::new(),
            password: SecretInput::new(),
            show_password: false,
            strength: StrengthCache::default(),
            urls: if kind.has_urls() {
                vec![String::new()]
            } else {
                Vec::new()
            },
            totp: SecretInput::new(),
            show_totp: false,
            notes: SecretInput::with_capacity(NOTES_CAPACITY),
            folder: String::new(),
            tags: String::new(),
            favourite: false,
            fields: kind
                .template()
                .iter()
                .map(|(label, hidden)| FieldForm {
                    label: label.to_string(),
                    hidden: *hidden,
                    value: SecretInput::new(),
                    show: false,
                })
                .collect(),
            autotype: String::new(),
            expires: String::new(),
            recovery: SecretInput::with_capacity(8 * 1024),
            used_codes: Vec::new(),
            gen_open: false,
            gen_phrase: sh.settings.generator_phrase,
            gen_opts: sh.settings.generator.clone(),
            phrase_opts: sh.settings.phrase.clone(),
            candidate: SecretInput::new(),
            error: None,
        }
    }

    pub fn from_item(item: &Item, vault: &Vault, sh: &Shared) -> EditForm {
        let mut form = EditForm::blank(item.kind, sh);
        form.id = Some(item.id);
        form.title = item.title.clone();
        form.username = item.username.clone();
        form.password.set(&item.password.open_str());
        form.urls = item.urls.clone();
        if form.urls.is_empty() && item.kind.has_urls() {
            form.urls.push(String::new());
        }
        form.totp.set(&item.totp.open_str());
        form.notes.set(&item.notes.open_str());
        form.folder = vault.folder_name(item.folder).unwrap_or("").to_string();
        form.tags = item.tags.join(", ");
        form.favourite = item.favourite;
        form.fields = item
            .fields
            .iter()
            .map(|f| FieldForm {
                label: f.label.clone(),
                hidden: f.hidden,
                value: SecretInput::with_text(&f.text()),
                show: false,
            })
            .collect();
        form.autotype = item.autotype.clone();
        form.expires = item
            .expires
            .map(crate::util::fmt_iso_date)
            .unwrap_or_default();
        let mut codes = zeroize::Zeroizing::new(String::new());
        for c in &item.recovery_codes {
            if !codes.is_empty() {
                codes.push('\n');
            }
            codes.push_str(&c.code.open_str());
            if c.used {
                form.used_codes.push(c.code.clone());
            }
        }
        form.recovery.set(&codes);
        form
    }

    /// Opens the generator with a first suggestion.
    pub fn open_generator(&mut self) {
        self.gen_open = true;
        self.regenerate();
    }

    fn regenerate(&mut self) {
        let fresh = if self.gen_phrase {
            generator::passphrase(&self.phrase_opts, &mut OsRng)
        } else {
            generator::password(&self.gen_opts, &mut OsRng)
        };
        self.candidate.set(&fresh);
    }

    /// For screenshots: a fixed, invented suggestion instead of a random one.
    pub fn demo_generator(&mut self) {
        self.gen_open = true;
        self.gen_phrase = false;
        self.candidate.set("m7#Qv2!xLp9@Wz4&Tr6k");
    }
}

/// Generator options shared by the edit form and the Generator page.
/// Returns true when something changed.
pub(super) fn generator_options(
    ui: &mut Ui,
    phrase_mode: &mut bool,
    opts: &mut PasswordOptions,
    phrase: &mut PhraseOptions,
) -> bool {
    let p = pal(ui);
    let before = (*phrase_mode, opts.clone(), phrase.clone());
    if let Some(i) = widgets::segmented(ui, &["Password", "Passphrase"], usize::from(*phrase_mode))
    {
        *phrase_mode = i == 1;
    }
    ui.add_space(2.0);
    if *phrase_mode {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Words").color(p.muted));
            let mut n = phrase.word_count();
            ui.add(egui::Slider::new(&mut n, 3..=12));
            phrase.words = n;
        });
        ui.horizontal(|ui| {
            ui.label(RichText::new("Separator").color(p.muted));
            for (label, sep) in [("-", "-"), ("space", " "), (".", "."), ("_", "_")] {
                if widgets::chip(ui, label, None, phrase.separator == sep).clicked() {
                    phrase.separator = sep.to_string();
                }
            }
        });
        ui.horizontal(|ui| {
            widgets::checkbox(ui, &mut phrase.capitalise, "Capitalise");
            ui.add_space(8.0);
            widgets::checkbox(ui, &mut phrase.add_number, "Add a number");
        });
    } else {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Length").color(p.muted));
            let mut n = opts.length();
            ui.add(egui::Slider::new(
                &mut n,
                generator::MIN_LENGTH..=generator::MAX_LENGTH,
            ));
            opts.length = n;
        });
        ui.horizontal_wrapped(|ui| {
            widgets::checkbox(ui, &mut opts.upper, "A–Z");
            ui.add_space(6.0);
            widgets::checkbox(ui, &mut opts.lower, "a–z");
            ui.add_space(6.0);
            widgets::checkbox(ui, &mut opts.digits, "0–9");
            ui.add_space(6.0);
            widgets::checkbox(ui, &mut opts.symbols, "!@#$");
            ui.add_space(6.0);
            widgets::checkbox(
                ui,
                &mut opts.exclude_lookalikes,
                "No look-alikes (0 O 1 l I)",
            );
        });
        if !(opts.upper || opts.lower || opts.digits || opts.symbols) {
            opts.lower = true;
        }
    }
    before != (*phrase_mode, opts.clone(), phrase.clone())
}

impl Main {
    pub(super) fn edit_ui(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        let mut save = false;
        let mut cancel = false;
        let folders: Vec<String> = self
            .v
            .vault
            .folders
            .iter()
            .map(|f| f.name.clone())
            .collect();
        let Some(form) = self.edit.as_mut() else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(if form.id.is_some() {
                    format!("Edit {}", form.kind.label().to_lowercase())
                } else {
                    format!("New {}", form.kind.label().to_lowercase())
                })
                .font(semibold(22.0)),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if widgets::primary_button(ui, &Icon::SAVE.with("Save"), true)
                    .on_hover_text("Save (Ctrl+S)")
                    .clicked()
                {
                    save = true;
                }
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    cancel = true;
                }
            });
        });
        if ui.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::S)) {
            save = true;
        }
        if let Some(e) = &form.error {
            widgets::banner(ui, Icon::ERROR, p.danger, e);
        }
        ui.add_space(4.0);
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_max_width((ui.available_width() - 12.0).min(760.0));
                ui.spacing_mut().item_spacing.y = 10.0;
                widgets::card(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 5.0;
                    let w = ui.available_width();
                    widgets::caption(ui, "Title");
                    let title = widgets::text_input(ui, &mut form.title, "For example: Example Mail", w);
                    if form.id.is_none() && form.title.is_empty() && !form.gen_open {
                        title.request_focus();
                    }
                    if super::bidi::needs_native(&form.title) {
                        // The text box cannot join Kurdish or Arabic letters;
                        // this line shows the title as it will appear.
                        ui.horizontal(|ui| {
                            widgets::caption(ui, "Shown as");
                            super::bidi::label(ui, form.title.trim(), 14.5, true, p.text);
                        });
                    }
                    if let Some(label) = form.kind.username_label() {
                        ui.add_space(2.0);
                        widgets::caption(ui, label);
                        widgets::text_input(ui, &mut form.username, "", w);
                    }
                    if let Some(label) = form.kind.password_label() {
                        ui.add_space(2.0);
                        widgets::caption(ui, label);
                        ui.horizontal(|ui| {
                            widgets::secret_input(ui, &mut form.password, form.show_password, "", w - 172.0);
                            let icon = if form.show_password { Icon::HIDE } else { Icon::VIEW };
                            if widgets::icon_button(ui, icon, "Show or hide").clicked() {
                                form.show_password = !form.show_password;
                            }
                            if widgets::ghost_button(ui, &Icon::SHUFFLE.with("Generate")).clicked() {
                                if form.gen_open {
                                    form.gen_open = false;
                                } else {
                                    form.open_generator();
                                }
                            }
                        });
                        if form.kind != Kind::Licence {
                            let empty = form.password.is_empty();
                            let s = form.strength.get(form.password.as_str()).clone();
                            strength_block(ui, &s, empty, w);
                        }
                        if form.gen_open {
                            ui.add_space(2.0);
                            egui::Frame::new()
                                .fill(p.bg)
                                .stroke(egui::Stroke::new(1.0_f32, p.border))
                                .corner_radius(egui::CornerRadius::same(10))
                                .inner_margin(egui::Margin::same(12))
                                .show(ui, |ui| {
                                    ui.set_width(ui.available_width());
                                    ui.spacing_mut().item_spacing.y = 6.0;
                                    ui.horizontal(|ui| {
                                        ui.add(
                                            egui::Label::new(
                                                RichText::new(form.candidate.as_str())
                                                    .monospace()
                                                    .size(15.0)
                                                    .color(p.text),
                                            )
                                            .wrap(),
                                        );
                                    });
                                    let bits = if form.gen_phrase {
                                        form.phrase_opts.entropy_bits()
                                    } else {
                                        form.gen_opts.entropy_bits()
                                    };
                                    ui.label(
                                        RichText::new(format!("{bits:.0} bits of entropy"))
                                            .size(12.5)
                                            .color(p.muted),
                                    );
                                    if generator_options(
                                        ui,
                                        &mut form.gen_phrase,
                                        &mut form.gen_opts,
                                        &mut form.phrase_opts,
                                    ) {
                                        form.regenerate();
                                    }
                                    ui.horizontal(|ui| {
                                        if widgets::primary_button(ui, "Use this password", true).clicked() {
                                            form.password.set(form.candidate.as_str());
                                            form.candidate.wipe();
                                            form.gen_open = false;
                                            // Remember these options as the defaults.
                                            sh.settings.generator = form.gen_opts.clone();
                                            sh.settings.phrase = form.phrase_opts.clone();
                                            sh.settings.generator_phrase = form.gen_phrase;
                                        }
                                        if widgets::ghost_button(ui, &Icon::REFRESH.with("Another")).clicked() {
                                            form.regenerate();
                                        }
                                    });
                                });
                        }
                    }
                    if form.kind.has_urls() {
                        ui.add_space(2.0);
                        widgets::caption(ui, "Web addresses");
                        let mut remove = None;
                        let many = form.urls.len() > 1;
                        for (n, url) in form.urls.iter_mut().enumerate() {
                            ui.horizontal(|ui| {
                                widgets::text_input(ui, url, "https://", w - if many { 44.0 } else { 0.0 });
                                if many && widgets::icon_button(ui, Icon::CLOSE, "Remove this address").clicked() {
                                    remove = Some(n);
                                }
                            });
                        }
                        if let Some(n) = remove {
                            form.urls.remove(n);
                        }
                        if widgets::link(ui, "+ Add another address").clicked() {
                            form.urls.push(String::new());
                        }
                    }
                    if form.kind.has_totp() {
                        ui.add_space(2.0);
                        widgets::caption(ui, "One-time code (authenticator) setup key");
                        ui.horizontal(|ui| {
                            widgets::secret_input(
                                ui,
                                &mut form.totp,
                                form.show_totp,
                                "Paste the setup key or the otpauth:// link",
                                w - 44.0,
                            );
                            let icon = if form.show_totp { Icon::HIDE } else { Icon::VIEW };
                            if widgets::icon_button(ui, icon, "Show or hide").clicked() {
                                form.show_totp = !form.show_totp;
                            }
                        });
                        if !form.totp.is_empty() {
                            if let Err(e) = crate::totp::Totp::parse(form.totp.as_str()) {
                                ui.colored_label(p.danger, e.to_string());
                            }
                        }
                    }
                });

                widgets::card(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 5.0;
                    let w = ui.available_width();
                    widgets::section(ui, if form.kind == Kind::Login { "Custom fields" } else { "Details" });
                    let mut remove = None;
                    for (n, f) in form.fields.iter_mut().enumerate() {
                        ui.horizontal(|ui| {
                            widgets::text_input(ui, &mut f.label, "Field name", 190.0);
                            let show = !f.hidden || f.show;
                            widgets::secret_input(ui, &mut f.value, show, "", w - 190.0 - 96.0);
                            if f.hidden {
                                let icon = if f.show { Icon::HIDE } else { Icon::VIEW };
                                if widgets::icon_button(ui, icon, "Show or hide").clicked() {
                                    f.show = !f.show;
                                }
                            } else {
                                ui.add_space(40.0);
                            }
                            if widgets::icon_button(ui, Icon::CLOSE, "Remove this field").clicked() {
                                remove = Some(n);
                            }
                        });
                    }
                    if let Some(n) = remove {
                        form.fields.remove(n);
                    }
                    ui.horizontal(|ui| {
                        if widgets::link(ui, "+ Add a field").clicked() {
                            form.fields.push(FieldForm {
                                label: String::new(),
                                hidden: false,
                                value: SecretInput::new(),
                                show: false,
                            });
                        }
                        ui.add_space(12.0);
                        if widgets::link(ui, "+ Add a hidden field").clicked() {
                            form.fields.push(FieldForm {
                                label: String::new(),
                                hidden: true,
                                value: SecretInput::new(),
                                show: false,
                            });
                        }
                    });
                });

                widgets::card(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 5.0;
                    let w = ui.available_width();
                    widgets::section(ui, "Notes");
                    widgets::text_area(ui, &mut form.notes, "Anything else worth keeping with this item", w, 4);
                    if form.kind == Kind::Login {
                        ui.add_space(4.0);
                        widgets::section(ui, "Recovery codes");
                        widgets::note(ui, "Backup codes for two-step login, one per line. You can tick them off as you use them.");
                        widgets::text_area(ui, &mut form.recovery, "", w, 3);
                    }
                });

                widgets::card(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 5.0;
                    let w = ui.available_width();
                    widgets::section(ui, "Organise");
                    let half = (w - 12.0) / 2.0;
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.set_width(half);
                            widgets::caption(ui, "Folder");
                            ui.horizontal(|ui| {
                                widgets::text_input(ui, &mut form.folder, "No folder", half - 44.0);
                                ui.menu_button(RichText::new(Icon::CHEVRON_DOWN.glyph()).size(12.0), |ui| {
                                    if ui.button("No folder").clicked() {
                                        form.folder.clear();
                                        ui.close_menu();
                                    }
                                    for name in &folders {
                                        if ui.button(name).clicked() {
                                            form.folder = name.clone();
                                            ui.close_menu();
                                        }
                                    }
                                });
                            });
                        });
                        ui.add_space(4.0);
                        ui.vertical(|ui| {
                            ui.set_width(half);
                            widgets::caption(ui, "Tags (separate with commas)");
                            widgets::text_input(ui, &mut form.tags, "work, family", half);
                        });
                    });
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.set_width(half);
                            widgets::caption(ui, "Expires on (optional)");
                            widgets::text_input(ui, &mut form.expires, "YYYY-MM-DD", half);
                        });
                        ui.add_space(4.0);
                        ui.vertical(|ui| {
                            ui.set_width(half);
                            widgets::caption(ui, "Favourite");
                            ui.horizontal(|ui| {
                                if widgets::toggle(ui, form.favourite, true).clicked() {
                                    form.favourite = !form.favourite;
                                }
                                ui.label(RichText::new("Show in Favourites").color(p.muted));
                            });
                        });
                    });
                    if form.kind == Kind::Login {
                        widgets::caption(ui, "Auto-type sequence (leave empty for the usual one)");
                        widgets::text_input(ui, &mut form.autotype, crate::autotype::DEFAULT_SEQUENCE, w);
                        widgets::note(ui, "Placeholders: {USERNAME} {PASSWORD} {TOTP} {TAB} {ENTER} {DELAY 200}");
                    }
                });
                ui.add_space(vec2(0.0, 10.0).y);
            });
        if cancel {
            self.edit = None;
        } else if save {
            self.save_edit(&ctx, sh);
        }
    }

    fn save_edit(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        let Some(form) = self.edit.as_mut() else {
            return;
        };
        // Validate first; nothing is changed if something is wrong.
        let problem = if form.title.trim().is_empty() {
            Some("Give the item a title.".to_string())
        } else if !form.totp.is_empty() {
            crate::totp::Totp::parse(form.totp.as_str())
                .err()
                .map(|e| e.to_string())
        } else {
            None
        }
        .or_else(|| {
            (!form.autotype.trim().is_empty())
                .then(|| crate::autotype::parse_sequence(&form.autotype).err())
                .flatten()
                .map(|e| format!("Auto-type sequence: {e}"))
        });
        let expires = if form.expires.trim().is_empty() {
            Ok(None)
        } else {
            crate::util::parse_iso_date(&form.expires)
                .map(Some)
                .ok_or("\"Expires on\" needs a date such as 2027-06-30.".to_string())
        };
        let expires = match (problem, expires) {
            (Some(e), _) | (None, Err(e)) => {
                form.error = Some(e);
                return;
            }
            (None, Ok(x)) => x,
        };
        let Some(form) = self.edit.take() else { return };
        let session = self.v.session.clone();
        let now = sh.now;
        let folder = self.v.vault.folder_id(&form.folder);
        let id = match form.id {
            Some(id) => id,
            None => {
                let item = Item {
                    fields: Vec::new(),
                    ..Item::new(form.kind, now)
                };
                let id = item.id;
                self.v.vault.items.push(item);
                id
            }
        };
        let Some(item) = self.v.vault.item_mut(id) else {
            return;
        };
        item.title = form.title.trim().to_string();
        item.username = form.username.trim().to_string();
        item.set_password(&session, form.password.as_str(), now);
        item.urls = form
            .urls
            .iter()
            .map(|u| u.trim().to_string())
            .filter(|u| !u.is_empty())
            .collect();
        item.totp = Protected::seal_str(&session, form.totp.as_str().trim());
        item.notes = Protected::seal_str(&session, form.notes.as_str());
        item.folder = folder;
        item.tags = form
            .tags
            .split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect();
        item.favourite = form.favourite;
        item.fields = form
            .fields
            .iter()
            .filter(|f| !f.label.trim().is_empty() || !f.value.is_empty())
            .map(|f| {
                let label = if f.label.trim().is_empty() {
                    "Field"
                } else {
                    f.label.trim()
                };
                if f.hidden {
                    CustomField::hidden(&session, label, f.value.as_str())
                } else {
                    CustomField::plain(label, f.value.as_str())
                }
            })
            .collect();
        item.autotype = form.autotype.trim().to_string();
        item.expires = expires;
        item.recovery_codes = form
            .recovery
            .as_str()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(|code| {
                let sealed = Protected::seal_str(&session, code);
                RecoveryCode {
                    used: form.used_codes.iter().any(|u| u.same_secret(&sealed)),
                    code: sealed,
                }
            })
            .collect();
        item.modified = now;
        drop(form);
        self.selected = Some(id);
        self.reveal.clear();
        sh.toast("Saved", false);
        self.changed(ctx, sh);
    }
}
