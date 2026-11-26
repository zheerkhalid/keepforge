//! The unlocked window: header, navigation rail, item list, and the state
//! every page of an open vault shares. Dropping [`Main`] locks the vault.

use super::app::{Go, Msg, Shared};
use super::dialogs::{ConfirmAction, Dialog};
use super::edit::EditForm;
use super::theme::{pal, pal_ctx, regular, semibold, Icon};
use super::widgets;
use crate::autotype;
use crate::health::Report;
use crate::model::{Id, Item, Kind};
use crate::settings::SortOrder;
use crate::store::{OpenVault, SaveError};
use eframe::egui::{
    self, vec2, Align, Align2, Color32, CornerRadius, Frame, Key, Layout, Margin, Rect, RichText,
    Sense, Stroke, TextureHandle, Ui,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Nav {
    All,
    Favourites,
    Kind(Kind),
    Folder(Id),
    Tag(String),
    Trash,
    Health,
    Exposure,
    Authenticator,
    Generator,
    Tools,
    Settings,
}

impl Nav {
    pub fn is_list(&self) -> bool {
        matches!(
            self,
            Nav::All | Nav::Favourites | Nav::Kind(_) | Nav::Folder(_) | Nav::Tag(_) | Nav::Trash
        )
    }
}

pub fn kind_icon(kind: Kind) -> Icon {
    match kind {
        Kind::Login => Icon::KEY,
        Kind::Card => Icon::CARD,
        Kind::Identity => Icon::CONTACT,
        Kind::Note => Icon::NOTE,
        Kind::Wifi => Icon::WIFI,
        Kind::Licence => Icon::CERTIFICATE,
    }
}

#[derive(Clone, PartialEq)]
struct ListKey {
    rev: u64,
    nav: Nav,
    search: String,
    fav_only: bool,
    kind: Option<Kind>,
    search_hidden: bool,
    sort: SortOrder,
}

/// Height of one row of the item list.
const ROW: f32 = 58.0;

/// Orders list rows: by title, or newest first with the title as tie-break.
pub fn sort_items(items: &mut [&Item], order: SortOrder) {
    match order {
        SortOrder::Title => items.sort_by_cached_key(|i| i.title.to_lowercase()),
        SortOrder::Changed => {
            items.sort_by_cached_key(|i| (std::cmp::Reverse(i.modified), i.title.to_lowercase()))
        }
        SortOrder::Created => {
            items.sort_by_cached_key(|i| (std::cmp::Reverse(i.created), i.title.to_lowercase()))
        }
    }
}

/// Where the selection lands after a navigation key. `current` is the
/// position of the selected row, if it is in the list.
pub fn step_selection(current: Option<usize>, len: usize, key: Key, page: usize) -> Option<usize> {
    if len == 0 {
        return None;
    }
    let last = len - 1;
    Some(match (key, current) {
        (Key::Home, _) => 0,
        (Key::End, _) => last,
        (Key::ArrowDown | Key::PageDown | Key::Enter, None) => 0,
        (Key::ArrowUp | Key::PageUp, None) => last,
        (Key::ArrowDown, Some(n)) => (n + 1).min(last),
        (Key::ArrowUp, Some(n)) => n.saturating_sub(1),
        (Key::PageDown, Some(n)) => (n + page.max(1)).min(last),
        (Key::PageUp, Some(n)) => n.saturating_sub(page.max(1)),
        (_, Some(n)) => n.min(last),
        (_, None) => return None,
    })
}

pub struct Main {
    pub v: OpenVault,
    /// Bumped on every change to the vault.
    pub rev: u64,
    pub nav: Nav,
    pub search: String,
    focus_search: bool,
    /// Bring the selected row into view on the next frame.
    pub(super) scroll_to_selected: bool,
    /// Rows that fit in the list (for Page Up / Page Down).
    list_page: usize,
    pub fav_only: bool,
    pub kind_filter: Option<Kind>,
    pub selected: Option<Id>,
    pub edit: Option<Box<EditForm>>,
    /// Revealed secrets: key → egui time at which they hide again.
    pub reveal: HashMap<String, f64>,
    list_cache: Option<(ListKey, Vec<Id>)>,
    saving: bool,
    save_again: bool,
    pub last_saved: Option<i64>,
    pub save_error: Option<String>,
    lock_pending: Option<bool>,
    pub health: Option<(u64, Report)>,
    health_running: Option<u64>,
    pub health_cancel: Arc<AtomicBool>,
    /// Passwords found in known breaches: item → times seen.
    pub pwned: HashMap<Id, u64>,
    pub pwned_progress: Option<(usize, usize)>,
    pub pwned_done: bool,
    pub pwned_error: Option<String>,
    pub pwned_cancel: Arc<AtomicBool>,
    pub ranges: Arc<Mutex<crate::hibp::RangeCache>>,
    pub pages: super::pages::PageState,
    pub exp: super::exposure::ExposureState,
    pub tools: super::tools::Tools,
    pub dialog: Option<Dialog>,
    pub kdf_secs: Option<f64>,
    pub typing: bool,
    /// Cached strength of the selected item's password: (item, revision, score).
    pub pw_score: Option<(Id, u64, u8)>,
}

impl Main {
    pub fn new(v: OpenVault, kdf_secs: Option<f64>) -> Main {
        let exp = super::exposure::ExposureState::new(&v.vault);
        Main {
            v,
            rev: 1,
            nav: Nav::All,
            search: String::new(),
            focus_search: false,
            scroll_to_selected: false,
            list_page: 8,
            fav_only: false,
            kind_filter: None,
            selected: None,
            edit: None,
            reveal: HashMap::new(),
            list_cache: None,
            saving: false,
            save_again: false,
            last_saved: None,
            save_error: None,
            lock_pending: None,
            health: None,
            health_running: None,
            health_cancel: Arc::new(AtomicBool::new(false)),
            pwned: HashMap::new(),
            pwned_progress: None,
            pwned_done: false,
            pwned_error: None,
            pwned_cancel: Arc::new(AtomicBool::new(false)),
            ranges: Arc::new(Mutex::new(crate::hibp::RangeCache::default())),
            pages: super::pages::PageState::default(),
            exp,
            tools: super::tools::Tools::default(),
            dialog: None,
            kdf_secs,
            typing: false,
            pw_score: None,
        }
    }

    pub fn offer_emergency_sheet(&mut self) {
        self.dialog = Some(Dialog::Emergency);
    }

    /// Demo only: invented results of the two online checks.
    pub fn demo_online_results(&mut self) {
        for i in &self.v.vault.items {
            if i.title == "Pixel Forum" {
                self.pwned.insert(i.id, 184_320);
            }
        }
        self.pwned_done = true;
        self.exp.cache = crate::demo::exposure_cache(crate::util::now());
        self.exp.generation += 1;
    }

    /// A message that arrives while the program is closing: only the result
    /// of a save matters then.
    pub fn save_finished_on_exit(&mut self, msg: Msg) {
        if let Msg::Saved(result) = msg {
            self.saving = false;
            self.save_again = false;
            if let Ok(done) = result {
                self.v.saved(&done);
            }
        }
    }

    /// Something is still running that a screenshot should wait for.
    pub fn busy(&self) -> bool {
        self.health_running.is_some()
    }

    pub fn saving_in_flight(&self) -> bool {
        self.saving || self.save_again
    }

    /// Lock as soon as the save that is under way has finished.
    pub fn lock_after_save(&mut self, close: bool) {
        self.lock_pending = Some(close);
    }

    // ----------------------------------------------------------------------------------
    // Changes and saving
    // ----------------------------------------------------------------------------------

    /// Call after every change to the vault: refreshes caches and saves.
    pub fn changed(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        self.exposure_sync();
        self.rev += 1;
        self.list_cache = None;
        self.request_save(ctx, sh, false);
    }

    pub fn request_save(&mut self, ctx: &egui::Context, sh: &mut Shared, force: bool) {
        if self.v.path.is_none() {
            // The demo vault lives in memory only.
            return;
        }
        if self.saving {
            self.save_again = true;
            return;
        }
        if let Some(mut job) = self.v.save_job(sh.settings.backups, sh.now) {
            job.force = force;
            self.saving = true;
            sh.spawn(ctx, move || Msg::Saved(job.run()));
        }
    }

    pub fn message(&mut self, ctx: &egui::Context, sh: &mut Shared, msg: Msg) -> Option<Go> {
        match msg {
            Msg::Saved(result) => {
                self.saving = false;
                match result {
                    Ok(done) => {
                        self.v.saved(&done);
                        self.last_saved = Some(done.at);
                        self.save_error = None;
                        if self.save_again {
                            self.save_again = false;
                            self.request_save(ctx, sh, false);
                        }
                    }
                    Err(SaveError::ChangedOnDisk) => {
                        self.save_again = false;
                        if self.lock_pending.is_none() {
                            self.dialog = Some(Dialog::Conflict);
                        }
                        self.save_error =
                            Some("The vault file was changed by another device or program.".into());
                    }
                    Err(SaveError::Io(e)) => {
                        self.save_again = false;
                        self.save_error = Some(e.clone());
                        sh.toast(e, true);
                    }
                }
                if !self.saving {
                    if let Some(close) = self.lock_pending.take() {
                        if let Some(e) = &self.save_error {
                            sh.toast(format!("The last change was not saved. {e}"), true);
                        }
                        return Some(if close { Go::LockAndClose } else { Go::Lock });
                    }
                }
            }
            Msg::Health(rev, report) => {
                self.health_running = None;
                if !report.cancelled {
                    self.health = Some((rev, report));
                }
            }
            Msg::Pwned(id, result) => match result {
                Ok(count) => {
                    if count > 0 {
                        self.pwned.insert(id, count);
                    }
                    if let Some((done, _)) = &mut self.pwned_progress {
                        *done += 1;
                    }
                }
                Err(e) => self.pwned_error = Some(e),
            },
            Msg::PwnedDone => {
                self.pwned_progress = None;
                self.pwned_done = self.pwned_error.is_none();
            }
            Msg::AutoTyped(result) => {
                self.typing = false;
                if let Err(e) = result {
                    crate::sys::show_and_focus(sh.hwnd);
                    sh.toast(e, true);
                }
            }
            Msg::NewSealer(result, secs) => self.new_sealer(ctx, sh, result, secs),
            Msg::ImportLoaded(result) => self.import_loaded(sh, result),
            Msg::Exposure(e) => self.exposure_event(ctx, sh, e),
            Msg::Sites(e) => self.sites_event(ctx, sh, e),
            Msg::SiteList(result) => self.site_list_arrived(ctx, sh, result),
            Msg::PwChecked(results) => {
                self.exp.pw_busy = false;
                self.exp.pw_results = results;
            }
            Msg::Peer(result) => self.pages.peer_result(result),
            Msg::Tool(m) => self.tools.message(sh, m),
            Msg::Calibrated(_) | Msg::Unlocked(..) | Msg::Created(..) | Msg::Toast(..) => {}
        }
        None
    }

    /// Starts the health analysis if the cached one is out of date.
    pub fn ensure_health(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        let fresh = self.health.as_ref().map(|(rev, _)| *rev) == Some(self.rev);
        if fresh || self.health_running == Some(self.rev) {
            return;
        }
        self.health_cancel.store(true, Ordering::Relaxed);
        self.health_cancel = Arc::new(AtomicBool::new(false));
        self.health_running = Some(self.rev);
        let (items, rev, months, now, cancel) = (
            self.v.vault.items.clone(),
            self.rev,
            sh.settings.old_password_months,
            sh.now,
            self.health_cancel.clone(),
        );
        sh.spawn(ctx, move || {
            Msg::Health(
                rev,
                crate::health::analyse(&items, months, now, &cancel, |_, _| {}),
            )
        });
    }

    // ----------------------------------------------------------------------------------
    // The list
    // ----------------------------------------------------------------------------------

    fn matches_nav(&self, item: &Item) -> bool {
        match &self.nav {
            Nav::Trash => item.in_trash(),
            _ if item.in_trash() => false,
            Nav::Favourites => item.favourite,
            Nav::Kind(k) => item.kind == *k,
            Nav::Folder(f) => item.folder == Some(*f),
            Nav::Tag(t) => item.tags.iter().any(|x| x.eq_ignore_ascii_case(t)),
            _ => true,
        }
    }

    fn matches_search(&self, item: &Item, terms: &[String], hidden: bool) -> bool {
        if terms.is_empty() {
            return true;
        }
        let mut hay = String::new();
        let mut add = |s: &str| {
            hay.push_str(&s.to_lowercase());
            hay.push('\n');
        };
        add(&item.title);
        add(&item.username);
        for u in &item.urls {
            add(u);
        }
        for t in &item.tags {
            add(t);
        }
        if let Some(f) = self.v.vault.folder_name(item.folder) {
            add(f);
        }
        for f in &item.fields {
            add(&f.label);
            if !f.hidden {
                add(&f.value);
            } else if hidden {
                add(&f.text());
            }
        }
        // Notes are searched as the task asks; they are decrypted only for
        // the comparison and wiped right after.
        let notes = item.notes.open_str();
        let mut notes_lower = zeroize::Zeroizing::new(notes.to_lowercase());
        let found = terms
            .iter()
            .all(|t| hay.contains(t.as_str()) || notes_lower.contains(t.as_str()));
        zeroize::Zeroize::zeroize(&mut *notes_lower);
        zeroize::Zeroize::zeroize(&mut hay);
        found
    }

    /// The ids shown in the list, filtered and sorted (cached until
    /// something changes).
    pub fn visible(&mut self, sh: &Shared) -> Vec<Id> {
        let key = ListKey {
            rev: self.rev,
            nav: self.nav.clone(),
            search: self.search.clone(),
            fav_only: self.fav_only,
            kind: self.kind_filter,
            search_hidden: sh.settings.search_hidden,
            sort: sh.settings.list_sort,
        };
        if let Some((k, ids)) = &self.list_cache {
            if *k == key {
                return ids.clone();
            }
        }
        let terms: Vec<String> = self
            .search
            .split_whitespace()
            .map(|t| t.to_lowercase())
            .collect();
        let extra = matches!(self.nav, Nav::All | Nav::Folder(_) | Nav::Tag(_));
        let mut items: Vec<&Item> = self
            .v
            .vault
            .items
            .iter()
            .filter(|i| self.matches_nav(i))
            .filter(|i| !extra || !self.fav_only || i.favourite)
            .filter(|i| !extra || self.kind_filter.map(|k| i.kind == k).unwrap_or(true))
            .filter(|i| self.matches_search(i, &terms, sh.settings.search_hidden))
            .collect();
        if self.nav == Nav::Trash {
            items.sort_by_key(|i| std::cmp::Reverse(i.deleted));
        } else {
            sort_items(&mut items, sh.settings.list_sort);
        }
        let ids: Vec<Id> = items.iter().map(|i| i.id).collect();
        self.list_cache = Some((key, ids.clone()));
        ids
    }

    pub fn select(&mut self, id: Option<Id>) {
        if self.selected != id {
            self.selected = id;
            self.reveal.clear();
            self.edit = None;
        }
    }

    pub fn go_to_item(&mut self, id: Id) {
        self.nav = Nav::All;
        self.search.clear();
        self.fav_only = false;
        self.kind_filter = None;
        self.select(Some(id));
    }

    // ----------------------------------------------------------------------------------
    // One-click actions
    // ----------------------------------------------------------------------------------

    pub fn copy_username(&mut self, sh: &mut Shared, id: Id) {
        if let Some(item) = self.v.vault.item(id) {
            if item.username.is_empty() {
                sh.toast("This item has no user name.", true);
            } else {
                sh.copy_plain(&item.username, "User name");
            }
        }
    }

    pub fn copy_password(&mut self, sh: &mut Shared, id: Id) {
        if let Some(item) = self.v.vault.item(id) {
            if item.password.is_empty() {
                sh.toast("This item has no password.", true);
            } else {
                let pw = item.password.open_str();
                sh.copy_secret(&pw, item.kind.password_label().unwrap_or("Password"));
            }
        }
    }

    pub fn copy_totp(&mut self, sh: &mut Shared, id: Id) {
        if let Some(item) = self.v.vault.item(id) {
            if item.totp.is_empty() {
                sh.toast("This item has no one-time code set up.", true);
                return;
            }
            let seed = item.totp.open_str();
            match crate::totp::Totp::parse(&seed) {
                Ok(t) => {
                    let code = zeroize::Zeroizing::new(t.code_at(sh.now as u64));
                    sh.copy_secret(&code, "One-time code");
                }
                Err(e) => sh.toast(e.to_string(), true),
            }
        }
    }

    pub fn open_first_url(&mut self, sh: &mut Shared, id: Id) {
        if let Some(url) = self.v.vault.item(id).and_then(|i| i.urls.first()) {
            if let Err(e) = crate::sys::open_url(url) {
                sh.toast(e, true);
            }
        }
    }

    /// The "Auto-type" button: minimise KeepForge, wait for the window
    /// underneath to come to the front, and type into it.
    pub fn autotype_button(&mut self, ctx: &egui::Context, sh: &mut Shared, id: Id) {
        if sh.demo {
            sh.toast("Auto-type is switched off in the demo.", false);
            return;
        }
        let Some(steps) = self.autotype_steps(sh, id) else {
            return;
        };
        self.typing = true;
        let own = sh.hwnd;
        crate::sys::minimize(own);
        sh.spawn(ctx, move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
            let target = loop {
                std::thread::sleep(std::time::Duration::from_millis(120));
                match autotype::foreground() {
                    Some(t) if autotype::reachability(t.hwnd) != autotype::Reach::Own => break Some(t),
                    _ if std::time::Instant::now() > deadline => break None,
                    _ => {}
                }
            };
            match target {
                Some(t) => Msg::AutoTyped(autotype::type_into(t.hwnd, steps)),
                None => Msg::AutoTyped(Err(
                    "There was no other window to type into. Click the window first, then use the hotkey.".into(),
                )),
            }
        });
    }

    fn autotype_steps(&mut self, sh: &mut Shared, id: Id) -> Option<Vec<autotype::Step>> {
        let item = self.v.vault.item(id)?;
        let tokens = match autotype::parse_sequence(autotype::sequence_of(item)) {
            Ok(t) => t,
            Err(e) => {
                sh.toast(
                    format!("This item's auto-type sequence has a mistake. {e}"),
                    true,
                );
                return None;
            }
        };
        match autotype::steps_for(item, &tokens, sh.now as u64) {
            Ok(steps) => Some(steps),
            Err(e) => {
                sh.toast(e, true);
                None
            }
        }
    }

    pub fn autotype_into(&mut self, ctx: &egui::Context, sh: &mut Shared, id: Id, target: isize) {
        let Some(steps) = self.autotype_steps(sh, id) else {
            return;
        };
        self.typing = true;
        sh.spawn(ctx, move || {
            Msg::AutoTyped(autotype::type_into(target, steps))
        });
    }

    /// The global hotkey was pressed while `target` had the focus.
    pub fn hotkey_pressed(&mut self, ctx: &egui::Context, sh: &mut Shared, target: isize) {
        if self.typing || self.lock_pending.is_some() {
            return;
        }
        let reach = autotype::reachability(target);
        if let Some(message) = autotype::reach_message(reach) {
            if reach != autotype::Reach::Own {
                crate::sys::show_and_focus(sh.hwnd);
            }
            sh.toast(message, true);
            return;
        }
        let title = autotype::window_title(target);
        let mut scored: Vec<(u32, Id)> = self
            .v
            .vault
            .items
            .iter()
            .filter(|i| i.kind == Kind::Login && !i.in_trash())
            .map(|i| (autotype::match_score(&title, i), i.id))
            .filter(|(score, _)| *score > 0)
            .collect();
        scored.sort_by_key(|(score, _)| std::cmp::Reverse(*score));
        match scored.len() {
            1 => self.autotype_into(ctx, sh, scored[0].1, target),
            0 => {
                crate::sys::show_and_focus(sh.hwnd);
                sh.toast(
                    format!(
                        "No saved login matches the window \"{}\". Pick one and use the Auto-type button.",
                        crate::util::truncate(&title, 60)
                    ),
                    true,
                );
            }
            _ => {
                crate::sys::show_and_focus(sh.hwnd);
                self.dialog = Some(Dialog::AutoType {
                    target,
                    title,
                    candidates: scored.into_iter().map(|(_, id)| id).collect(),
                });
            }
        }
    }

    pub fn new_item(&mut self, sh: &Shared, kind: Kind) {
        let mut form = EditForm::blank(kind, sh);
        if let Nav::Folder(f) = &self.nav {
            form.folder = self.v.vault.folder_name(Some(*f)).unwrap_or("").to_string();
        }
        if let Nav::Tag(t) = &self.nav {
            form.tags = t.clone();
        }
        if !self.nav.is_list() || self.nav == Nav::Trash {
            self.nav = Nav::All;
        }
        self.selected = None;
        self.reveal.clear();
        self.edit = Some(Box::new(form));
    }

    /// Removes items that have waited in the trash longer than the setting
    /// allows (called once, right after unlocking).
    pub fn purge_old_trash(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        let gone = self.v.vault.purge_trash(sh.now, sh.settings.trash_days);
        if gone > 0 {
            sh.toast(
                format!(
                    "{gone} item(s) that were in the trash for more than {} days were removed.",
                    sh.settings.trash_days
                ),
                false,
            );
            self.changed(ctx, sh);
        }
    }

    /// Moves an item to the trash, or (for an item already there) asks
    /// before deleting it for good.
    pub fn trash_item(&mut self, ctx: &egui::Context, sh: &mut Shared, id: Id) {
        let Some(item) = self.v.vault.item(id) else {
            return;
        };
        if item.in_trash() {
            self.dialog = Some(Dialog::confirm(
                "Delete for good?",
                &format!(
                    "\"{}\" will be removed from the vault permanently. This cannot be undone.",
                    item.title
                ),
                "Delete for good",
                ConfirmAction::DeleteForever(id),
            ));
        } else {
            // Moving to the trash can be undone, so it needs no question.
            self.v.vault.move_to_trash(id, sh.now);
            self.selected = None;
            self.edit = None;
            sh.toast("Moved to the trash", false);
            self.changed(ctx, sh);
        }
    }

    // ----------------------------------------------------------------------------------
    // Keyboard
    // ----------------------------------------------------------------------------------

    fn handle_keys(&mut self, ctx: &egui::Context, sh: &mut Shared) -> Option<Go> {
        if self.dialog.is_some() || sh.about_open {
            return None;
        }
        let typing = ctx.wants_keyboard_input();
        // The modifier is read from each key event itself, so a quick chord
        // is recognised even when it starts and ends within one frame.
        let (find, new, lock, edit, user, totp, copy, delete, escape) = ctx.input_mut(|i| {
            let cmd = egui::Modifiers::COMMAND;
            (
                i.consume_key(cmd, Key::F),
                i.consume_key(cmd, Key::N),
                i.consume_key(cmd, Key::L),
                i.consume_key(cmd, Key::E),
                i.consume_key(cmd, Key::B),
                i.consume_key(cmd, Key::T),
                i.events.iter().any(|e| matches!(e, egui::Event::Copy)),
                i.key_pressed(Key::Delete),
                i.key_pressed(Key::Escape),
            )
        });
        if lock {
            return Some(Go::Lock);
        }
        if find {
            if !self.nav.is_list() {
                self.nav = Nav::All;
            }
            self.focus_search = true;
        }
        if new && self.edit.is_none() {
            let kind = match &self.nav {
                Nav::Kind(k) => *k,
                _ => Kind::Login,
            };
            self.new_item(sh, kind);
        }
        // Arrow keys walk the list, also while the search box has the focus
        // (Ctrl+F, type, arrow down, Ctrl+C). Enter picks the first result.
        if self.nav.is_list() && self.edit.is_none() {
            let nav_key = ctx.input_mut(|i| {
                let mut keys = vec![Key::ArrowDown, Key::ArrowUp, Key::PageDown, Key::PageUp];
                if !typing {
                    keys.extend([Key::Home, Key::End]);
                } else if self.selected.is_none() {
                    keys.push(Key::Enter);
                }
                keys.into_iter()
                    .find(|k| i.consume_key(egui::Modifiers::NONE, *k))
            });
            if let Some(key) = nav_key {
                let ids = self.visible(sh);
                let current = self
                    .selected
                    .and_then(|id| ids.iter().position(|x| *x == id));
                if let Some(n) = step_selection(current, ids.len(), key, self.list_page) {
                    self.select(Some(ids[n]));
                    self.scroll_to_selected = true;
                }
            }
        }
        let selected = self
            .selected
            .filter(|_| self.nav.is_list() && self.edit.is_none());
        if let Some(id) = selected {
            if edit {
                self.start_edit(sh, id);
            }
            if user {
                self.copy_username(sh, id);
            }
            if totp {
                self.copy_totp(sh, id);
            }
            if copy && !typing {
                self.copy_password(sh, id);
            }
            if delete && !typing {
                self.trash_item(ctx, sh, id);
            }
        }
        if escape {
            if self.edit.is_some() {
                // Esc never throws away an edit by accident.
            } else if !self.search.is_empty() {
                self.search.clear();
            } else if self.selected.is_some() {
                self.select(None);
            }
        }
        None
    }

    pub fn start_edit(&mut self, sh: &Shared, id: Id) {
        if let Some(item) = self.v.vault.item(id) {
            if !item.in_trash() {
                self.edit = Some(Box::new(EditForm::from_item(item, &self.v.vault, sh)));
                self.reveal.clear();
            }
        }
    }

    // ----------------------------------------------------------------------------------
    // Frame
    // ----------------------------------------------------------------------------------

    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        logo: Option<&TextureHandle>,
    ) -> Option<Go> {
        let p = pal_ctx(ctx);
        if self.lock_pending.is_some() {
            // Nothing of the vault is drawn while the last save finishes.
            egui::CentralPanel::default()
                .frame(Frame::new().fill(p.bg))
                .show(ctx, |ui| widgets::busy_state(ui, "Saving and locking…", ""));
            return None;
        }
        let mut go = self.handle_keys(ctx, sh);
        self.exposure_auto(ctx, sh);
        let now = ctx.input(|i| i.time);
        self.reveal.retain(|_, until| *until > now);

        if let Some(g) = self.header(ctx, sh, logo) {
            go = Some(g);
        }
        self.rail(ctx, sh);
        if self.nav.is_list() {
            egui::SidePanel::left("list")
                .exact_width(336.0)
                .resizable(false)
                .frame(Frame::new().fill(p.bg).inner_margin(Margin {
                    left: 16,
                    right: 10,
                    top: 14,
                    bottom: 0,
                }))
                .show(ctx, |ui| self.list_ui(ui, sh));
            egui::CentralPanel::default()
                .frame(
                    Frame::new()
                        .fill(p.rail)
                        .inner_margin(Margin::symmetric(22, 16)),
                )
                .show(ctx, |ui| {
                    let full = ui.max_rect();
                    ui.painter().vline(
                        full.left() - 22.0,
                        full.y_range().expand(16.0),
                        Stroke::new(1.0_f32, p.border),
                    );
                    self.detail_pane(ui, sh)
                });
        } else {
            egui::CentralPanel::default()
                .frame(
                    Frame::new()
                        .fill(p.bg)
                        .inner_margin(Margin::symmetric(24, 18)),
                )
                .show(ctx, |ui| match self.nav {
                    Nav::Health => self.health_ui(ui, sh),
                    Nav::Exposure => self.exposure_ui(ui, sh),
                    Nav::Authenticator => self.authenticator_ui(ui, sh),
                    Nav::Generator => self.generator_ui(ui, sh),
                    Nav::Tools => self.tools_ui(ui, sh),
                    _ => {
                        if let Some(g) = self.settings_ui(ui, sh) {
                            go = Some(g);
                        }
                    }
                });
        }
        if let Some(g) = self.dialogs(ctx, sh) {
            go = Some(g);
        }
        go
    }

    fn header(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        logo: Option<&TextureHandle>,
    ) -> Option<Go> {
        let p = pal_ctx(ctx);
        let mut go = None;
        egui::TopBottomPanel::top("header")
            .exact_height(64.0)
            .frame(
                Frame::new()
                    .fill(p.rail)
                    .inner_margin(Margin::symmetric(18, 0)),
            )
            .show(ctx, |ui| {
                let full = ui.max_rect();
                ui.painter().hline(
                    full.x_range().expand(18.0),
                    full.bottom(),
                    Stroke::new(1.0_f32, p.border),
                );
                ui.horizontal_centered(|ui| {
                    super::start::paint_logo(ui, logo, 32.0);
                    ui.add_space(2.0);
                    ui.label(RichText::new("KeepForge").font(semibold(19.0)));
                    if sh.demo {
                        widgets::badge(ui, "DEMO", p.info)
                            .on_hover_text("Invented data. Nothing is saved or sent.");
                    }
                    ui.add_space(198.0 - ui.min_rect().width().min(198.0));

                    // Search
                    let search_width = (ui.available_width() - 470.0).clamp(220.0, 460.0);
                    Frame::new()
                        .fill(if p.dark { p.card } else { p.bg })
                        .stroke(Stroke::new(1.0_f32, p.border))
                        .corner_radius(CornerRadius::same(10))
                        .inner_margin(Margin::symmetric(12, 6))
                        .show(ui, |ui| {
                            ui.set_width(search_width);
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(Icon::SEARCH.glyph())
                                        .size(14.0)
                                        .color(p.faint),
                                );
                                let edit = egui::TextEdit::singleline(&mut self.search)
                                    .hint_text(
                                        RichText::new(
                                            "Search titles, user names, sites, tags and notes",
                                        )
                                        .color(p.faint),
                                    )
                                    .frame(false)
                                    .desired_width(ui.available_width() - 52.0)
                                    .font(regular(15.0));
                                let resp = ui.add(edit);
                                if resp.changed() && !self.nav.is_list() {
                                    self.nav = Nav::All;
                                }
                                if self.focus_search {
                                    resp.request_focus();
                                    self.focus_search = false;
                                }
                                if !self.search.is_empty() {
                                    if widgets::icon_button(ui, Icon::CLOSE, "Clear search (Esc)")
                                        .clicked()
                                    {
                                        self.search.clear();
                                    }
                                } else {
                                    ui.label(RichText::new("Ctrl+F").size(11.5).color(p.faint));
                                }
                            });
                        });

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if widgets::icon_button(ui, Icon::INFO, "About KeepForge").clicked() {
                            sh.about_open = true;
                        }
                        let lock =
                            egui::Button::new(RichText::new(Icon::LOCK.with("Lock")).color(p.text))
                                .fill(Color32::TRANSPARENT)
                                .stroke(Stroke::new(1.0_f32, p.border))
                                .corner_radius(CornerRadius::same(8))
                                .min_size(vec2(0.0, 34.0));
                        if ui
                            .add(lock)
                            .on_hover_text("Lock the vault (Ctrl+L)")
                            .clicked()
                        {
                            go = Some(Go::Lock);
                        }
                        ui.add_space(4.0);
                        // Vault name and save state.
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 0.0;
                            ui.add_space(13.0);
                            ui.with_layout(Layout::top_down(Align::Max), |ui| {
                                ui.label(
                                    RichText::new(crate::util::truncate(&self.v.vault.name, 26))
                                        .font(semibold(14.0)),
                                );
                                let (text, color) = if sh.demo {
                                    ("In memory only".to_string(), p.faint)
                                } else if self.saving {
                                    ("Saving…".to_string(), p.muted)
                                } else if self.save_error.is_some() {
                                    ("Not saved".to_string(), p.danger)
                                } else {
                                    ("Saved".to_string(), p.faint)
                                };
                                ui.label(RichText::new(text).size(11.5).color(color));
                            });
                        });
                        // Clipboard countdown.
                        if let Some(pending) = sh.clip {
                            let left = match crate::clipboard::decide(
                                &pending,
                                sh_ms(sh),
                                pending.sequence,
                            ) {
                                crate::clipboard::Tick::Keep(Some(s)) => Some(s),
                                _ => None,
                            };
                            ui.add_space(6.0);
                            let label = match left {
                                Some(s) => format!("Clipboard clears in {:.0} s", s.ceil()),
                                None => "Secret on clipboard".to_string(),
                            };
                            let chip = egui::Button::new(
                                RichText::new(format!("{label}  {}", Icon::CLOSE.glyph()))
                                    .size(12.5)
                                    .color(p.warn),
                            )
                            .fill(p.warn.gamma_multiply(0.14))
                            .stroke(Stroke::NONE)
                            .corner_radius(CornerRadius::same(14))
                            .min_size(vec2(0.0, 28.0));
                            if ui
                                .add(chip)
                                .on_hover_text("Clear the clipboard now")
                                .clicked()
                            {
                                sh.clear_clipboard();
                            }
                        }
                    });
                });
            });
        go
    }

    fn rail(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        let p = pal_ctx(ctx);
        let mut pick: Option<Nav> = None;
        let mut folder_menu: Option<(Id, bool)> = None;
        let mut add_folder = false;
        egui::SidePanel::left("rail")
            .exact_width(216.0)
            .resizable(false)
            .frame(
                Frame::new()
                    .fill(p.rail)
                    .inner_margin(Margin::symmetric(10, 10)),
            )
            .show(ctx, |ui| {
                let full = ui.max_rect();
                ui.painter().vline(
                    full.right() + 10.0,
                    full.y_range().expand(10.0),
                    Stroke::new(1.0_f32, p.border),
                );
                ui.spacing_mut().item_spacing.y = 2.0;
                let items = &self.v.vault.items;
                let live = items.iter().filter(|i| !i.in_trash());
                let count_all = live.clone().count();
                let count_fav = live.clone().filter(|i| i.favourite).count();
                let trash = items.iter().filter(|i| i.in_trash()).count();
                let current = self.nav.clone();
                let mut row = |ui: &mut Ui,
                               nav: Nav,
                               icon: Icon,
                               label: &str,
                               count: Option<usize>|
                 -> egui::Response {
                    let active = current == nav;
                    let (rect, resp) =
                        ui.allocate_exact_size(vec2(ui.available_width(), 30.0), Sense::click());
                    if active {
                        ui.painter()
                            .rect_filled(rect, CornerRadius::same(8), p.selected);
                        let bar = Rect::from_min_size(
                            rect.left_center() - vec2(0.0, 8.0),
                            vec2(3.0, 16.0),
                        );
                        ui.painter()
                            .rect_filled(bar, CornerRadius::same(2), p.accent);
                    } else if resp.hovered() {
                        ui.painter()
                            .rect_filled(rect, CornerRadius::same(8), p.hover);
                    }
                    let fg = if active { p.text } else { p.muted };
                    ui.painter().text(
                        rect.left_center() + vec2(22.0, 0.0),
                        Align2::CENTER_CENTER,
                        icon.glyph(),
                        regular(15.0),
                        if active { p.accent } else { fg },
                    );
                    let text_rect = Rect::from_min_max(
                        rect.min + vec2(42.0, 0.0),
                        rect.max - vec2(if count.is_some() { 36.0 } else { 8.0 }, 1.0),
                    );
                    widgets::text_in(
                        ui,
                        text_rect,
                        label,
                        if active {
                            semibold(14.0)
                        } else {
                            regular(14.0)
                        },
                        fg,
                    );
                    if let Some(n) = count {
                        ui.painter().text(
                            rect.right_center() - vec2(10.0, 1.0),
                            Align2::RIGHT_CENTER,
                            n.to_string(),
                            regular(12.0),
                            p.faint,
                        );
                    }
                    if resp.clicked() {
                        pick = Some(nav);
                    }
                    resp
                };
                let heading = |ui: &mut Ui, text: &str| {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.add_space(12.0);
                        ui.label(RichText::new(text).size(11.0).color(p.faint));
                    });
                };

                // The bottom group is fixed; the rest scrolls if it has to.
                let bottom_height = 7.0 * 32.0 + 16.0;
                let scroll_height = (ui.available_height() - bottom_height).max(120.0);
                egui::ScrollArea::vertical()
                    .max_height(scroll_height)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        row(ui, Nav::All, Icon::APPS, "All items", Some(count_all));
                        row(
                            ui,
                            Nav::Favourites,
                            Icon::STAR,
                            "Favourites",
                            Some(count_fav),
                        );
                        heading(ui, "TYPES");
                        for kind in Kind::ALL {
                            let n = live.clone().filter(|i| i.kind == kind).count();
                            row(ui, Nav::Kind(kind), kind_icon(kind), kind.plural(), Some(n));
                        }
                        ui.add_space(6.0);
                        ui.horizontal(|ui| {
                            ui.add_space(12.0);
                            ui.label(RichText::new("FOLDERS").size(11.0).color(p.faint));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                let add = egui::Button::new(
                                    RichText::new(Icon::ADD.glyph()).size(11.0).color(p.muted),
                                )
                                .fill(Color32::TRANSPARENT)
                                .stroke(Stroke::NONE);
                                if ui.add(add).on_hover_text("New folder").clicked() {
                                    add_folder = true;
                                }
                            });
                        });
                        for f in &self.v.vault.folders {
                            let n = live.clone().filter(|i| i.folder == Some(f.id)).count();
                            let resp = row(ui, Nav::Folder(f.id), Icon::FOLDER, &f.name, Some(n));
                            resp.context_menu(|ui| {
                                if ui.button("Rename folder").clicked() {
                                    folder_menu = Some((f.id, false));
                                    ui.close_menu();
                                }
                                if ui.button("Delete folder").clicked() {
                                    folder_menu = Some((f.id, true));
                                    ui.close_menu();
                                }
                            });
                        }
                        let tags = self.v.vault.all_tags();
                        if !tags.is_empty() {
                            heading(ui, "TAGS");
                            for t in tags {
                                let n = live
                                    .clone()
                                    .filter(|i| i.tags.iter().any(|x| x.eq_ignore_ascii_case(&t)))
                                    .count();
                                row(ui, Nav::Tag(t.clone()), Icon::TAG, &t, Some(n));
                            }
                        }
                    });
                ui.add_space(4.0);
                widgets::divider(ui);
                ui.add_space(4.0);
                row(ui, Nav::Health, Icon::HEALTH, "Security dashboard", None);
                row(ui, Nav::Exposure, Icon::SHIELD, "Exposure check", None);
                row(ui, Nav::Authenticator, Icon::PHONE, "Authenticator", None);
                row(ui, Nav::Generator, Icon::SHUFFLE, "Generator", None);
                row(ui, Nav::Tools, Icon::REPAIR, "Tools", None);
                row(ui, Nav::Trash, Icon::DELETE, "Trash", Some(trash));
                row(ui, Nav::Settings, Icon::SETTINGS, "Settings", None);
            });
        if let Some(nav) = pick {
            if self.nav != nav {
                self.nav = nav;
                self.select(None);
                self.fav_only = false;
                self.kind_filter = None;
                if !self.nav.is_list() {
                    self.search.clear();
                }
                // Typed test passwords and results do not outlive the page.
                self.tools.leave(sh);
            }
        }
        if add_folder {
            self.dialog = Some(Dialog::Folder {
                id: None,
                name: String::new(),
            });
        }
        if let Some((id, delete)) = folder_menu {
            let name = self.v.vault.folder_name(Some(id)).unwrap_or("").to_string();
            self.dialog = Some(if delete {
                Dialog::confirm(
                    "Delete this folder?",
                    &format!("The folder \"{name}\" is removed. The items in it are kept and simply have no folder."),
                    "Delete folder",
                    ConfirmAction::DeleteFolder(id),
                )
            } else {
                Dialog::Folder { id: Some(id), name }
            });
        }
    }

    fn nav_title(&self) -> String {
        match &self.nav {
            Nav::All => "All items".into(),
            Nav::Favourites => "Favourites".into(),
            Nav::Kind(k) => k.plural().into(),
            Nav::Folder(f) => self
                .v
                .vault
                .folder_name(Some(*f))
                .unwrap_or("Folder")
                .into(),
            Nav::Tag(t) => format!("Tag: {t}"),
            Nav::Trash => "Trash".into(),
            _ => String::new(),
        }
    }

    fn list_ui(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let ids = self.visible(sh);
        let mut new_kind: Option<Kind> = None;
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 0.0;
                ui.add(
                    egui::Label::new(RichText::new(self.nav_title()).font(semibold(20.0))).truncate(),
                );
                ui.label(
                    RichText::new(match ids.len() {
                        1 => "1 item".to_string(),
                        n => format!("{n} items"),
                    })
                    .size(12.5)
                    .color(p.faint),
                );
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if self.nav == Nav::Trash {
                    if !ids.is_empty() && widgets::ghost_button(ui, "Empty trash").clicked() {
                        self.dialog = Some(Dialog::confirm(
                            "Empty the trash?",
                            &format!("{} item(s) will be removed from the vault permanently. This cannot be undone.", ids.len()),
                            "Empty trash",
                            ConfirmAction::EmptyTrash,
                        ));
                    }
                } else {
                    let menu = ui.menu_button(
                        RichText::new(Icon::ADD.with("New"))
                            .font(semibold(14.0))
                            .color(p.accent),
                        |ui| {
                            ui.set_min_width(190.0);
                            for kind in Kind::ALL {
                                if ui
                                    .button(format!("{}   {}", kind_icon(kind).glyph(), kind.label()))
                                    .clicked()
                                {
                                    new_kind = Some(kind);
                                    ui.close_menu();
                                }
                            }
                        },
                    );
                    menu.response.on_hover_text("New item (Ctrl+N)");
                    let current = sh.settings.list_sort;
                    let sort = ui.menu_button(
                        RichText::new(if Icon::SORT.glyph().is_empty() {
                            "Sort"
                        } else {
                            Icon::SORT.glyph()
                        })
                        .size(14.0)
                        .color(p.muted),
                        |ui| {
                            ui.set_min_width(190.0);
                            for order in SortOrder::ALL {
                                if ui
                                    .selectable_label(order == current, order.label())
                                    .clicked()
                                {
                                    sh.settings.list_sort = order;
                                    self.scroll_to_selected = true;
                                    ui.close_menu();
                                }
                            }
                        },
                    );
                    sort.response
                        .on_hover_text(format!("Sort order: {}", current.label()));
                }
            });
        });
        if let Some(kind) = new_kind {
            self.new_item(sh, kind);
        }

        // Extra filters on top of the navigation.
        if matches!(self.nav, Nav::All | Nav::Folder(_) | Nav::Tag(_)) {
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = vec2(5.0, 5.0);
                ui.spacing_mut().button_padding = vec2(9.0, 3.0);
                if small_chip(ui, &Icon::STAR.with("Favourites"), self.fav_only).clicked() {
                    self.fav_only = !self.fav_only;
                }
                for (kind, label) in [
                    (Kind::Login, "Logins"),
                    (Kind::Card, "Cards"),
                    (Kind::Identity, "Identities"),
                    (Kind::Note, "Notes"),
                    (Kind::Wifi, "Wi-Fi"),
                    (Kind::Licence, "Keys"),
                ] {
                    if small_chip(ui, label, self.kind_filter == Some(kind)).clicked() {
                        self.kind_filter = if self.kind_filter == Some(kind) {
                            None
                        } else {
                            Some(kind)
                        };
                    }
                }
            });
        }
        ui.add_space(6.0);

        if ids.is_empty() {
            let (icon, title, text) = if !self.search.is_empty() {
                (
                    Icon::SEARCH,
                    "Nothing found",
                    "No item matches your search. Try fewer or different words.",
                )
            } else if self.nav == Nav::Trash {
                (
                    Icon::DELETE,
                    "The trash is empty",
                    "Items you delete wait here until you empty the trash.",
                )
            } else if self.v.vault.items.iter().all(|i| i.in_trash()) {
                (Icon::KEY, "Your vault is empty", "Add your first login with the New button, or import from another manager in Settings.")
            } else {
                (Icon::APPS, "Nothing here yet", "No items in this view.")
            };
            widgets::empty_state(ui, icon, p.muted, title, text);
            return;
        }

        let mut clicked: Option<Id> = None;
        let mut action: Option<(Id, u8)> = None;
        // (A screenshot keeps asking: its window changes size while it starts.)
        let wanted = self.scroll_to_selected;
        self.scroll_to_selected = wanted && sh.shot;
        let scroll_to = wanted
            .then(|| {
                self.selected
                    .and_then(|id| ids.iter().position(|x| *x == id))
            })
            .flatten();
        self.list_page = ((ui.available_height() / ROW) as usize)
            .saturating_sub(1)
            .max(1);
        // Rows touch each other: the row height given to the scroll area must
        // be the whole distance from one row to the next.
        ui.spacing_mut().item_spacing.y = 0.0;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show_rows(ui, ROW, ids.len(), |ui, range| {
                ui.spacing_mut().item_spacing.y = 0.0;
                if let Some(n) = scroll_to {
                    // Rows outside the drawn range have a known place too.
                    let top = ui.cursor().top() + (n as f32 - range.start as f32) * ROW;
                    let row = Rect::from_min_size(
                        egui::pos2(ui.cursor().left(), top),
                        vec2(ui.available_width(), ROW),
                    );
                    ui.scroll_to_rect(row, None);
                }
                for id in &ids[range] {
                    let Some(item) = self.v.vault.item(*id) else {
                        continue;
                    };
                    let width = ui.available_width() - 8.0;
                    let (rect, resp) = ui.allocate_exact_size(vec2(width, ROW), Sense::click());
                    let rect = rect.shrink2(vec2(0.0, 2.0));
                    let selected = self.selected == Some(*id);
                    if selected {
                        ui.painter()
                            .rect_filled(rect, CornerRadius::same(10), p.selected);
                    } else if resp.hovered() {
                        ui.painter()
                            .rect_filled(rect, CornerRadius::same(10), p.hover);
                    }
                    let tile = Rect::from_min_size(rect.min + vec2(10.0, 9.0), vec2(36.0, 36.0));
                    widgets::letter_tile(ui, tile, &item.title);
                    // Quick actions on the selected or hovered row.
                    let show_actions = (selected || resp.hovered()) && !item.in_trash();
                    let mut right = rect.right() - 8.0;
                    if show_actions {
                        let mut buttons: Vec<(Icon, &str, u8)> = Vec::new();
                        if item.kind.has_urls() && item.urls.iter().any(|u| !u.trim().is_empty()) {
                            buttons.push((Icon::GLOBE, "Open the website", 3));
                        }
                        if !item.totp.is_empty() {
                            buttons.push((Icon::CLOCK, "Copy one-time code (Ctrl+T)", 2));
                        }
                        if !item.password.is_empty() {
                            buttons.push((Icon::KEY, "Copy password (Ctrl+C)", 1));
                        }
                        if item.kind.username_label().is_some() && !item.username.is_empty() {
                            buttons.push((Icon::CONTACT, "Copy user name (Ctrl+B)", 0));
                        }
                        for (icon, tip, code) in buttons {
                            let r = Rect::from_min_size(
                                egui::pos2(right - 26.0, rect.center().y - 13.0),
                                vec2(26.0, 26.0),
                            );
                            right -= 28.0;
                            let b = ui
                                .interact(r, resp.id.with(("act", code)), Sense::click())
                                .on_hover_text(tip);
                            if b.hovered() {
                                ui.painter().rect_filled(r, CornerRadius::same(6), p.border);
                            }
                            ui.painter().text(
                                r.center(),
                                Align2::CENTER_CENTER,
                                icon.glyph(),
                                regular(13.5),
                                if b.hovered() { p.text } else { p.muted },
                            );
                            if b.clicked() {
                                action = Some((*id, code));
                            }
                        }
                    } else if item.favourite {
                        ui.painter().text(
                            egui::pos2(right - 8.0, rect.center().y),
                            Align2::CENTER_CENTER,
                            Icon::STAR_FILL.glyph(),
                            regular(12.0),
                            p.warn,
                        );
                        right -= 22.0;
                    }
                    let title_rect = Rect::from_min_max(
                        egui::pos2(rect.left() + 56.0, rect.top() + 8.0),
                        egui::pos2(right - 4.0, rect.top() + 29.0),
                    );
                    widgets::text_in(ui, title_rect, &item.title, semibold(14.5), p.text);
                    let sub_rect = Rect::from_min_max(
                        egui::pos2(rect.left() + 56.0, rect.top() + 29.0),
                        egui::pos2(right - 4.0, rect.bottom() - 7.0),
                    );
                    let sub = if item.in_trash() {
                        format!(
                            "{} · deleted {}",
                            item.kind.label(),
                            crate::util::ago(item.deleted.unwrap_or(0), sh.now)
                        )
                    } else {
                        let s = item.subtitle();
                        if s.is_empty() {
                            item.kind.label().to_string()
                        } else {
                            s
                        }
                    };
                    widgets::text_in(ui, sub_rect, &sub, regular(12.5), p.muted);
                    if resp.clicked() && action.is_none() {
                        clicked = Some(*id);
                    }
                }
            });
        if let Some((id, code)) = action {
            match code {
                0 => self.copy_username(sh, id),
                1 => self.copy_password(sh, id),
                2 => self.copy_totp(sh, id),
                _ => self.open_first_url(sh, id),
            }
        } else if let Some(id) = clicked {
            if self.edit.is_some() && self.selected != Some(id) {
                sh.toast("Save or cancel your changes first.", true);
            } else {
                self.select(Some(id));
            }
        }
    }
}

fn sh_ms(sh: &Shared) -> u64 {
    sh.clock_ms()
}

fn small_chip(ui: &mut Ui, label: &str, active: bool) -> egui::Response {
    let p = pal(ui);
    let (fill, fg, stroke) = if active {
        (
            p.accent.gamma_multiply(0.16),
            p.accent,
            Stroke::new(1.0_f32, p.accent.gamma_multiply(0.6)),
        )
    } else {
        (
            Color32::TRANSPARENT,
            p.muted,
            Stroke::new(1.0_f32, p.border),
        )
    };
    ui.add(
        egui::Button::new(RichText::new(label).size(12.0).color(fg))
            .fill(fill)
            .stroke(stroke)
            .corner_radius(CornerRadius::same(12))
            .min_size(vec2(0.0, 24.0)),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(title: &str, created: i64, modified: i64) -> Item {
        let mut i = Item::new(Kind::Login, created);
        i.title = title.into();
        i.modified = modified;
        i
    }

    #[test]
    fn list_sorts_by_title_or_newest_first() {
        let items = [
            item("delta", 10, 40),
            item("Alpha", 30, 30),
            item("charlie", 20, 50),
            item("Bravo", 20, 50),
        ];
        let titles = |order| {
            let mut refs: Vec<&Item> = items.iter().collect();
            sort_items(&mut refs, order);
            refs.iter().map(|i| i.title.as_str()).collect::<Vec<_>>()
        };
        assert_eq!(
            titles(SortOrder::Title),
            ["Alpha", "Bravo", "charlie", "delta"]
        );
        // Newest first; equal times fall back to the title.
        assert_eq!(
            titles(SortOrder::Changed),
            ["Bravo", "charlie", "delta", "Alpha"]
        );
        assert_eq!(
            titles(SortOrder::Created),
            ["Alpha", "Bravo", "charlie", "delta"]
        );
    }

    #[test]
    fn keys_move_the_selection_and_stop_at_the_ends() {
        let step = |current, key| step_selection(current, 10, key, 4);
        assert_eq!(step_selection(None, 0, Key::ArrowDown, 4), None);
        assert_eq!(step(None, Key::ArrowDown), Some(0));
        assert_eq!(step(None, Key::Enter), Some(0));
        assert_eq!(step(None, Key::ArrowUp), Some(9));
        assert_eq!(step(Some(3), Key::ArrowDown), Some(4));
        assert_eq!(step(Some(9), Key::ArrowDown), Some(9));
        assert_eq!(step(Some(0), Key::ArrowUp), Some(0));
        assert_eq!(step(Some(3), Key::PageDown), Some(7));
        assert_eq!(step(Some(8), Key::PageDown), Some(9));
        assert_eq!(step(Some(2), Key::PageUp), Some(0));
        assert_eq!(step(Some(5), Key::Home), Some(0));
        assert_eq!(step(Some(5), Key::End), Some(9));
        // A page of zero rows (a very small window) still moves by one.
        assert_eq!(step_selection(Some(3), 10, Key::PageDown, 0), Some(4));
        // Other keys leave the selection where it is.
        assert_eq!(step(Some(5), Key::A), Some(5));
        assert_eq!(step(None, Key::A), None);
    }
}
