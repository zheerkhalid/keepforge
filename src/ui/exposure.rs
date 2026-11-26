//! The Exposure check page: email addresses, user names, phone numbers,
//! domains and passwords against breach, paste and infostealer sources;
//! where a user name is registered; and links from every result to the
//! saved logins it concerns. Also the sources part of Settings.

use super::app::{Msg, Shared};
use super::dialogs::{Dialog, Online};
use super::main_view::{Main, Nav};
use super::pages::page_header;
use super::theme::{pal, regular, semibold, Icon};
use super::widgets;
use crate::exposure::password::PwSource;
use crate::exposure::sites::{self, SiteEvent, SiteHit, SiteScan};
use crate::exposure::{
    self, Asked, Cache, Event, Exposure, Finding, FindingKind, OutcomeState, QueryKind, Record,
    Severity, SourceId, Task,
};
use crate::model::Id;
use crate::secret::SecretInput;
use crate::util;
use eframe::egui::{self, vec2, Color32, RichText, Sense, Ui};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// The settings code of the "where is this user name registered" scan.
pub const SITES_CODE: &str = "whatsmyname";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    Lookup(QueryKind),
    Password,
}

/// Something the user asked for that needs an online source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Pending {
    /// Look these values up; `all`: this is "Check all".
    Lookup(Vec<Task>, bool),
    Password,
    Sites(String),
    VaultSites,
}

impl Pending {
    /// The settings codes of the sources this needs, for the opt-in dialog.
    pub fn candidates(&self) -> Vec<(&'static str, &'static str, &'static str)> {
        match self {
            Pending::Lookup(tasks, _) => SourceId::ALL
                .into_iter()
                .filter(|s| tasks.iter().any(|t| s.supports(t.kind)))
                .map(|s| (s.code(), s.name(), s.sends()))
                .collect(),
            Pending::Password => PwSource::ALL
                .into_iter()
                .map(|s| {
                    let code = if s == PwSource::PwnedPasswords {
                        crate::settings::Settings::PWNED_CODE
                    } else {
                        s.code()
                    };
                    (code, s.name(), s.sends())
                })
                .collect(),
            Pending::Sites(_) => vec![(
                SITES_CODE,
                "Where is this user name registered (WhatsMyName list)",
                "Asks the public profile address of about 550 websites whether an account with this user name exists. Each website sees the user name and your IP address.",
            )],
            Pending::VaultSites => vec![(
                SourceId::HibpDomain.code(),
                SourceId::HibpDomain.name(),
                SourceId::HibpDomain.sends(),
            )],
        }
    }
}

pub struct Run {
    pub total: usize,
    pub done: usize,
    pub cancel: Arc<AtomicBool>,
    pub all: bool,
}

pub struct SitesRun {
    pub username: String,
    pub done: usize,
    pub total: usize,
    pub cancel: Arc<AtomicBool>,
    pub hits: Vec<SiteHit>,
}

/// Logins to change, for (cache generation, vault revision).
type Flagged = (u64, u64, Vec<(Id, String)>);

/// One source in Settings: code, name, text, key name, key page, website.
struct SourceRow {
    code: &'static str,
    name: &'static str,
    text: String,
    key_name: Option<&'static str>,
    key_page: &'static str,
    home: &'static str,
}

pub struct ExposureState {
    pub tab: Tab,
    pub input: String,
    pub selected: Option<(QueryKind, String)>,
    pub cache: Cache,
    /// The vault text the cache was last loaded from or stored to.
    stored: String,
    /// Changes whenever the cache changes.
    pub generation: u64,
    pub run: Option<Run>,
    pub sites_run: Option<SitesRun>,
    pub vault_sites_busy: bool,
    pub pw_input: SecretInput,
    pub pw_results: Vec<(PwSource, Result<u64, String>)>,
    pub pw_busy: bool,
    pub own_username: bool,
    pub problem: Option<String>,
    flagged: Option<Flagged>,
    pub key_inputs: HashMap<&'static str, SecretInput>,
    /// The automatic re-check has been considered for this unlock.
    pub auto_considered: bool,
    /// Scroll to the results once (demo screenshots).
    pub scroll_to_results: bool,
}

impl ExposureState {
    pub fn new(vault: &crate::model::Vault) -> ExposureState {
        ExposureState {
            tab: Tab::Lookup(QueryKind::Email),
            input: String::new(),
            selected: None,
            cache: Cache::load(vault),
            stored: vault.exposure.clone(),
            generation: 1,
            run: None,
            sites_run: None,
            vault_sites_busy: false,
            pw_input: SecretInput::new(),
            pw_results: Vec::new(),
            pw_busy: false,
            own_username: false,
            problem: None,
            flagged: None,
            key_inputs: HashMap::new(),
            auto_considered: false,
            scroll_to_results: false,
        }
    }

    pub fn busy(&self) -> bool {
        self.run.is_some() || self.sites_run.is_some() || self.vault_sites_busy || self.pw_busy
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!(
        "{} {}",
        util::thousands(n as u64),
        if n == 1 { one } else { many }
    )
}

fn severity_color(ui: &Ui, s: Severity) -> Color32 {
    let p = pal(ui);
    match s {
        Severity::Critical | Severity::High => p.danger,
        Severity::Medium => p.warn,
        Severity::Low => p.info,
    }
}

fn kind_icon(kind: QueryKind) -> Icon {
    match kind {
        QueryKind::Email => Icon::MAIL,
        QueryKind::Username => Icon::CONTACT,
        QueryKind::Phone => Icon::PHONE,
        QueryKind::Domain => Icon::GLOBE,
    }
}

/// A short "what was found" text for a record.
fn summary(r: &Record) -> (String, bool) {
    let list = r.exposures();
    let stealers = list
        .iter()
        .filter(|e| matches!(e.kind, FindingKind::Stealer | FindingKind::StealerSite))
        .count();
    let breaches = list.len() - stealers;
    let mut parts = Vec::new();
    if breaches > 0 {
        parts.push(if r.kind == QueryKind::Domain {
            plural(breaches, "breach at this site", "breaches at this site")
        } else {
            plural(breaches, "breach", "breaches")
        });
    }
    if stealers > 0 {
        parts.push(plural(
            stealers,
            "infostealer finding",
            "infostealer findings",
        ));
    }
    if let Some(scan) = &r.sites {
        parts.push(plural(
            scan.found.len(),
            "site with this name",
            "sites with this name",
        ));
    }
    if parts.is_empty() {
        let text = if r.outcomes.iter().any(|o| o.state != OutcomeState::Failed) {
            "Nothing found"
        } else if r.outcomes.is_empty() {
            "Not checked yet"
        } else {
            "Could not be checked"
        };
        (text.to_string(), false)
    } else {
        (parts.join(" · "), breaches + stealers > 0)
    }
}

impl Main {
    // ----------------------------------------------------------------------------------
    // Cache
    // ----------------------------------------------------------------------------------

    /// Reloads the cache when the vault changed underneath it (a merge).
    pub(super) fn exposure_sync(&mut self) {
        if self.v.vault.exposure != self.exp.stored {
            self.exp.cache = Cache::load(&self.v.vault);
            self.exp.stored = self.v.vault.exposure.clone();
            self.exp.generation += 1;
        }
    }

    /// Writes the cache into the vault and saves it.
    fn exposure_store(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        self.exp.cache.store(&mut self.v.vault);
        self.exp.stored = self.v.vault.exposure.clone();
        self.exp.generation += 1;
        self.changed(ctx, sh);
    }

    /// Logins that should get a new password because of what the Exposure
    /// check found, with the reason.
    pub fn exposed_items(&mut self) -> Vec<(Id, String)> {
        let key = (self.exp.generation, self.rev);
        if let Some((g, r, list)) = &self.exp.flagged {
            if (*g, *r) == key {
                return list.clone();
            }
        }
        let mut all: Vec<Exposure> = self
            .exp
            .cache
            .all_exposures()
            .into_iter()
            .map(|(_, _, e)| e)
            .collect();
        all.extend(exposure::merge(&self.exp.cache.site_breaches));
        let list = exposure::items_to_change(&self.v.vault, all.iter());
        self.exp.flagged = Some((key.0, key.1, list.clone()));
        list
    }

    /// Infostealer findings about the user, for the dashboard.
    pub fn stealer_findings(&self) -> Vec<(String, Exposure)> {
        self.exp
            .cache
            .all_exposures()
            .into_iter()
            .filter(|(_, _, e)| matches!(e.kind, FindingKind::Stealer | FindingKind::StealerSite))
            .map(|(_, v, e)| (v, e))
            .collect()
    }

    // ----------------------------------------------------------------------------------
    // Starting checks
    // ----------------------------------------------------------------------------------

    fn enabled_sources(&self, sh: &Shared, tasks: &[Task]) -> Vec<SourceId> {
        SourceId::ALL
            .into_iter()
            .filter(|s| sh.settings.source_on(s.code()) && tasks.iter().any(|t| s.supports(t.kind)))
            .collect()
    }

    fn enabled_pw_sources(&self, sh: &Shared) -> Vec<PwSource> {
        PwSource::ALL
            .into_iter()
            .filter(|s| {
                let code = if *s == PwSource::PwnedPasswords {
                    crate::settings::Settings::PWNED_CODE
                } else {
                    s.code()
                };
                sh.settings.source_on(code)
            })
            .collect()
    }

    /// Runs `what` when a source for it is on; otherwise asks which to turn on.
    pub(super) fn exposure_request(&mut self, ctx: &egui::Context, sh: &mut Shared, what: Pending) {
        if self.exp.busy() {
            return;
        }
        let ready = match &what {
            Pending::Lookup(tasks, _) => !self.enabled_sources(sh, tasks).is_empty(),
            Pending::Password => !self.enabled_pw_sources(sh).is_empty(),
            Pending::Sites(_) => sh.settings.source_on(SITES_CODE),
            Pending::VaultSites => sh.settings.source_on(SourceId::HibpDomain.code()),
        };
        if ready || sh.demo {
            self.exposure_start(ctx, sh, what);
        } else {
            let picks = what
                .candidates()
                .iter()
                .map(|(code, _, _)| (*code, false))
                .collect();
            self.dialog = Some(Dialog::Online(Online::Sources(what, picks), false));
        }
    }

    /// After the opt-in dialog: switch the chosen sources on, then run.
    pub(super) fn exposure_opted_in(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        what: Pending,
        picks: Vec<(&'static str, bool)>,
    ) {
        for (code, on) in picks {
            if on {
                sh.settings.set_source(code, true);
            }
        }
        self.exposure_start(ctx, sh, what);
    }

    pub(super) fn exposure_start(&mut self, ctx: &egui::Context, sh: &mut Shared, what: Pending) {
        if self.exp.busy() {
            return;
        }
        self.exp.problem = None;
        match what {
            Pending::Lookup(tasks, all) => self.start_lookup(ctx, sh, tasks, all),
            Pending::Password => self.start_password_check(ctx, sh),
            Pending::Sites(name) => self.start_site_scan(ctx, sh, name),
            Pending::VaultSites => self.start_vault_sites(ctx, sh),
        }
    }

    fn start_lookup(&mut self, ctx: &egui::Context, sh: &mut Shared, tasks: Vec<Task>, all: bool) {
        if tasks.is_empty() {
            return;
        }
        let sources = if sh.demo {
            SourceId::ALL
                .into_iter()
                .filter(|s| {
                    sh.settings.source_on(s.code()) || crate::demo::DEMO_SOURCES.contains(&s.code())
                })
                .collect()
        } else {
            self.enabled_sources(sh, &tasks)
        };
        let now = sh.now;
        for t in &tasks {
            self.exp.cache.record_mut(t.kind, &t.value, now).checked = now;
        }
        if tasks.len() == 1 {
            self.exp.selected = Some((tasks[0].kind, tasks[0].value.clone()));
        }
        let asked: Vec<Asked> = sources
            .iter()
            .map(|s| Asked {
                source: *s,
                key: s
                    .key_name()
                    .and_then(|k| self.v.vault.service_key(k))
                    .map(|k| zeroize::Zeroizing::new(k.open_str().to_string())),
            })
            .collect();
        if sh.demo {
            // The demo never goes online: invented answers, at once.
            for t in &tasks {
                for a in &asked {
                    if a.source.supports(t.kind) {
                        let result = crate::demo::exposure_answer(a.source, t.kind, &t.value);
                        self.exp
                            .cache
                            .record_mut(t.kind, &t.value, now)
                            .apply(a.source, result);
                    }
                }
            }
            if all {
                self.exp.cache.last_all = now;
            }
            self.exp.generation += 1;
            return;
        }
        let total = exposure::planned(&tasks, &asked);
        let cancel = Arc::new(AtomicBool::new(false));
        self.exp.run = Some(Run {
            total,
            done: 0,
            cancel: cancel.clone(),
            all,
        });
        self.exp.generation += 1;
        let (tx, ctx) = (sh.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let emit = Arc::new(move |e: Event| {
                let _ = tx.send(Msg::Exposure(e));
                ctx.request_repaint();
            });
            exposure::run(tasks, asked, Arc::new(exposure::Https), cancel, emit, true);
        });
    }

    fn start_password_check(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        if self.exp.pw_input.is_empty() {
            return;
        }
        let sources = self.enabled_pw_sources(sh);
        if sh.demo {
            let seen = if self.exp.pw_input.as_str() == "password" {
                10_434_004
            } else {
                0
            };
            self.exp.pw_results = [PwSource::PwnedPasswords, PwSource::XposedOrNot]
                .into_iter()
                .map(|s| (s, Ok(seen)))
                .collect();
            self.exp.pw_input.wipe();
            return;
        }
        let password = self.exp.pw_input.to_secret();
        self.exp.pw_input.wipe();
        let keys: Vec<(PwSource, Option<zeroize::Zeroizing<String>>)> = sources
            .iter()
            .map(|s| {
                (
                    *s,
                    s.key_name()
                        .and_then(|k| self.v.vault.service_key(k))
                        .map(|k| zeroize::Zeroizing::new(k.open_str().to_string())),
                )
            })
            .collect();
        self.exp.pw_busy = true;
        self.exp.pw_results.clear();
        sh.spawn(ctx, move || {
            let t = exposure::Https;
            let results = keys
                .into_iter()
                .map(|(s, key)| {
                    let r = exposure::password::check(
                        s,
                        &t,
                        password.as_str(),
                        key.as_ref().map(|k| k.as_str()),
                    )
                    .map_err(|e| e.to_string());
                    (s, r)
                })
                .collect();
            Msg::PwChecked(results)
        });
    }

    fn start_site_scan(&mut self, ctx: &egui::Context, sh: &mut Shared, username: String) {
        let Ok(username) = QueryKind::Username.normalize(&username) else {
            return;
        };
        let now = sh.now;
        self.exp
            .cache
            .record_mut(QueryKind::Username, &username, now);
        self.exp.selected = Some((QueryKind::Username, username.clone()));
        if sh.demo {
            let found = crate::demo::site_hits(&username);
            self.exp
                .cache
                .record_mut(QueryKind::Username, &username, now)
                .sites = Some(SiteScan {
                when: now,
                asked: 557,
                unclear: 61,
                found,
                complete: true,
            });
            self.exp.generation += 1;
            return;
        }
        let list: Vec<sites::Site> = sites::parse(sites::DATA)
            .into_iter()
            .filter(|s| s.usable(false) && s.request(&username).is_some())
            .collect();
        let cancel = Arc::new(AtomicBool::new(false));
        self.exp.sites_run = Some(SitesRun {
            username: username.clone(),
            done: 0,
            total: list.len(),
            cancel: cancel.clone(),
            hits: Vec::new(),
        });
        let (tx, ctx) = (sh.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let emit = Arc::new(move |e: SiteEvent| {
                let _ = tx.send(Msg::Sites(e));
                ctx.request_repaint();
            });
            sites::scan(
                &username,
                list,
                Arc::new(exposure::Https),
                cancel,
                sites::WORKERS,
                emit,
            );
        });
    }

    fn start_vault_sites(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        if sh.demo {
            self.exp.cache.site_breaches = crate::demo::site_breaches();
            self.exp.cache.sites_checked = sh.now;
            self.exp.generation += 1;
            return;
        }
        self.exp.vault_sites_busy = true;
        sh.spawn(ctx, || {
            Msg::SiteList(
                exposure::sources::hibp_all_breaches(&exposure::Https).map_err(|e| e.to_string()),
            )
        });
    }

    /// Every email address, user name and phone number in the vault.
    pub(super) fn all_vault_tasks(&self) -> Vec<Task> {
        let v = &self.v.vault;
        let mut tasks: Vec<Task> = Vec::new();
        for (kind, list) in [
            (QueryKind::Email, v.emails()),
            (QueryKind::Username, v.usernames()),
            (QueryKind::Phone, v.phones()),
        ] {
            for value in list {
                if let Ok(value) = kind.normalize(&value) {
                    if !tasks.iter().any(|t| t.kind == kind && t.value == value) {
                        tasks.push(Task { kind, value });
                    }
                }
            }
        }
        tasks
    }

    /// The optional periodic re-check: once per unlock, when it is on and
    /// the last full check is older than the chosen number of days.
    pub(super) fn exposure_auto(&mut self, ctx: &egui::Context, sh: &mut Shared) {
        if self.exp.auto_considered || sh.shot {
            return;
        }
        self.exp.auto_considered = true;
        let days = sh.settings.exposure_recheck_days;
        if days == 0 || sh.demo || self.exp.busy() {
            return;
        }
        let last = self.exp.cache.last_all;
        if last > 0 && sh.now - last < i64::from(days) * util::DAY {
            return;
        }
        let tasks = self.all_vault_tasks();
        if tasks.is_empty() || self.enabled_sources(sh, &tasks).is_empty() {
            return;
        }
        sh.toast("Checking your addresses and user names again (Exposure check, Settings › Online checks).", false);
        self.start_lookup(ctx, sh, tasks, true);
    }

    // ----------------------------------------------------------------------------------
    // Results arriving
    // ----------------------------------------------------------------------------------

    pub(super) fn exposure_event(&mut self, ctx: &egui::Context, sh: &mut Shared, e: Event) {
        match e {
            Event::Result {
                kind,
                value,
                source,
                result,
            } => {
                self.exp
                    .cache
                    .record_mut(kind, &value, sh.now)
                    .apply(source, result);
                if let Some(run) = &mut self.exp.run {
                    run.done += 1;
                }
                self.exp.generation += 1;
            }
            Event::Done => {
                if let Some(run) = self.exp.run.take() {
                    if run.all && !run.cancel.load(Ordering::Relaxed) {
                        self.exp.cache.last_all = sh.now;
                    }
                }
                self.exposure_store(ctx, sh);
            }
        }
    }

    pub(super) fn sites_event(&mut self, ctx: &egui::Context, sh: &mut Shared, e: SiteEvent) {
        let Some(run) = &mut self.exp.sites_run else {
            return;
        };
        match e {
            SiteEvent::Progress { done, total } => {
                run.done = done;
                run.total = total;
            }
            SiteEvent::Hit(hit) => run.hits.push(hit),
            SiteEvent::Done {
                asked,
                unclear,
                complete,
            } => {
                let mut run = self.exp.sites_run.take().expect("checked above");
                run.hits.sort_by_key(|h| h.name.to_lowercase());
                let now = sh.now;
                self.exp
                    .cache
                    .record_mut(QueryKind::Username, &run.username, now)
                    .sites = Some(SiteScan {
                    when: now,
                    asked,
                    unclear,
                    found: run.hits,
                    complete,
                });
                self.exposure_store(ctx, sh);
            }
        }
    }

    pub(super) fn site_list_arrived(
        &mut self,
        ctx: &egui::Context,
        sh: &mut Shared,
        result: Result<Vec<Finding>, String>,
    ) {
        self.exp.vault_sites_busy = false;
        match result {
            Ok(all) => {
                // Only the breaches of sites in the vault are kept.
                self.exp.cache.site_breaches = exposure::breaches_for_vault(&self.v.vault, &all);
                self.exp.cache.sites_checked = sh.now;
                self.exposure_store(ctx, sh);
            }
            Err(e) => self.exp.problem = Some(format!("Have I Been Pwned: {e}")),
        }
    }

    // ----------------------------------------------------------------------------------
    // The page
    // ----------------------------------------------------------------------------------

    pub(super) fn exposure_ui(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        let ctx = ui.ctx().clone();
        page_header(
            ui,
            "Exposure check",
            "Is your email, user name, phone or password in known breaches, leaks or infostealer logs?",
            |_| {},
        );
        let mut request: Option<Pending> = None;
        let mut go_settings = false;
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_max_width((ui.available_width() - 12.0).min(960.0));
                ui.spacing_mut().item_spacing.y = 12.0;

                // What to check.
                widgets::card(ui, |ui| {
                    ui.spacing_mut().item_spacing.y = 8.0;
                    let tabs = [
                        Tab::Lookup(QueryKind::Email),
                        Tab::Lookup(QueryKind::Username),
                        Tab::Lookup(QueryKind::Phone),
                        Tab::Lookup(QueryKind::Domain),
                        Tab::Password,
                    ];
                    let labels = ["Email", "User name", "Phone", "Domain", "Password"];
                    let current = tabs.iter().position(|t| *t == self.exp.tab).unwrap_or(0);
                    if let Some(i) = widgets::segmented(ui, &labels, current) {
                        if tabs[i] != self.exp.tab {
                            self.exp.tab = tabs[i];
                            self.exp.input.clear();
                            self.exp.selected = None;
                        }
                    }
                    match self.exp.tab {
                        Tab::Lookup(kind) => {
                            self.lookup_input(ui, sh, kind, &mut request, &mut go_settings)
                        }
                        Tab::Password => {
                            self.password_input(ui, sh, &mut request, &mut go_settings)
                        }
                    }
                });
                if let Some(problem) = &self.exp.problem {
                    widgets::banner(ui, Icon::ERROR, p.warn, problem);
                }

                match self.exp.tab {
                    Tab::Lookup(kind) => {
                        self.records_list(ui, sh, kind);
                        let selected = self
                            .exp
                            .selected
                            .clone()
                            .filter(|(k, _)| *k == kind)
                            .and_then(|(k, v)| self.exp.cache.record(k, &v).cloned());
                        if let Some(record) = selected {
                            self.record_view(ui, sh, &record, &mut request);
                        }
                        if kind == QueryKind::Domain {
                            self.vault_sites_card(ui, sh, &mut request);
                        }
                    }
                    Tab::Password => self.password_results(ui, sh),
                }

                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 4.0;
                    ui.label(RichText::new("Data from").size(12.0).color(p.faint));
                    for (name, url) in [
                        ("Have I Been Pwned", "https://haveibeenpwned.com"),
                        ("XposedOrNot", "https://xposedornot.com"),
                        ("Powered by LeakCheck", "https://leakcheck.io"),
                        ("Hudson Rock", "https://www.hudsonrock.com/free-tools"),
                        ("Leak-Lookup", "https://leak-lookup.com"),
                        ("Enzoic", "https://www.enzoic.com"),
                        ("WhatsMyName (CC BY-SA 4.0)", sites::PROJECT),
                    ] {
                        if ui
                            .add(
                                egui::Label::new(RichText::new(name).size(12.0).color(p.muted))
                                    .sense(Sense::click()),
                            )
                            .on_hover_text(url)
                            .on_hover_cursor(egui::CursorIcon::PointingHand)
                            .clicked()
                        {
                            if let Err(e) = crate::sys::open_url(url) {
                                sh.toast(e, true);
                            }
                        }
                        ui.label(RichText::new("·").size(12.0).color(p.faint));
                    }
                    ui.label(
                        RichText::new("Not affiliated with any of them.")
                            .size(12.0)
                            .color(p.faint),
                    );
                });
                ui.add_space(8.0);
            });
        if go_settings {
            self.nav = Nav::Settings;
        }
        if let Some(what) = request {
            self.exposure_request(&ctx, sh, what);
        }
    }

    fn sources_line(&self, ui: &mut Ui, sh: &Shared, kinds: &[QueryKind], go_settings: &mut bool) {
        let p = pal(ui);
        let mut on: Vec<String> = Vec::new();
        let mut off: Vec<String> = Vec::new();
        for s in SourceId::ALL {
            if !kinds.iter().any(|k| s.supports(*k))
                || (s == SourceId::HibpDomain && !kinds.contains(&QueryKind::Domain))
            {
                continue;
            }
            let has_key = s
                .key_name()
                .is_none_or(|k| self.v.vault.service_key(k).is_some())
                || sh.demo;
            if sh.settings.source_on(s.code())
                || (sh.demo && crate::demo::DEMO_SOURCES.contains(&s.code()))
            {
                on.push(if has_key {
                    s.name().to_string()
                } else {
                    format!("{} (no key yet)", s.name())
                });
            } else {
                off.push(s.name().to_string());
            }
        }
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            if on.is_empty() {
                ui.label(
                    RichText::new("No source is on yet; pressing Check lets you choose.")
                        .size(12.5)
                        .color(p.muted),
                );
            } else {
                ui.label(
                    RichText::new(format!("Asks: {}", on.join(", ")))
                        .size(12.5)
                        .color(p.muted),
                );
            }
            if !off.is_empty() {
                ui.label(
                    RichText::new(format!("· Off: {}", off.join(", ")))
                        .size(12.5)
                        .color(p.faint),
                );
            }
            if widgets::link(ui, "Sources and keys…").clicked() {
                *go_settings = true;
            }
        });
    }

    fn lookup_input(
        &mut self,
        ui: &mut Ui,
        sh: &mut Shared,
        kind: QueryKind,
        request: &mut Option<Pending>,
        go_settings: &mut bool,
    ) {
        let p = pal(ui);
        let busy = self.exp.busy();
        let suggestions: Vec<String> = match kind {
            QueryKind::Email => self.v.vault.emails(),
            QueryKind::Username => self.v.vault.usernames(),
            QueryKind::Phone => self.v.vault.phones(),
            QueryKind::Domain => Vec::new(),
        };
        let input_w = (ui.available_width() - 380.0).clamp(220.0, 400.0);
        ui.horizontal_wrapped(|ui| {
            let resp = widgets::text_input(ui, &mut self.exp.input, kind.hint(), input_w);
            let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if (widgets::primary_button(ui, "Check", !busy).clicked() || enter) && !busy {
                match kind.normalize(&self.exp.input) {
                    Ok(value) => *request = Some(Pending::Lookup(vec![Task { kind, value }], false)),
                    Err(e) => self.exp.problem = Some(e.to_string()),
                }
            }
            if kind != QueryKind::Domain {
                let tasks = self.all_vault_tasks();
                if !tasks.is_empty()
                    && widgets::ghost_button_enabled(ui, &format!("Check all from my vault ({})", tasks.len()), !busy)
                        .on_hover_text("Every email address, user name and phone number saved in this vault, one source request at a time.")
                        .clicked()
                {
                    *request = Some(Pending::Lookup(tasks, true));
                }
            }
        });
        if !suggestions.is_empty() {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("From your vault:").size(12.5).color(p.faint));
                for value in suggestions.iter().take(12) {
                    if widgets::chip(ui, value, None, false).clicked() && !busy {
                        self.exp.input = value.clone();
                        if let Ok(value) = kind.normalize(value) {
                            *request = Some(Pending::Lookup(vec![Task { kind, value }], false));
                        }
                    }
                }
            });
        }
        self.sources_line(ui, sh, &[kind], go_settings);
        if let Some(run) = &self.exp.run {
            let cancel = run.cancel.clone();
            let (done, total) = (run.done, run.total.max(1));
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().size(16.0).color(p.accent));
                ui.label(format!(
                    "{done} of {total} answers (each service is asked at its own pace)"
                ));
                if widgets::ghost_button(ui, "Cancel").clicked() {
                    cancel.store(true, Ordering::Relaxed);
                }
            });
            let w = ui.available_width();
            widgets::progress_bar(ui, done as f32 / total as f32, w, p.accent);
        }
        let last = self.exp.cache.last_all;
        let text = match kind {
            QueryKind::Email | QueryKind::Username | QueryKind::Phone => format!(
                "Only check your own details. Nothing is sent until you press Check{}",
                if last > 0 {
                    format!(". \"Check all\" last ran {}.", util::ago(last, sh.now))
                } else {
                    ".".to_string()
                }
            ),
            QueryKind::Domain => "A domain shows two things: breaches at that website (from the public Have I Been Pwned list) and infostealer logs with logins for it (Hudson Rock).".to_string(),
        };
        widgets::note(ui, &text);
    }

    fn records_list(&mut self, ui: &mut Ui, sh: &mut Shared, kind: QueryKind) {
        let p = pal(ui);
        let records: Vec<Record> = self
            .exp
            .cache
            .records
            .iter()
            .filter(|r| r.kind == kind)
            .cloned()
            .collect();
        if records.is_empty() {
            return;
        }
        let mut remove: Option<String> = None;
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 2.0;
            widgets::section(ui, &format!("Checked ({})", records.len()));
            let now = util::now();
            for r in records.iter().take(60) {
                let selected = self.exp.selected.as_ref() == Some(&(r.kind, r.value.clone()));
                let (text, bad) = summary(r);
                let (rect, resp) =
                    ui.allocate_exact_size(vec2(ui.available_width(), 38.0), Sense::click());
                let value_w = (rect.width() * 0.4).clamp(160.0, 330.0);
                if selected {
                    ui.painter()
                        .rect_filled(rect, egui::CornerRadius::same(8), p.selected);
                } else if resp.hovered() {
                    ui.painter()
                        .rect_filled(rect, egui::CornerRadius::same(8), p.hover);
                }
                ui.painter().text(
                    rect.left_center() + vec2(10.0, 0.0),
                    egui::Align2::LEFT_CENTER,
                    kind_icon(kind).glyph(),
                    regular(15.0),
                    p.muted,
                );
                widgets::text_in(
                    ui,
                    egui::Rect::from_min_max(
                        rect.min + vec2(36.0, 0.0),
                        egui::pos2(rect.left() + value_w, rect.bottom()),
                    ),
                    &r.value,
                    regular(14.0),
                    p.text,
                );
                let color = if bad {
                    p.danger
                } else if text == "Nothing found" {
                    p.accent
                } else {
                    p.muted
                };
                widgets::text_in(
                    ui,
                    egui::Rect::from_min_max(
                        egui::pos2(rect.left() + value_w + 10.0, rect.top()),
                        rect.max - vec2(190.0, 0.0),
                    ),
                    &text,
                    regular(13.0),
                    color,
                );
                let failed = r.failed();
                let when = if failed > 0 {
                    format!("{} · {} failed", util::ago(r.checked, now), failed)
                } else {
                    util::ago(r.checked, now)
                };
                widgets::text_in_right(
                    ui,
                    egui::Rect::from_min_max(
                        rect.right_top() - vec2(185.0, 0.0),
                        rect.right_bottom() - vec2(36.0, 0.0),
                    ),
                    &when,
                    regular(12.0),
                    p.faint,
                );
                let x = egui::Rect::from_center_size(
                    rect.right_center() - vec2(16.0, 0.0),
                    vec2(22.0, 22.0),
                );
                let x_resp = ui.interact(x, ui.id().with(("forget", &r.value)), Sense::click());
                ui.painter().text(
                    x.center(),
                    egui::Align2::CENTER_CENTER,
                    Icon::CLOSE.glyph(),
                    regular(11.0),
                    if x_resp.hovered() { p.danger } else { p.faint },
                );
                if x_resp.on_hover_text("Forget this result").clicked() {
                    remove = Some(r.value.clone());
                } else if resp
                    .on_hover_cursor(egui::CursorIcon::PointingHand)
                    .clicked()
                {
                    self.exp.selected = Some((r.kind, r.value.clone()));
                }
            }
        });
        if let Some(value) = remove {
            self.exp.cache.remove(kind, &value);
            if self
                .exp
                .selected
                .as_ref()
                .map(|(_, v)| v == &value)
                .unwrap_or(false)
            {
                self.exp.selected = None;
            }
            let ctx = ui.ctx().clone();
            self.exposure_store(&ctx, sh);
        }
    }

    fn record_view(
        &mut self,
        ui: &mut Ui,
        sh: &mut Shared,
        r: &Record,
        request: &mut Option<Pending>,
    ) {
        let p = pal(ui);
        let exposures = r.exposures();
        let change: Vec<(Id, String)> = exposure::items_to_change(&self.v.vault, exposures.iter());
        // Headline.
        let (headline, color) = if exposures.is_empty() {
            if r.outcomes.iter().any(|o| o.state != OutcomeState::Failed) {
                ("Not found in the sources that answered. That is good news, though no service knows every leak.".to_string(), p.accent)
            } else if r.outcomes.is_empty() {
                ("Not checked by any online source yet.".to_string(), p.muted)
            } else {
                ("No source could be asked. See below.".to_string(), p.warn)
            }
        } else {
            let mut text = summary(r).0;
            if !change.is_empty() {
                text.push_str(&format!(
                    "; {} saved {} should get a new password",
                    change.len(),
                    if change.len() == 1 { "login" } else { "logins" }
                ));
            }
            (
                text,
                if exposures.iter().any(|e| e.severity() >= Severity::High) {
                    p.danger
                } else {
                    p.warn
                },
            )
        };
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(kind_icon(r.kind).glyph())
                        .size(18.0)
                        .color(p.muted),
                );
                widgets::line_label(ui, &r.value, semibold(17.0), p.text);
                ui.label(
                    RichText::new(format!("checked {}", util::ago(r.checked, util::now())))
                        .size(12.5)
                        .color(p.faint),
                );
            });
            ui.add(
                egui::Label::new(RichText::new(headline).font(semibold(15.0)).color(color)).wrap(),
            );
            // Which sources were asked and how they did.
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = vec2(6.0, 4.0);
                for o in &r.outcomes {
                    let (icon, c, text) = match o.state {
                        OutcomeState::Found => (
                            Icon::WARNING,
                            p.danger,
                            format!("{}: {} found", o.source.name(), o.count),
                        ),
                        OutcomeState::Clean => (
                            Icon::DONE,
                            p.accent,
                            format!("{}: nothing found", o.source.name()),
                        ),
                        _ => (
                            Icon::ERROR,
                            p.warn,
                            format!("{}: {}", o.source.name(), o.message),
                        ),
                    };
                    widgets::badge(ui, &icon.with(&text), c);
                }
            });
            for o in r
                .outcomes
                .iter()
                .filter(|o| o.state != OutcomeState::Failed && !o.message.is_empty())
            {
                widgets::note(ui, &format!("{}: {}", o.source.name(), o.message));
            }
        });

        let shown = 80;
        for e in exposures.iter().take(shown) {
            if self.exp.scroll_to_results && e.kind == FindingKind::Breach {
                ui.scroll_to_cursor(Some(egui::Align::TOP));
                self.exp.scroll_to_results = false;
            }
            self.exposure_card(ui, sh, e);
        }
        if exposures.len() > shown {
            widgets::note(
                ui,
                &format!(
                    "… and {} more, mostly smaller leaks without details.",
                    exposures.len() - shown
                ),
            );
        }
        if r.kind == QueryKind::Username {
            self.sites_card(ui, sh, r, request);
        }
    }

    fn exposure_card(&mut self, ui: &mut Ui, sh: &mut Shared, e: &Exposure) {
        let p = pal(ui);
        let matches = exposure::matching_items(&self.v.vault, e);
        let sev = e.severity();
        let sev_color = severity_color(ui, sev);
        let mut open: Option<String> = None;
        let mut go: Option<Id> = None;
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            ui.horizontal(|ui| {
                let (tile, _) = ui.allocate_exact_size(vec2(36.0, 36.0), Sense::hover());
                widgets::letter_tile(ui, tile, &e.name);
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&e.name).font(semibold(16.0)));
                        widgets::badge(ui, sev.label(), sev_color);
                        let kind = match e.kind {
                            FindingKind::Stealer | FindingKind::StealerSite => "Infostealer",
                            FindingKind::Paste => "Paste",
                            FindingKind::SiteBreach => "Site breach",
                            _ => "Breach",
                        };
                        widgets::badge(ui, kind, p.muted);
                    });
                    let mut facts: Vec<String> = Vec::new();
                    if !e.date.is_empty() {
                        facts.push(match e.kind {
                            FindingKind::Stealer => format!("Infected {}", e.date),
                            _ => format!("Happened {}", e.date),
                        });
                    }
                    if e.records > 0 {
                        facts.push(format!("{} accounts", util::thousands(e.records)));
                    }
                    if !e.domain.is_empty() && !e.name.eq_ignore_ascii_case(&e.domain) {
                        facts.push(e.domain.clone());
                    }
                    if !e.password_risk.is_empty() && e.password_risk != "unknown" {
                        facts.push(format!("passwords stored: {}", e.password_risk));
                    }
                    ui.label(RichText::new(facts.join(" · ")).size(12.5).color(p.muted));
                });
            });
            if !e.data.is_empty() {
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = vec2(6.0, 4.0);
                    for d in e.data.iter().take(16) {
                        let lower = d.to_lowercase();
                        let c = if lower.contains("password") {
                            p.danger
                        } else if lower.contains("phone")
                            || lower.contains("address")
                            || lower.contains("birth")
                        {
                            p.warn
                        } else {
                            p.info
                        };
                        widgets::badge(ui, d, c);
                    }
                });
            }
            if !e.facts.is_empty() {
                ui.label(RichText::new(e.facts.join(" · ")).size(12.5).color(p.muted));
            }
            if !e.description.is_empty() {
                ui.add(
                    egui::Label::new(RichText::new(&e.description).size(13.0).color(p.muted))
                        .wrap(),
                );
            }
            // What to do.
            ui.label(RichText::new("What to do").font(semibold(13.5)));
            ui.scope(|ui| {
                ui.spacing_mut().item_spacing.y = 3.0;
                for line in e.advice() {
                    let mut job = egui::text::LayoutJob::default();
                    let font = regular(13.0);
                    job.append(
                        "•  ",
                        0.0,
                        egui::TextFormat::simple(font.clone(), sev_color),
                    );
                    job.append(&line, 0.0, egui::TextFormat::simple(font, p.text));
                    ui.add(egui::Label::new(job).wrap());
                }
            });
            // The logins it concerns.
            if !matches.is_empty() {
                widgets::divider(ui);
                for m in &matches {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(Icon::KEY.glyph()).color(p.muted));
                        ui.label(
                            RichText::new("You have an account here in KeepForge:")
                                .size(13.0)
                                .color(p.muted),
                        );
                        widgets::line_label(ui, &m.title, regular(14.0), p.text);
                        if m.change_password {
                            widgets::badge(ui, "Change its password", p.danger);
                        } else {
                            widgets::badge(ui, "Password changed since", p.accent);
                        }
                        if widgets::ghost_button(
                            ui,
                            &format!("Open {}", Icon::CHEVRON_RIGHT.glyph()),
                        )
                        .clicked()
                        {
                            go = Some(m.item);
                        }
                    });
                }
            }
            // Who reported it.
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing.x = 6.0;
                let names: Vec<&str> = e.sources.iter().map(|s| s.short()).collect::<Vec<_>>();
                let mut names = names;
                names.dedup();
                ui.label(
                    RichText::new(format!("Reported by {}", names.join(", ")))
                        .size(12.0)
                        .color(p.faint),
                );
                for (source, link) in &e.links {
                    if widgets::link(ui, &format!("Details ({})", source.short()))
                        .on_hover_text(link)
                        .clicked()
                    {
                        open = Some(link.clone());
                    }
                }
            });
        });
        if let Some(url) = open {
            if let Err(err) = crate::sys::open_url(&url) {
                sh.toast(err, true);
            }
        }
        if let Some(id) = go {
            self.go_to_item(id);
        }
    }

    fn sites_card(
        &mut self,
        ui: &mut Ui,
        sh: &mut Shared,
        r: &Record,
        request: &mut Option<Pending>,
    ) {
        let p = pal(ui);
        let total_sites = sites::parse(sites::DATA)
            .iter()
            .filter(|s| s.usable(false))
            .count();
        let mut open: Option<String> = None;
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "Where is this user name registered?");
            widgets::note(ui, &format!(
                "KeepForge can ask the public profile address of about {total_sites} websites whether an account called \"{}\" exists. That shows accounts you may have forgotten (close them, or give them a unique password). Each website sees the user name and your IP address; sites that block automated visits or need a login are skipped.",
                r.value
            ));
            let running = self.exp.sites_run.as_ref().map(|s| {
                (
                    s.username.clone(),
                    s.done,
                    s.total,
                    s.cancel.clone(),
                    s.hits.len(),
                )
            });
            match running {
                Some((name, done, total, cancel, hits)) => {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().size(16.0).color(p.accent));
                        ui.label(format!(
                            "Asking websites about {name}: {done} of {total}, {hits} found so far"
                        ));
                        if widgets::ghost_button(ui, "Cancel").clicked() {
                            cancel.store(true, Ordering::Relaxed);
                        }
                    });
                    let w = ui.available_width();
                    widgets::progress_bar(ui, done as f32 / total.max(1) as f32, w, p.accent);
                }
                None => {
                    widgets::checkbox(
                        ui,
                        &mut self.exp.own_username,
                        "This is my own user name. I am not looking up someone else.",
                    );
                    ui.horizontal(|ui| {
                        let label = if r.sites.is_some() {
                            "Search the websites again"
                        } else {
                            "Search the websites"
                        };
                        if widgets::primary_button(
                            ui,
                            label,
                            self.exp.own_username && !self.exp.busy(),
                        )
                        .clicked()
                        {
                            *request = Some(Pending::Sites(r.value.clone()));
                        }
                        ui.label(
                            RichText::new("Takes a minute or two; six websites at a time.")
                                .size(12.5)
                                .color(p.faint),
                        );
                    });
                }
            }
            if let Some(scan) = &r.sites {
                widgets::divider(ui);
                ui.label(
                    RichText::new(format!(
                        "{} on {} of {} websites asked{} ({}). {} gave no clear answer.",
                        if scan.found.is_empty() {
                            "No account found"
                        } else {
                            "Accounts found"
                        },
                        scan.found.len(),
                        scan.asked,
                        if scan.complete {
                            ""
                        } else {
                            ", search cancelled"
                        },
                        util::ago(scan.when, util::now()),
                        scan.unclear
                    ))
                    .size(13.0)
                    .color(p.muted),
                );
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing = vec2(6.0, 6.0);
                    for hit in &scan.found {
                        if widgets::chip(
                            ui,
                            &format!("{}  ·  {}", hit.name, hit.category),
                            None,
                            false,
                        )
                        .on_hover_text(format!("Open {}", hit.url))
                        .clicked()
                        {
                            open = Some(hit.url.clone());
                        }
                    }
                });
                if !scan.found.is_empty() {
                    widgets::note(ui, "A match means a profile page exists for that name; it may belong to someone else with the same name.");
                }
            }
            ui.label(
                RichText::new(format!(
                    "{}. KeepForge uses an unchanged copy of the list.",
                    sites::ATTRIBUTION
                ))
                .size(12.0)
                .color(p.faint),
            );
        });
        if let Some(url) = open {
            if let Err(e) = crate::sys::open_url(&url) {
                sh.toast(e, true);
            }
        }
    }

    fn vault_sites_card(&mut self, ui: &mut Ui, sh: &mut Shared, request: &mut Option<Pending>) {
        let p = pal(ui);
        let found = exposure::merge(&self.exp.cache.site_breaches);
        let checked = self.exp.cache.sites_checked;
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            widgets::section(ui, "Were the sites in my vault breached?");
            widgets::note(ui, "Downloads the public list of every breach Have I Been Pwned knows about (no key, nothing about you is sent) and compares it with the web addresses of your saved logins on this PC.");
            ui.horizontal(|ui| {
                let busy = self.exp.busy();
                if self.exp.vault_sites_busy {
                    ui.add(egui::Spinner::new().size(16.0).color(p.accent));
                    ui.label("Downloading the list…");
                } else if widgets::primary_button(
                    ui,
                    if checked > 0 {
                        "Compare again"
                    } else {
                        "Compare my saved sites"
                    },
                    !busy,
                )
                .clicked()
                {
                    *request = Some(Pending::VaultSites);
                }
                if checked > 0 {
                    ui.label(
                        RichText::new(format!("Last compared {}", util::ago(checked, sh.now)))
                            .size(12.5)
                            .color(p.faint),
                    );
                }
            });
        });
        if checked > 0 {
            if found.is_empty() {
                widgets::note(
                    ui,
                    "None of the sites saved in this vault is in the list of known breaches.",
                );
            }
            for e in found.iter().take(80) {
                self.exposure_card(ui, sh, e);
            }
        }
    }

    fn password_input(
        &mut self,
        ui: &mut Ui,
        sh: &mut Shared,
        request: &mut Option<Pending>,
        go_settings: &mut bool,
    ) {
        let p = pal(ui);
        let input_w = (ui.available_width() - 380.0).clamp(220.0, 400.0);
        ui.horizontal_wrapped(|ui| {
            widgets::secret_input(ui, &mut self.exp.pw_input, false, "Type or paste a password", input_w);
            let ready = !self.exp.pw_input.is_empty() && !self.exp.busy();
            if widgets::primary_button(ui, "Check", ready).clicked() {
                *request = Some(Pending::Password);
            }
            if widgets::ghost_button(ui, "Check all saved passwords").on_hover_text("Opens the security dashboard and checks every saved password with Pwned Passwords.").clicked() {
                self.nav = Nav::Health;
                let ctx = ui.ctx().clone();
                self.request_pwned_scan(&ctx, sh);
            }
        });
        let on: Vec<&str> = self
            .enabled_pw_sources(sh)
            .iter()
            .map(|s| s.name())
            .collect();
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 6.0;
            let text = if on.is_empty() {
                "No password source is on yet; pressing Check lets you choose.".to_string()
            } else {
                format!("Asks: {}", on.join(", "))
            };
            ui.label(RichText::new(text).size(12.5).color(p.muted));
            if widgets::link(ui, "Sources and keys…").clicked() {
                *go_settings = true;
            }
        });
        widgets::note(ui, "The password is hashed on this PC and only the first characters of the hash are sent; the match is made here. The password and its full hash never leave this PC.");
    }

    fn password_results(&mut self, ui: &mut Ui, _sh: &mut Shared) {
        let p = pal(ui);
        if self.exp.pw_busy {
            widgets::card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::Spinner::new().size(16.0).color(p.accent));
                    ui.label("Checking…");
                });
            });
            return;
        }
        if self.exp.pw_results.is_empty() {
            return;
        }
        let worst = self
            .exp
            .pw_results
            .iter()
            .filter_map(|(_, r)| r.as_ref().ok())
            .copied()
            .max()
            .unwrap_or(0);
        widgets::card(ui, |ui| {
            ui.spacing_mut().item_spacing.y = 6.0;
            if worst > 0 {
                ui.label(
                    RichText::new(Icon::WARNING.with(&format!(
                        "Seen {} times in known breaches. Do not use this password anywhere.",
                        util::thousands(worst)
                    )))
                    .font(semibold(15.0))
                    .color(p.danger),
                );
                widgets::note(ui, "Attackers try leaked passwords first. If you use it, change it on every site, starting with email and banking.");
            } else if self.exp.pw_results.iter().any(|(_, r)| r.is_ok()) {
                ui.label(
                    RichText::new(
                        Icon::DONE.with(
                            "Not found in known breaches. That alone does not make it strong.",
                        ),
                    )
                    .font(semibold(15.0))
                    .color(p.accent),
                );
            }
            for (source, result) in &self.exp.pw_results {
                let (c, text) = match result {
                    Ok(0) => (p.accent, "not found".to_string()),
                    Ok(n) => (p.danger, format!("seen {} times", util::thousands(*n))),
                    Err(e) => (p.warn, e.clone()),
                };
                ui.label(
                    RichText::new(format!("{}: {text}", source.name()))
                        .size(13.0)
                        .color(c),
                );
            }
        });
    }

    // ----------------------------------------------------------------------------------
    // Settings › Online checks
    // ----------------------------------------------------------------------------------

    pub(super) fn exposure_settings(&mut self, ui: &mut Ui, sh: &mut Shared) {
        let p = pal(ui);
        widgets::note(ui, "KeepForge works offline. Each source below is off until you turn it on, and is only asked when you press Check. No telemetry is ever sent.");
        let mut open: Option<&'static str> = None;
        let mut save: Option<&'static str> = None;
        let mut remove: Option<&'static str> = None;
        let rows: Vec<SourceRow> = SourceId::ALL
            .into_iter()
            .map(|s| {
                let kinds: Vec<&str> = s.kinds().iter().map(|k| k.label()).collect();
                SourceRow {
                    code: s.code(),
                    name: s.name(),
                    text: format!("Checks: {}. {} Finds: {}", kinds.join(", ").to_lowercase(), s.sends(), s.returns()),
                    key_name: s.key_name(),
                    key_page: s.key_page(),
                    home: s.home(),
                }
            })
            .chain(PwSource::ALL.into_iter().map(|s| SourceRow {
                code: if s == PwSource::PwnedPasswords { crate::settings::Settings::PWNED_CODE } else { s.code() },
                name: s.name(),
                text: format!("Checks: passwords. {}", s.sends()),
                key_name: s.key_name(),
                key_page: s.key_page(),
                home: s.home(),
            }))
            .chain(std::iter::once(SourceRow {
                code: SITES_CODE,
                name: "Where a user name is registered",
                text: "Checks: your own user name. Asks the public profile page of about 550 websites from the WhatsMyName list, six at a time. Each website sees the user name and your IP address.".to_string(),
                key_name: None,
                key_page: "",
                home: sites::PROJECT,
            }))
            .collect();
        for (i, row) in rows.into_iter().enumerate() {
            let SourceRow {
                code,
                name,
                text,
                key_name,
                key_page,
                home,
            } = row;
            if i > 0 {
                widgets::divider(ui);
            }
            let mut on = sh.settings.source_on(code);
            let was = on;
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.set_width((ui.available_width() - 90.0).max(200.0));
                    ui.spacing_mut().item_spacing.y = 1.0;
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(name).font(regular(14.5)));
                        if key_name.is_some() {
                            widgets::badge(ui, "Your own API key", p.info);
                        } else {
                            widgets::badge(ui, "Free", p.accent);
                        }
                        if widgets::link(ui, "Website").on_hover_text(home).clicked() {
                            open = Some(home);
                        }
                    });
                    ui.add(egui::Label::new(RichText::new(text).size(12.5).color(p.muted)).wrap());
                });
                if widgets::toggle(ui, on, true).clicked() {
                    on = !on;
                }
            });
            if on != was {
                sh.settings.set_source(code, on);
            }
            if let Some(key_name) = key_name {
                let stored = self.v.vault.service_key(key_name).is_some();
                ui.horizontal(|ui| {
                    ui.add_space(4.0);
                    let input = self.exp.key_inputs.entry(key_name).or_default();
                    let hint = if key_name == "enzoic-api-key" {
                        if stored {
                            "Stored. Paste key:secret to replace it"
                        } else {
                            "API key:secret"
                        }
                    } else if stored {
                        "Stored. Paste a new key to replace it"
                    } else {
                        "API key"
                    };
                    widgets::secret_input(ui, input, false, hint, 300.0);
                    let ready = !input.is_empty();
                    if widgets::primary_button(ui, "Save key", ready).clicked() {
                        save = Some(key_name);
                    }
                    if stored && widgets::ghost_button(ui, "Remove key").clicked() {
                        remove = Some(key_name);
                    }
                    if widgets::link(ui, "Get a key")
                        .on_hover_text(key_page)
                        .clicked()
                    {
                        open = Some(key_page);
                    }
                });
                ui.label(RichText::new(if stored { "A key is stored inside this encrypted vault." } else { "No key stored. Keys are kept only inside this encrypted vault, never in the settings file." }).size(12.0).color(p.faint));
            }
        }
        widgets::divider(ui);
        let mut days = sh.settings.exposure_recheck_days;
        let options: [(u32, &str); 4] = [
            (0, "Never"),
            (7, "Weekly"),
            (30, "Monthly"),
            (90, "Every 3 months"),
        ];
        let labels: Vec<&str> = options.iter().map(|(_, l)| *l).collect();
        let current = options.iter().position(|(d, _)| *d == days).unwrap_or(0);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_width((ui.available_width() - 380.0).max(200.0));
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.label(RichText::new("Check again by itself").font(regular(14.5)));
                ui.add(egui::Label::new(RichText::new("When on, unlocking the vault re-checks all its email addresses, user names and phone numbers with the sources that are on, if the last \"Check all\" is older than this. Off by default: then nothing is ever sent without a click.").size(12.5).color(p.muted)).wrap());
            });
            if let Some(i) = widgets::segmented(ui, &labels, current) {
                days = options[i].0;
            }
        });
        sh.settings.exposure_recheck_days = days;
        if let Some(url) = open {
            if let Err(e) = crate::sys::open_url(url) {
                sh.toast(e, true);
            }
        }
        if let Some(key_name) = save {
            if let Some(input) = self.exp.key_inputs.get_mut(key_name) {
                let text = input.as_str().trim().to_string();
                input.wipe();
                let valid = if key_name == "enzoic-api-key" {
                    text.split_once(':')
                        .is_some_and(|(a, b)| !a.is_empty() && !b.is_empty())
                } else {
                    !text.is_empty()
                        && text.len() <= 100
                        && text.chars().all(|c| c.is_ascii_alphanumeric())
                };
                if valid {
                    let sealed = crate::secret::Protected::seal_str(&self.v.session, &text);
                    self.v.vault.set_service_key(key_name, sealed);
                    sh.toast("Key saved in the vault.", false);
                    self.changed(ui.ctx(), sh);
                } else if key_name == "enzoic-api-key" {
                    sh.toast("Paste the Enzoic key and secret as key:secret.", true);
                } else {
                    sh.toast(
                        "That does not look like an API key (letters and digits only).",
                        true,
                    );
                }
            }
        }
        if let Some(key_name) = remove {
            self.v
                .vault
                .set_service_key(key_name, crate::secret::Protected::default());
            sh.toast("Key removed from the vault.", false);
            self.changed(ui.ctx(), sh);
        }
    }
}
