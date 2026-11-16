//! Application state, background-work plumbing and everything that sits
//! above the individual screens: locking, clipboard, toasts, screenshots.

use super::main_view::Main;
use super::start::{CreateState, UnlockState, WelcomeState};
use super::theme::{self, pal_ctx, semibold, Icon};
use super::widgets;
use crate::breach::{BreachError, EmailResult};
use crate::clipboard::{self, Pending, Tick};
use crate::harden::Step;
use crate::health::Report;
use crate::model::Id;
use crate::settings::Settings;
use crate::store::{OpenError, OpenVault, SaveError, Saved};
use crate::sys::{SysEvent, SysWindow};
use crate::torrent::{PeerError, PeerReport};
use crate::vaultfile::{Calibration, Sealer, VaultError};
use eframe::egui::{
    self, vec2, Align, Align2, CornerRadius, Frame, Layout, Margin, RichText, Stroke,
};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

/// How the app was started.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// Show an invented in-memory vault; nothing is read or written.
    pub demo: bool,
    /// Render one frame of the chosen view to this PNG, then exit.
    pub screenshot: Option<PathBuf>,
    /// Which screen to open first (see `--help`).
    pub view: Option<String>,
    /// Force the light theme (for screenshots).
    pub light: bool,
    /// A vault file to open (from the command line or a double-click).
    pub vault: Option<PathBuf>,
    /// Demo only: lock after this many idle seconds (for testing auto-lock).
    pub idle_lock_secs: Option<u64>,
    /// Hardening steps already applied by `main`, for display and the log.
    pub steps: Vec<Step>,
    /// False when started in compatibility mode after a failed start.
    pub strict: bool,
    /// Removed once the window has drawn its first frames.
    pub start_marker: Option<PathBuf>,
}

/// Results coming back from worker threads.
pub enum Msg {
    Calibrated(Calibration),
    Unlocked(Result<Box<OpenVault>, OpenError>, f64, u64),
    Created(Result<Box<OpenVault>, OpenError>, f64),
    Saved(Result<Saved, SaveError>),
    Health(u64, Report),
    Pwned(Id, Result<u64, String>),
    PwnedDone,
    Email(String, Result<EmailResult, BreachError>),
    EmailDone,
    Peer(Result<PeerReport, PeerError>),
    NewSealer(Result<Sealer, VaultError>, f64),
    ImportLoaded(Result<crate::import::Loaded, String>),
    AutoTyped(Result<(), String>),
    Tool(super::tools::ToolMsg),
    Toast(String, bool),
}

/// Where to go next; returned by the screens.
pub enum Go {
    Welcome,
    Create { then_import: bool },
    Unlock(PathBuf),
    Opened(Box<Opened>),
    Lock,
    LockAndClose,
    Quit,
}

/// A vault that has just been unlocked or created.
pub struct Opened {
    pub vault: OpenVault,
    /// How long the key derivation took, when it was measured.
    pub kdf_secs: Option<f64>,
    /// Go straight to the import dialog.
    pub then_import: bool,
    /// Newly created: offer the emergency sheet.
    pub fresh: bool,
}

pub struct Toast {
    pub text: String,
    pub error: bool,
    pub born: Instant,
}

struct Shot {
    path: PathBuf,
    frames: u32,
    requested: bool,
}

/// State shared by every screen.
pub struct Shared {
    pub settings: Settings,
    saved_settings: Settings,
    pub data_dir: PathBuf,
    pub demo: bool,
    /// Screenshot mode: no clipboard, no dialogs from the system.
    pub shot: bool,
    pub tx: Sender<Msg>,
    pub toasts: Vec<Toast>,
    pub clip: Option<Pending>,
    clock: Instant,
    pub hwnd: isize,
    pub steps: Vec<Step>,
    pub strict: bool,
    pub calibration: Option<Calibration>,
    pub calibrating: bool,
    pub about_open: bool,
    /// Unix time, refreshed every frame.
    pub now: i64,
    pub sys: Option<SysWindow>,
    capture_applied: Option<bool>,
    pub idle_lock_secs: Option<u64>,
}

impl Shared {
    pub fn toast(&mut self, text: impl Into<String>, error: bool) {
        self.toasts.push(Toast {
            text: text.into(),
            error,
            born: Instant::now(),
        });
    }

    fn ms(&self) -> u64 {
        self.clock.elapsed().as_millis() as u64
    }

    /// Milliseconds on the clock the clipboard timer uses.
    pub fn clock_ms(&self) -> u64 {
        self.ms()
    }

    /// Copies a secret: kept out of clipboard history and cloud sync, and
    /// cleared again after the configured delay.
    pub fn copy_secret(&mut self, text: &str, what: &str) {
        if self.shot {
            return;
        }
        match clipboard::set_text(text, true) {
            Ok(sequence) => {
                self.clip = Some(Pending {
                    sequence,
                    set_at_ms: self.ms(),
                    timeout_secs: self.settings.clipboard_seconds,
                });
                self.toast(format!("{what} copied"), false);
            }
            Err(e) => self.toast(e, true),
        }
    }

    /// Copies something that is not a secret (a user name, a checksum).
    pub fn copy_plain(&mut self, text: &str, what: &str) {
        if self.shot {
            return;
        }
        match clipboard::set_text(text, false) {
            Ok(_) => self.toast(format!("{what} copied"), false),
            Err(e) => self.toast(e, true),
        }
    }

    /// Clears the clipboard if it still holds a secret we copied.
    pub fn clear_clipboard(&mut self) {
        if let Some(p) = self.clip.take() {
            clipboard::clear_if_ours(&p);
        }
    }

    /// Runs `work` on a new thread and delivers its result as a message.
    pub fn spawn(&self, ctx: &egui::Context, work: impl FnOnce() -> Msg + Send + 'static) {
        let (tx, ctx) = (self.tx.clone(), ctx.clone());
        std::thread::spawn(move || {
            let _ = tx.send(work());
            ctx.request_repaint();
        });
    }

    /// Starts the "target one second" benchmark unless it has been done.
    pub fn ensure_calibration(&mut self, ctx: &egui::Context) {
        if self.calibration.is_some() || self.calibrating || self.shot {
            return;
        }
        self.calibrating = true;
        self.spawn(ctx, || Msg::Calibrated(crate::vaultfile::calibrate()));
    }

    fn persist_settings(&mut self) {
        if self.settings == self.saved_settings {
            return;
        }
        self.settings.sanitize();
        if !self.demo {
            if let Err(e) = self.settings.save(&self.data_dir) {
                self.toast(e, true);
            }
        }
        self.saved_settings = self.settings.clone();
    }

    fn apply_capture_protection(&mut self) {
        let want = self.settings.hide_from_capture
            && !self.shot
            && !(self.demo && std::env::var_os("KEEPFORGE_DEMO_ALLOW_CAPTURE").is_some());
        if self.capture_applied == Some(want) || self.hwnd == 0 {
            return;
        }
        let step = crate::harden::set_capture_protection(self.hwnd, want);
        self.steps.retain(|s| s.name != step.name);
        self.steps.push(step);
        self.capture_applied = Some(want);
    }
}

pub enum Screen {
    Welcome(WelcomeState),
    Create(Box<CreateState>),
    Unlock(Box<UnlockState>),
    Main(Box<Main>),
}

pub struct App {
    pub(super) sh: Shared,
    pub(super) screen: Screen,
    rx: Receiver<Msg>,
    sys_rx: Receiver<SysEvent>,
    pub(super) logo: Option<egui::TextureHandle>,
    shot: Option<Shot>,
    frames: u64,
    start_marker: Option<PathBuf>,
    was_minimized: bool,
    title_locked: Option<bool>,
    start_minimised: bool,
}

/// Starts the window.
pub fn run(options: Options, icon: egui::IconData) -> eframe::Result<()> {
    let viewport = egui::ViewportBuilder::default()
        .with_title(if options.demo {
            "KeepForge (demo)"
        } else {
            "KeepForge"
        })
        .with_inner_size([1280.0, 800.0])
        .with_min_inner_size([1040.0, 640.0])
        .with_drag_and_drop(true)
        .with_icon(icon.clone());
    let native = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "KeepForge",
        native,
        Box::new(move |cc| Ok(Box::new(App::new(cc, options, icon)))),
    )
}

fn window_handle(cc: &eframe::CreationContext<'_>) -> isize {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    match cc.window_handle().map(|h| h.as_raw()) {
        Ok(RawWindowHandle::Win32(h)) => h.hwnd.get(),
        _ => 0,
    }
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, options: Options, icon: egui::IconData) -> Self {
        let ctx = &cc.egui_ctx;
        theme::install(ctx);
        crate::util::set_local_offset(crate::sys::local_utc_offset());
        let shot = options.screenshot.is_some();
        let data_dir = if options.demo {
            // Nothing is read from or written to this folder in demo mode.
            PathBuf::from("C:\\Users\\Alex\\AppData\\Roaming\\KeepForge")
        } else {
            crate::settings::data_dir()
        };
        let mut settings = if options.demo {
            Settings::default()
        } else {
            Settings::load(&data_dir)
        };
        if options.light {
            settings.theme = crate::settings::ThemeChoice::Light;
        }
        theme::apply_choice(ctx, settings.theme);

        let logo = (icon.width > 0).then(|| {
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [icon.width as usize, icon.height as usize],
                &icon.rgba,
            );
            ctx.load_texture("logo", image, egui::TextureOptions::LINEAR)
        });
        let (tx, rx) = channel();
        let (sys_tx, sys_rx) = channel();
        let hwnd = window_handle(cc);
        // The background window: session lock / sleep notices, hotkey, tray.
        // Not started for screenshots, so nothing global is registered there.
        let sys = if shot || hwnd == 0 {
            None
        } else {
            let wake = ctx.clone();
            SysWindow::start(hwnd, sys_tx, Box::new(move || wake.request_repaint()))
        };
        if let Some(sys) = &sys {
            sys.set_tray(settings.tray_icon && !options.demo);
        }
        let mut sh = Shared {
            saved_settings: settings.clone(),
            settings,
            data_dir,
            demo: options.demo,
            shot,
            tx,
            toasts: Vec::new(),
            clip: None,
            clock: Instant::now(),
            hwnd,
            steps: options.steps.clone(),
            strict: options.strict,
            calibration: None,
            calibrating: false,
            about_open: false,
            now: crate::util::now(),
            sys,
            capture_applied: None,
            idle_lock_secs: options.idle_lock_secs,
        };
        sh.apply_capture_protection();
        if !options.strict {
            sh.toast(
                "KeepForge started in compatibility mode because the last start did not finish. Some process protections are off (see Settings).",
                true,
            );
        }

        let view = options.view.clone().unwrap_or_default();
        let screen = if options.demo {
            super::demo_views::initial_screen(&view, &mut sh)
        } else if let Some(path) = &options.vault {
            Screen::Unlock(Box::new(UnlockState::new(path.clone(), &sh.settings)))
        } else {
            match sh.settings.recent.first() {
                Some(recent) if std::path::Path::new(&recent.path).exists() => Screen::Unlock(
                    Box::new(UnlockState::new(PathBuf::from(&recent.path), &sh.settings)),
                ),
                _ => Screen::Welcome(WelcomeState::default()),
            }
        };
        if view == "about" {
            sh.about_open = true;
        }
        App {
            start_minimised: sh.settings.start_minimised && !options.demo && !shot,
            sh,
            screen,
            rx,
            sys_rx,
            logo,
            shot: options.screenshot.clone().map(|path| Shot {
                path,
                frames: 0,
                requested: false,
            }),
            frames: 0,
            start_marker: options.start_marker.clone(),
            was_minimized: false,
            title_locked: None,
        }
    }

    // ----------------------------------------------------------------------------------
    // Screen changes and locking
    // ----------------------------------------------------------------------------------

    /// Drops every piece of UI state that could hold vault data.
    fn wipe_ui(&mut self, ctx: &egui::Context) {
        self.sh.clear_clipboard();
        // Text-edit state (cursor, undo history), scroll positions, etc.
        ctx.memory_mut(|m| m.data.clear());
    }

    pub(super) fn go(&mut self, ctx: &egui::Context, go: Go) {
        match go {
            Go::Welcome => self.screen = Screen::Welcome(WelcomeState::default()),
            Go::Create { then_import } => {
                self.sh.ensure_calibration(ctx);
                self.screen = Screen::Create(Box::new(CreateState::new(&self.sh, then_import)));
            }
            Go::Unlock(path) => {
                self.screen = Screen::Unlock(Box::new(UnlockState::new(path, &self.sh.settings)));
            }
            Go::Opened(opened) => {
                let Opened {
                    vault,
                    kdf_secs,
                    then_import,
                    fresh,
                } = *opened;
                if let Some(path) = &vault.path {
                    self.sh
                        .settings
                        .remember(path, &vault.vault.name, None, self.sh.now);
                }
                let mut main = Main::new(vault, kdf_secs);
                if fresh {
                    main.offer_emergency_sheet();
                }
                if then_import {
                    main.start_import(ctx, &mut self.sh);
                }
                self.screen = Screen::Main(Box::new(main));
                self.apply_hotkey();
            }
            Go::Lock | Go::LockAndClose => {
                let close = matches!(go, Go::LockAndClose);
                let (path, demo_name) = match &mut self.screen {
                    Screen::Main(m) => {
                        if m.saving_in_flight() {
                            // Let the save that is under way finish first;
                            // the content of the vault is hidden meanwhile.
                            m.lock_after_save(close);
                            return;
                        }
                        (m.v.path.clone(), m.v.vault.name.clone())
                    }
                    _ => return,
                };
                // Replacing the screen drops the unlocked vault, which wipes
                // the session key; then the leftovers in the toolkit go too.
                self.screen = match (close, path) {
                    (false, Some(path)) => {
                        Screen::Unlock(Box::new(UnlockState::new(path, &self.sh.settings)))
                    }
                    (false, None) => Screen::Unlock(Box::new(UnlockState::demo(&demo_name))),
                    (true, _) => Screen::Welcome(WelcomeState::default()),
                };
                self.wipe_ui(ctx);
                if let Some(sys) = &self.sh.sys {
                    sys.set_hotkey(None);
                }
            }
            Go::Quit => ctx.send_viewport_cmd(egui::ViewportCommand::Close),
        }
    }

    pub(super) fn apply_hotkey(&self) {
        let Some(sys) = &self.sh.sys else { return };
        let unlocked = matches!(self.screen, Screen::Main(_));
        let hotkey = (unlocked && self.sh.settings.autotype_enabled && !self.sh.demo)
            .then(|| crate::sys::parse_hotkey(&self.sh.settings.autotype_hotkey))
            .flatten();
        sys.set_hotkey(hotkey);
    }

    fn drain_messages(&mut self, ctx: &egui::Context) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Msg::Calibrated(c) => {
                    self.sh.calibration = Some(c);
                    self.sh.calibrating = false;
                }
                Msg::Toast(text, error) => self.sh.toast(text, error),
                Msg::Unlocked(result, secs, attempt) => {
                    if let Screen::Unlock(u) = &mut self.screen {
                        if let Some(go) = u.unlocked(result, secs, attempt, &mut self.sh) {
                            self.go(ctx, go);
                        }
                    }
                }
                Msg::Created(result, secs) => {
                    if let Screen::Create(c) = &mut self.screen {
                        if let Some(go) = c.created(result, secs, &mut self.sh) {
                            self.go(ctx, go);
                        }
                    }
                }
                other => {
                    let go = match &mut self.screen {
                        Screen::Main(m) => m.message(ctx, &mut self.sh, other),
                        _ => None,
                    };
                    if let Some(go) = go {
                        self.go(ctx, go);
                    }
                }
            }
        }
        while let Ok(event) = self.sys_rx.try_recv() {
            match event {
                SysEvent::SessionLocked | SysEvent::Suspending => {
                    if self.sh.settings.lock_on_session && matches!(self.screen, Screen::Main(_)) {
                        self.go(ctx, Go::Lock);
                    }
                }
                SysEvent::TrayLock => {
                    if matches!(self.screen, Screen::Main(_)) {
                        self.go(ctx, Go::Lock);
                    }
                }
                SysEvent::TrayExit => self.go(ctx, Go::Quit),
                SysEvent::TrayShow => {}
                SysEvent::Hotkey(target) => {
                    if let Screen::Main(m) = &mut self.screen {
                        m.hotkey_pressed(ctx, &mut self.sh, target);
                    }
                }
            }
        }
    }

    /// Idle, minimise and clipboard timers.
    fn timers(&mut self, ctx: &egui::Context) {
        self.sh.now = crate::util::now();
        // Clipboard auto-clear.
        if let Some(p) = self.sh.clip {
            match clipboard::decide(&p, self.sh.ms(), clipboard::sequence()) {
                Tick::Keep(_) => ctx.request_repaint_after(std::time::Duration::from_millis(250)),
                Tick::Clear => {
                    clipboard::clear();
                    self.sh.clip = None;
                }
                Tick::Forget => self.sh.clip = None,
            }
        }
        let minimized = ctx.input(|i| i.viewport().minimized).unwrap_or(false);
        let just_minimized = minimized && !self.was_minimized;
        self.was_minimized = minimized;
        if !matches!(self.screen, Screen::Main(_)) {
            return;
        }
        // Keep checking while unlocked, even when nothing else repaints.
        ctx.request_repaint_after(std::time::Duration::from_millis(1000));
        if self.shot.is_some() {
            return;
        }
        let limit = match self.sh.idle_lock_secs {
            Some(secs) => secs,
            None => u64::from(self.sh.settings.auto_lock_minutes) * 60,
        };
        if limit > 0 && crate::sys::idle_seconds() >= limit {
            self.sh
                .toast("Locked after a period without activity.", false);
            self.go(ctx, Go::Lock);
            return;
        }
        if just_minimized && self.sh.settings.lock_on_minimize {
            self.go(ctx, Go::Lock);
        }
    }

    fn handle_screenshot(&mut self, ctx: &egui::Context) {
        let Some(shot) = &mut self.shot else { return };
        ctx.request_repaint();
        shot.frames += 1;
        // KEEPFORGE_SHOT_SCALE renders as a scaled display would (2 = 200 %),
        // to check layouts in the small logical window that gives.
        let scale = std::env::var("KEEPFORGE_SHOT_SCALE")
            .ok()
            .and_then(|v| v.parse::<f32>().ok())
            .filter(|v| (0.5..=4.0).contains(v))
            .unwrap_or(1.0);
        if shot.frames == 1 {
            ctx.set_pixels_per_point(scale);
        }
        if shot.frames == 3 {
            // With one point per pixel this gives an exact 1280 x 800 image.
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(
                vec2(1280.0, 800.0) / scale,
            ));
        }
        let image = ctx.input(|i| {
            i.events.iter().find_map(|e| match e {
                egui::Event::Screenshot { image, .. } => Some(image.clone()),
                _ => None,
            })
        });
        if let Some(image) = image {
            let [w, h] = image.size;
            if let Some(parent) = shot.path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let result = image::save_buffer(
                &shot.path,
                image.as_raw(),
                w as u32,
                h as u32,
                image::ColorType::Rgba8,
            );
            if let Err(e) = result {
                eprintln!("screenshot failed: {e}");
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            self.shot = None;
            return;
        }
        let busy = match &self.screen {
            Screen::Main(m) => m.busy(),
            _ => false,
        };
        if !shot.requested && shot.frames > 40 && (!busy || shot.frames > 1500) {
            shot.requested = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
        }
    }

    /// Takes over what egui wanted to copy or open, so that copies go
    /// through our protected clipboard path and only web links are opened.
    fn handle_output(&mut self, ctx: &egui::Context) {
        let commands = ctx.output_mut(|o| std::mem::take(&mut o.commands));
        for command in commands {
            match command {
                egui::OutputCommand::CopyText(mut text) => {
                    if !text.is_empty() {
                        self.sh.copy_secret(&text, "Text");
                    }
                    zeroize::Zeroize::zeroize(&mut text);
                }
                egui::OutputCommand::OpenUrl(open) => {
                    if let Err(e) = crate::sys::open_url(&open.url) {
                        self.sh.toast(e, true);
                    }
                }
                egui::OutputCommand::CopyImage(_) => {}
            }
        }
    }

    // ----------------------------------------------------------------------------------
    // Dialogs and toasts
    // ----------------------------------------------------------------------------------

    fn about_dialog(&mut self, ctx: &egui::Context) {
        if !self.sh.about_open {
            return;
        }
        let p = pal_ctx(ctx);
        let mut close = false;
        let modal = egui::Modal::new(egui::Id::new("about"))
            .frame(
                Frame::new()
                    .fill(p.card)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .corner_radius(CornerRadius::same(16))
                    .inner_margin(Margin::same(28)),
            )
            .show(ctx, |ui| {
                ui.set_width(400.0);
                ui.vertical_centered(|ui| {
                    let (rect, _) = ui.allocate_exact_size(vec2(84.0, 84.0), egui::Sense::hover());
                    if let Some(logo) = &self.logo {
                        ui.painter().image(
                            logo.id(),
                            rect,
                            egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                            egui::Color32::WHITE,
                        );
                    }
                    ui.add_space(6.0);
                    ui.label(RichText::new("KeepForge").font(semibold(26.0)));
                    ui.label(
                        RichText::new(format!("Version {}", env!("CARGO_PKG_VERSION")))
                            .color(p.muted),
                    );
                    ui.add_space(10.0);
                    ui.label("An offline password manager. One encrypted file, no account, no cloud.");
                    ui.add_space(10.0);
                    ui.label(RichText::new("Developed by Zheer Khalid").font(semibold(15.0)));
                    ui.add_space(2.0);
                    ui.hyperlink_to(RichText::new("zheer.dev").color(p.accent), "https://zheer.dev");
                    ui.hyperlink_to(
                        RichText::new("github.com/zheerkhalid/keepforge").color(p.accent),
                        "https://github.com/zheerkhalid/keepforge",
                    );
                    ui.add_space(10.0);
                    ui.add(
                        egui::Label::new(
                            RichText::new(
                                "Free and open source under the MIT License. KeepForge has not been independently audited.",
                            )
                            .size(12.0)
                            .color(p.faint),
                        )
                        .wrap(),
                    );
                    ui.add_space(14.0);
                    if widgets::primary_button(ui, "Close", true).clicked() {
                        close = true;
                    }
                });
            });
        if close || modal.should_close() {
            self.sh.about_open = false;
        }
    }

    fn toasts_ui(&mut self, ctx: &egui::Context) {
        self.sh
            .toasts
            .retain(|t| t.born.elapsed().as_secs_f32() < if t.error { 8.0 } else { 3.0 });
        if self.sh.toasts.is_empty() {
            return;
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(250));
        let p = pal_ctx(ctx);
        egui::Area::new(egui::Id::new("toasts"))
            .anchor(Align2::RIGHT_BOTTOM, vec2(-18.0, -18.0))
            .order(egui::Order::Tooltip)
            .show(ctx, |ui| {
                ui.with_layout(Layout::bottom_up(Align::Max), |ui| {
                    for t in self.sh.toasts.iter().rev().take(4) {
                        let color = if t.error { p.danger } else { p.accent };
                        Frame::new()
                            .fill(p.card)
                            .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.7)))
                            .corner_radius(CornerRadius::same(10))
                            .inner_margin(Margin::symmetric(14, 10))
                            .show(ui, |ui| {
                                ui.set_max_width((ui.available_width() - 12.0).min(440.0));
                                ui.horizontal(|ui| {
                                    let icon = if t.error { Icon::ERROR } else { Icon::DONE };
                                    ui.label(RichText::new(icon.glyph()).color(color));
                                    ui.add(egui::Label::new(t.text.as_str()).wrap());
                                });
                            });
                    }
                });
            });
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.frames += 1;
        if self.frames < 25 {
            // Keep drawing until the start counts as a success (see below).
            ctx.request_repaint();
        }
        if self.frames == 20 {
            // The window is up and drawing: this start counts as a success.
            if let Some(marker) = self.start_marker.take() {
                let _ = std::fs::remove_file(marker);
            }
        }
        if self.start_minimised && self.frames == 2 {
            crate::sys::minimize(self.sh.hwnd);
            self.start_minimised = false;
        }
        self.drain_messages(ctx);
        self.timers(ctx);
        self.handle_screenshot(ctx);
        theme::apply_choice(ctx, self.sh.settings.theme);

        let logo = self.logo.clone();
        let go = match &mut self.screen {
            Screen::Welcome(s) => s.ui(ctx, &mut self.sh, logo.as_ref()),
            Screen::Create(s) => s.ui(ctx, &mut self.sh, logo.as_ref()),
            Screen::Unlock(s) => s.ui(ctx, &mut self.sh, logo.as_ref()),
            Screen::Main(s) => s.ui(ctx, &mut self.sh, logo.as_ref()),
        };
        if let Some(go) = go {
            self.go(ctx, go);
        }

        // The window title says whether a vault is open (never its name).
        let locked = !matches!(self.screen, Screen::Main(_));
        if self.title_locked != Some(locked) {
            self.title_locked = Some(locked);
            let title = match (self.sh.demo, locked) {
                (true, true) => "KeepForge (demo, locked)",
                (true, false) => "KeepForge (demo)",
                (false, true) => "KeepForge (locked)",
                (false, false) => "KeepForge",
            };
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title.to_string()));
        }
        self.about_dialog(ctx);
        self.toasts_ui(ctx);
        self.handle_output(ctx);

        // Settings changed this frame: save them and apply the ones with
        // an effect outside the window.
        if self.sh.settings != self.sh.saved_settings {
            let hotkey_changed = self.sh.settings.autotype_hotkey
                != self.sh.saved_settings.autotype_hotkey
                || self.sh.settings.autotype_enabled != self.sh.saved_settings.autotype_enabled;
            let tray_changed = self.sh.settings.tray_icon != self.sh.saved_settings.tray_icon;
            self.sh.persist_settings();
            self.sh.apply_capture_protection();
            if hotkey_changed {
                self.apply_hotkey();
            }
            if tray_changed {
                if let Some(sys) = &self.sh.sys {
                    sys.set_tray(self.sh.settings.tray_icon && !self.sh.demo);
                }
            }
        }
    }

    fn raw_input_hook(&mut self, _ctx: &egui::Context, raw_input: &mut egui::RawInput) {
        if self.shot.is_some() {
            // Screenshots must not depend on where the mouse happens to be.
            raw_input.events.retain(|e| {
                !matches!(
                    e,
                    egui::Event::PointerMoved(_)
                        | egui::Event::MouseMoved(_)
                        | egui::Event::PointerButton { .. }
                        | egui::Event::MouseWheel { .. }
                        | egui::Event::Paste(_)
                )
            });
            raw_input.events.push(egui::Event::PointerGone);
            return;
        }
        // The toolkit's own clipboard is not used; pasted text is read from
        // the Windows clipboard here.
        for event in &mut raw_input.events {
            if let egui::Event::Paste(text) = event {
                zeroize::Zeroize::zeroize(text);
                if let Some(real) = clipboard::get_text() {
                    text.push_str(&real);
                }
            }
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Let a save that is under way finish (at most a few seconds).
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        while matches!(&self.screen, Screen::Main(m) if m.saving_in_flight()) {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.rx.recv_timeout(left) {
                Ok(msg) => {
                    if let Screen::Main(m) = &mut self.screen {
                        m.save_finished_on_exit(msg);
                    }
                }
                Err(_) => break,
            }
        }
        // Clear our secret from the clipboard, then drop the vault.
        self.sh.clear_clipboard();
        self.screen = Screen::Welcome(WelcomeState::default());
        self.sh.sys = None;
        if let Some(marker) = self.start_marker.take() {
            let _ = std::fs::remove_file(marker);
        }
    }
}
