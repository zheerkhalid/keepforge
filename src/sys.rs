//! Small pieces of Windows: idle time, Caps Lock, time zone, opening links,
//! and a background message window for session lock / sleep notifications,
//! the auto-type hotkey and the tray icon.

use std::ffi::c_void;
use std::sync::mpsc::Sender;
use std::sync::Mutex;
use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, POINT, WPARAM};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetKeyState, GetLastInputInfo, RegisterHotKey, UnregisterHotKey, HOT_KEY_MODIFIERS,
    LASTINPUTINFO, MOD_ALT, MOD_CONTROL, MOD_NOREPEAT, MOD_SHIFT, MOD_WIN, VK_CAPITAL,
};
use windows::Win32::UI::Shell::{
    ShellExecuteW, Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE,
    NOTIFYICONDATAW,
};
use windows::Win32::UI::WindowsAndMessaging::*;

// --------------------------------------------------------------------------------------
// Simple queries
// --------------------------------------------------------------------------------------

/// Seconds since the last keyboard or mouse input anywhere in the session.
pub fn idle_seconds() -> u64 {
    let mut info = LASTINPUTINFO {
        cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: the structure is correctly sized and initialised.
    unsafe {
        if !GetLastInputInfo(&mut info).as_bool() {
            return 0;
        }
        u64::from(GetTickCount().wrapping_sub(info.dwTime)) / 1000
    }
}

pub fn caps_lock_on() -> bool {
    // SAFETY: plain key state query.
    unsafe { GetKeyState(i32::from(VK_CAPITAL.0)) & 1 != 0 }
}

/// The current offset of local time from UTC, in seconds.
pub fn local_utc_offset() -> i64 {
    let mut tz = TIME_ZONE_INFORMATION::default();
    // SAFETY: tz is a valid out pointer.
    let id = unsafe { GetTimeZoneInformation(&mut tz) };
    let bias = match id {
        2 => tz.Bias + tz.DaylightBias,
        1 => tz.Bias + tz.StandardBias,
        _ => tz.Bias,
    };
    -i64::from(bias) * 60
}

fn hwnd(raw: isize) -> HWND {
    HWND(raw as *mut c_void)
}

/// Opens a web address in the default browser. Only `http://` and
/// `https://` are ever opened; anything else is refused.
pub fn open_url(url: &str) -> Result<(), String> {
    let u = url.trim();
    let lower = u.to_lowercase();
    let full = if lower.starts_with("https://") || lower.starts_with("http://") {
        u.to_string()
    } else if !u.contains("://") && !u.contains(' ') && u.contains('.') && !u.starts_with('-') {
        format!("https://{u}")
    } else {
        return Err("Only web addresses (http or https) can be opened.".into());
    };
    if full.chars().any(|c| c.is_control() || c == '"') {
        return Err("This address contains characters that are not allowed.".into());
    }
    shell_open(&full)
}

/// Opens a folder in File Explorer.
pub fn open_folder(path: &std::path::Path) -> Result<(), String> {
    if !path.is_dir() {
        return Err("That folder does not exist.".into());
    }
    shell_open(&path.to_string_lossy())
}

fn shell_open(target: &str) -> Result<(), String> {
    let target = HSTRING::from(target);
    // SAFETY: valid strings; the return value is an error code when <= 32.
    let r = unsafe {
        ShellExecuteW(
            HWND::default(),
            w!("open"),
            &target,
            PCWSTR::null(),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };
    if r.0 as isize > 32 {
        Ok(())
    } else {
        Err("Windows could not open it.".into())
    }
}

pub fn minimize(raw: isize) {
    // SAFETY: a window handle of this process.
    unsafe {
        let _ = ShowWindow(hwnd(raw), SW_MINIMIZE);
    }
}

pub fn is_minimized(raw: isize) -> bool {
    // SAFETY: a window handle of this process.
    unsafe { IsIconic(hwnd(raw)).as_bool() }
}

/// Restores the window and brings it to the front.
pub fn show_and_focus(raw: isize) {
    // SAFETY: a window handle of this process.
    unsafe {
        if IsIconic(hwnd(raw)).as_bool() {
            let _ = ShowWindow(hwnd(raw), SW_RESTORE);
        }
        let _ = SetForegroundWindow(hwnd(raw));
    }
}

/// A named mutex that exists for as long as the returned handle is kept.
/// Setup programs use it to notice that KeepForge is running.
pub struct AppMutex(windows::Win32::Foundation::HANDLE);

impl Drop for AppMutex {
    fn drop(&mut self) {
        // SAFETY: the handle is owned by this value.
        unsafe {
            let _ = windows::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

pub fn app_mutex(name: &str) -> Option<AppMutex> {
    let name = HSTRING::from(name);
    // SAFETY: plain Win32 call with a valid name.
    unsafe { windows::Win32::System::Threading::CreateMutexW(None, false, &name) }
        .ok()
        .map(AppMutex)
}

/// A plain message box, for errors before the window exists.
pub fn message_box(title: &str, text: &str) {
    let (title, text) = (HSTRING::from(title), HSTRING::from(text));
    // SAFETY: valid strings.
    unsafe {
        MessageBoxW(HWND::default(), &text, &title, MB_OK | MB_ICONWARNING);
    }
}

// --------------------------------------------------------------------------------------
// Hotkey text
// --------------------------------------------------------------------------------------

/// A parsed hotkey: modifier flags and a virtual-key code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hotkey {
    pub modifiers: u32,
    pub vk: u32,
}

/// Parses text such as `Ctrl+Alt+A` or `Ctrl+Shift+F9`. At least one of
/// Ctrl / Alt / Win is required so a plain letter can never be captured.
pub fn parse_hotkey(text: &str) -> Option<Hotkey> {
    let mut modifiers = 0u32;
    let mut vk = None;
    for part in text.split('+') {
        let p = part.trim().to_uppercase();
        match p.as_str() {
            "CTRL" | "CONTROL" => modifiers |= MOD_CONTROL.0,
            "ALT" => modifiers |= MOD_ALT.0,
            "SHIFT" => modifiers |= MOD_SHIFT.0,
            "WIN" | "WINDOWS" => modifiers |= MOD_WIN.0,
            key => {
                if vk.is_some() {
                    return None;
                }
                let bytes = key.as_bytes();
                vk = Some(if bytes.len() == 1 && bytes[0].is_ascii_alphanumeric() {
                    u32::from(bytes[0])
                } else {
                    let n: u32 = key.strip_prefix('F')?.parse().ok()?;
                    if !(1..=24).contains(&n) {
                        return None;
                    }
                    0x70 + n - 1
                });
            }
        }
    }
    if modifiers & (MOD_CONTROL.0 | MOD_ALT.0 | MOD_WIN.0) == 0 {
        return None;
    }
    Some(Hotkey { modifiers, vk: vk? })
}

// --------------------------------------------------------------------------------------
// Background message window
// --------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysEvent {
    /// Windows was locked, the user switched, or the session disconnected.
    SessionLocked,
    /// The PC is going to sleep.
    Suspending,
    /// The auto-type hotkey was pressed; the window that had the focus.
    Hotkey(isize),
    TrayShow,
    TrayLock,
    TrayExit,
}

const WM_TRAY: u32 = WM_APP + 1;
const WM_SET_HOTKEY: u32 = WM_APP + 2;
const WM_SET_TRAY: u32 = WM_APP + 3;
const WM_QUIT_THREAD: u32 = WM_APP + 4;
const HOTKEY_ID: i32 = 1;
const MENU_SHOW: usize = 1;
const MENU_LOCK: usize = 2;
const MENU_EXIT: usize = 3;

struct State {
    tx: Sender<SysEvent>,
    wake: Box<dyn Fn() + Send>,
    main_window: isize,
    tray: bool,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn emit(event: SysEvent) {
    if let Ok(guard) = STATE.lock() {
        if let Some(s) = guard.as_ref() {
            let _ = s.tx.send(event);
            (s.wake)();
        }
    }
}

unsafe fn tray_data(window: HWND) -> NOTIFYICONDATAW {
    let mut data = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: 1,
        uFlags: NIF_ICON | NIF_MESSAGE | NIF_TIP,
        uCallbackMessage: WM_TRAY,
        ..Default::default()
    };
    let module = GetModuleHandleW(PCWSTR::null()).unwrap_or_default();
    // Icon resource 1 is the application icon embedded by the build script.
    data.hIcon = LoadIconW(HINSTANCE(module.0), PCWSTR(std::ptr::without_provenance(1)))
        .or_else(|_| LoadIconW(HINSTANCE::default(), IDI_APPLICATION))
        .unwrap_or_default();
    for (i, c) in "KeepForge".encode_utf16().enumerate() {
        data.szTip[i] = c;
    }
    data
}

unsafe fn set_tray(window: HWND, on: bool) {
    let was = STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.tray))
        .unwrap_or(false);
    if on == was {
        return;
    }
    let data = tray_data(window);
    let _ = Shell_NotifyIconW(if on { NIM_ADD } else { NIM_DELETE }, &data);
    if let Ok(mut g) = STATE.lock() {
        if let Some(s) = g.as_mut() {
            s.tray = on;
        }
    }
}

unsafe fn tray_menu(window: HWND) {
    let Ok(menu) = CreatePopupMenu() else { return };
    let _ = AppendMenuW(menu, MF_STRING, MENU_SHOW, w!("Show KeepForge"));
    let _ = AppendMenuW(menu, MF_STRING, MENU_LOCK, w!("Lock"));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, MENU_EXIT, w!("Exit"));
    let mut pt = POINT::default();
    let _ = GetCursorPos(&mut pt);
    // Needed so the menu closes when the user clicks elsewhere.
    let _ = SetForegroundWindow(window);
    let choice = TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_NONOTIFY | TPM_RIGHTBUTTON,
        pt.x,
        pt.y,
        0,
        window,
        None,
    );
    let _ = DestroyMenu(menu);
    match choice.0 as usize {
        MENU_SHOW => show_main(),
        MENU_LOCK => emit(SysEvent::TrayLock),
        MENU_EXIT => {
            // The window must be awake to process the exit.
            emit(SysEvent::TrayExit);
        }
        _ => {}
    }
}

fn show_main() {
    let main = STATE
        .lock()
        .ok()
        .and_then(|g| g.as_ref().map(|s| s.main_window))
        .unwrap_or(0);
    if main != 0 {
        show_and_focus(main);
    }
    emit(SysEvent::TrayShow);
}

unsafe extern "system" fn wnd_proc(
    window: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_WTSSESSION_CHANGE => {
            // WTS_CONSOLE_DISCONNECT 2, WTS_REMOTE_DISCONNECT 4, WTS_SESSION_LOGOFF 6, WTS_SESSION_LOCK 7
            if matches!(wparam.0, 2 | 4 | 6 | 7) {
                emit(SysEvent::SessionLocked);
            }
            LRESULT(0)
        }
        WM_POWERBROADCAST => {
            // PBT_APMSUSPEND
            if wparam.0 == 4 {
                emit(SysEvent::Suspending);
            }
            LRESULT(1)
        }
        WM_HOTKEY => {
            let focus = GetForegroundWindow();
            emit(SysEvent::Hotkey(focus.0 as isize));
            LRESULT(0)
        }
        WM_TRAY => {
            match lparam.0 as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => show_main(),
                WM_RBUTTONUP | WM_CONTEXTMENU => tray_menu(window),
                _ => {}
            }
            LRESULT(0)
        }
        WM_SET_HOTKEY => {
            let _ = UnregisterHotKey(window, HOTKEY_ID);
            if lparam.0 != 0 {
                let _ = RegisterHotKey(
                    window,
                    HOTKEY_ID,
                    HOT_KEY_MODIFIERS(wparam.0 as u32) | MOD_NOREPEAT,
                    lparam.0 as u32,
                );
            }
            LRESULT(0)
        }
        WM_SET_TRAY => {
            set_tray(window, wparam.0 != 0);
            LRESULT(0)
        }
        WM_QUIT_THREAD => {
            let _ = UnregisterHotKey(window, HOTKEY_ID);
            set_tray(window, false);
            let _ = WTSUnRegisterSessionNotification(window);
            let _ = DestroyWindow(window);
            LRESULT(0)
        }
        WM_DESTROY => {
            PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(window, msg, wparam, lparam),
    }
}

/// Handle to the background message window.
pub struct SysWindow {
    window: isize,
}

impl SysWindow {
    /// Starts the background thread. `wake` is called after every event so
    /// the user interface runs and picks it up.
    pub fn start(
        main_window: isize,
        tx: Sender<SysEvent>,
        wake: Box<dyn Fn() + Send>,
    ) -> Option<SysWindow> {
        if let Ok(mut g) = STATE.lock() {
            *g = Some(State {
                tx,
                wake,
                main_window,
                tray: false,
            });
        }
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<isize>();
        std::thread::Builder::new()
            .name("keepforge-sys".into())
            .spawn(move || {
                // SAFETY: a standard window class, window and message loop,
                // all owned by this thread.
                unsafe {
                    let module = GetModuleHandleW(PCWSTR::null()).unwrap_or_default();
                    let class = WNDCLASSW {
                        lpfnWndProc: Some(wnd_proc),
                        hInstance: HINSTANCE(module.0),
                        lpszClassName: w!("KeepForgeSysWindow"),
                        ..Default::default()
                    };
                    RegisterClassW(&class);
                    // A hidden top-level window (not message-only: power and
                    // session broadcasts only reach top-level windows).
                    let window = CreateWindowExW(
                        WS_EX_TOOLWINDOW,
                        w!("KeepForgeSysWindow"),
                        w!("KeepForge"),
                        WS_POPUP,
                        0,
                        0,
                        0,
                        0,
                        HWND::default(),
                        HMENU::default(),
                        HINSTANCE(module.0),
                        None,
                    );
                    let Ok(window) = window else {
                        let _ = ready_tx.send(0);
                        return;
                    };
                    let _ = WTSRegisterSessionNotification(window, NOTIFY_FOR_THIS_SESSION);
                    let _ = ready_tx.send(window.0 as isize);
                    let mut msg = MSG::default();
                    while GetMessageW(&mut msg, HWND::default(), 0, 0).as_bool() {
                        let _ = TranslateMessage(&msg);
                        DispatchMessageW(&msg);
                    }
                }
            })
            .ok()?;
        let window = ready_rx.recv().ok().filter(|w| *w != 0)?;
        Some(SysWindow { window })
    }

    fn post(&self, msg: u32, wparam: usize, lparam: isize) {
        // SAFETY: posting to our own window; a stale handle just fails.
        unsafe {
            let _ = PostMessageW(hwnd(self.window), msg, WPARAM(wparam), LPARAM(lparam));
        }
    }

    /// Registers (or with `None`, removes) the global auto-type hotkey.
    pub fn set_hotkey(&self, hotkey: Option<Hotkey>) {
        match hotkey {
            Some(h) => self.post(WM_SET_HOTKEY, h.modifiers as usize, h.vk as isize),
            None => self.post(WM_SET_HOTKEY, 0, 0),
        }
    }

    pub fn set_tray(&self, on: bool) {
        self.post(WM_SET_TRAY, usize::from(on), 0);
    }
}

impl Drop for SysWindow {
    fn drop(&mut self) {
        self.post(WM_QUIT_THREAD, 0, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hotkey_text() {
        let h = parse_hotkey("Ctrl+Alt+A").unwrap();
        assert_eq!(h.modifiers, MOD_CONTROL.0 | MOD_ALT.0);
        assert_eq!(h.vk, 0x41);
        assert_eq!(parse_hotkey(" ctrl + shift + f9 ").unwrap().vk, 0x78);
        assert_eq!(parse_hotkey("Win+Alt+7").unwrap().vk, 0x37);
        for bad in [
            "A",
            "Shift+A",
            "Ctrl+",
            "Ctrl+Alt",
            "Ctrl+A+B",
            "Ctrl+F25",
            "Ctrl+Space",
            "",
        ] {
            assert!(parse_hotkey(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn urls_are_filtered() {
        for bad in [
            "file:///C:/Windows/System32/calc.exe",
            "javascript:alert(1)",
            "calc.exe /x",
            "ms-settings:",
            "-arg.example",
            "",
            "C:\\Windows\\notepad.exe a",
        ] {
            assert!(open_url(bad).is_err(), "{bad}");
        }
        assert!(local_utc_offset().abs() <= 16 * 3600);
        let _ = idle_seconds();
        let _ = caps_lock_on();
    }
}
