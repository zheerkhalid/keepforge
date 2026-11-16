//! Auto-type: typing a login into another window with `SendInput`.
//!
//! Safety rules: never type into KeepForge itself; never type into a window
//! that runs with higher rights than we have (Windows silently drops such
//! input, so we say so instead); stop the moment the target window is no
//! longer in front, so a password cannot land in the wrong place.

use crate::model::Item;
use crate::secret::SecretString;
use crate::util;
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    GetAsyncKeyState, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, VIRTUAL_KEY, VK_CONTROL, VK_LWIN, VK_MENU, VK_RETURN,
    VK_RWIN, VK_SHIFT, VK_TAB,
};
use windows::Win32::UI::WindowsAndMessaging::{
    GetForegroundWindow, GetWindowTextW, GetWindowThreadProcessId, IsWindow, SetForegroundWindow,
};

pub const DEFAULT_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";
pub const MAX_DELAY_MS: u32 = 5000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Token {
    Text(String),
    Username,
    Password,
    Totp,
    Tab,
    Enter,
    Delay(u32),
}

/// Parses a sequence such as `{USERNAME}{TAB}{PASSWORD}{DELAY 200}{ENTER}`.
/// Placeholders are case-insensitive; `{{` and `}}` type literal braces;
/// anything else is typed as written.
pub fn parse_sequence(sequence: &str) -> Result<Vec<Token>, String> {
    let mut out: Vec<Token> = Vec::new();
    let mut text = String::new();
    let mut chars = sequence.chars().peekable();
    let flush = |text: &mut String, out: &mut Vec<Token>| {
        if !text.is_empty() {
            out.push(Token::Text(std::mem::take(text)));
        }
    };
    while let Some(c) = chars.next() {
        match c {
            '{' if chars.peek() == Some(&'{') => {
                chars.next();
                text.push('{');
            }
            '}' if chars.peek() == Some(&'}') => {
                chars.next();
                text.push('}');
            }
            '{' => {
                let mut name = String::new();
                let mut closed = false;
                for n in chars.by_ref() {
                    if n == '}' {
                        closed = true;
                        break;
                    }
                    name.push(n);
                }
                if !closed {
                    return Err("A { is missing its closing }.".into());
                }
                flush(&mut text, &mut out);
                let upper = name.trim().to_uppercase();
                let token = match upper.as_str() {
                    "USERNAME" => Token::Username,
                    "PASSWORD" => Token::Password,
                    "TOTP" => Token::Totp,
                    "TAB" => Token::Tab,
                    "ENTER" => Token::Enter,
                    other => match other.strip_prefix("DELAY") {
                        Some(ms) => {
                            let ms: u32 = ms.trim().parse().map_err(|_| {
                                "{DELAY} needs a number of milliseconds, for example {DELAY 200}."
                                    .to_string()
                            })?;
                            if ms > MAX_DELAY_MS {
                                return Err(format!(
                                    "{{DELAY}} can be at most {MAX_DELAY_MS} milliseconds."
                                ));
                            }
                            Token::Delay(ms)
                        }
                        None => {
                            return Err(format!(
                                "Unknown placeholder {{{}}}. Use {{USERNAME}}, {{PASSWORD}}, {{TOTP}}, {{TAB}}, {{ENTER}} or {{DELAY 200}}.",
                                name.trim()
                            ))
                        }
                    },
                };
                out.push(token);
            }
            '}' => return Err("A } has no opening {.".into()),
            other => text.push(other),
        }
    }
    flush(&mut text, &mut out);
    if out.is_empty() {
        return Err("The sequence is empty.".into());
    }
    Ok(out)
}

/// How well a window title fits an item (0 = not at all). The item's title
/// or the name of one of its sites has to appear in the window title.
pub fn match_score(window_title: &str, item: &Item) -> u32 {
    let hay = window_title.to_lowercase();
    let mut best = 0u32;
    let title = item.title.trim().to_lowercase();
    if title.chars().count() >= 3 && hay.contains(&title) {
        best = best.max(10 + title.len() as u32);
    }
    for url in &item.urls {
        let host = util::host_of(url);
        if host.is_empty() {
            continue;
        }
        let base = util::base_domain(&host);
        if hay.contains(&host) {
            best = best.max(8 + host.len() as u32);
        } else if hay.contains(&base) {
            best = best.max(6 + base.len() as u32);
        } else if let Some(label) = base.split('.').next() {
            // "example" from example.com, as a whole word.
            if label.len() >= 4
                && hay
                    .split(|c: char| !c.is_alphanumeric())
                    .any(|word| word == label)
            {
                best = best.max(2 + label.len() as u32);
            }
        }
    }
    best
}

// --------------------------------------------------------------------------------------
// Windows
// --------------------------------------------------------------------------------------

/// One thing to send to the target window.
pub enum Step {
    Text(SecretString),
    Tab,
    Enter,
    Delay(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub hwnd: isize,
    pub title: String,
}

fn hwnd(raw: isize) -> HWND {
    HWND(raw as *mut _)
}

pub fn window_title(raw: isize) -> String {
    let mut buf = [0u16; 512];
    // SAFETY: the buffer is valid for its length.
    let n = unsafe { GetWindowTextW(hwnd(raw), &mut buf) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

/// The window that currently has the focus.
pub fn foreground() -> Option<Target> {
    // SAFETY: no arguments.
    let h = unsafe { GetForegroundWindow() };
    if h.0.is_null() {
        return None;
    }
    Some(Target {
        hwnd: h.0 as isize,
        title: window_title(h.0 as isize),
    })
}

fn window_pid(raw: isize) -> u32 {
    let mut pid = 0u32;
    // SAFETY: pid is a valid out pointer.
    unsafe { GetWindowThreadProcessId(hwnd(raw), Some(&mut pid)) };
    pid
}

fn token_elevated(process: HANDLE) -> Option<bool> {
    // SAFETY: handles are checked and closed; the buffer matches the struct.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(process, TOKEN_QUERY, &mut token).ok()?;
        let mut elevation = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok.then_some(elevation.TokenIsElevated != 0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reach {
    Ok,
    /// The window belongs to KeepForge.
    Own,
    /// The window runs with higher rights; Windows would drop our input.
    Elevated,
    /// The window no longer exists.
    Gone,
}

pub fn reachability(raw: isize) -> Reach {
    // SAFETY: plain queries on a window handle that may be stale.
    unsafe {
        if !IsWindow(hwnd(raw)).as_bool() {
            return Reach::Gone;
        }
        let pid = window_pid(raw);
        if pid == GetCurrentProcessId() {
            return Reach::Own;
        }
        let we_are_elevated = token_elevated(GetCurrentProcess()).unwrap_or(false);
        if we_are_elevated {
            return Reach::Ok;
        }
        match OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) {
            Ok(process) => {
                let elevated = token_elevated(process);
                let _ = CloseHandle(process);
                match elevated {
                    Some(false) => Reach::Ok,
                    // Elevated, or we could not even ask: treat as out of reach.
                    _ => Reach::Elevated,
                }
            }
            Err(_) => Reach::Elevated,
        }
    }
}

pub fn reach_message(reach: Reach) -> Option<&'static str> {
    match reach {
        Reach::Ok => None,
        Reach::Own => Some("Auto-type does not type into KeepForge itself. Click the window you want to fill first."),
        Reach::Elevated => Some(
            "That window runs with administrator rights, and Windows does not let KeepForge type into it. Copy and paste instead.",
        ),
        Reach::Gone => Some("The window to type into is no longer open."),
    }
}

fn key(vk: VIRTUAL_KEY, scan: u16, flags: KEYBD_EVENT_FLAGS) -> INPUT {
    INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: vk,
                wScan: scan,
                dwFlags: flags,
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn send(inputs: &mut [INPUT]) -> bool {
    // SAFETY: a valid slice of INPUT structures.
    let sent = unsafe { SendInput(inputs, std::mem::size_of::<INPUT>() as i32) };
    // The structures held the characters typed: wipe them.
    for i in inputs.iter_mut() {
        *i = key(VIRTUAL_KEY(0), 0, KEYBD_EVENT_FLAGS(0));
    }
    sent as usize == inputs.len()
}

fn press(vk: VIRTUAL_KEY) -> bool {
    send(&mut [
        key(vk, 0, KEYBD_EVENT_FLAGS(0)),
        key(vk, 0, KEYEVENTF_KEYUP),
    ])
}

fn modifiers_down() -> bool {
    [VK_CONTROL, VK_MENU, VK_SHIFT, VK_LWIN, VK_RWIN]
        .iter()
        // SAFETY: plain key state query.
        .any(|vk| unsafe { GetAsyncKeyState(vk.0 as i32) } < 0)
}

fn is_foreground(raw: isize) -> bool {
    // SAFETY: no arguments.
    unsafe { GetForegroundWindow().0 as isize == raw }
}

/// Types the steps into the target window. Blocking: run on a worker thread.
pub fn type_into(target: isize, steps: Vec<Step>) -> Result<(), String> {
    if let Some(msg) = reach_message(reachability(target)) {
        return Err(msg.into());
    }
    // Bring the target to the front if it is not there already.
    let deadline = Instant::now() + Duration::from_millis(1500);
    while !is_foreground(target) {
        // SAFETY: the handle was validated above; failure is handled by the loop.
        unsafe {
            let _ = SetForegroundWindow(hwnd(target));
        }
        if Instant::now() > deadline {
            return Err(
                "Could not bring the target window to the front. Click it and try again.".into(),
            );
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    // A hotkey's own modifier keys must be released first, or the typed
    // characters would arrive as shortcuts.
    let deadline = Instant::now() + Duration::from_secs(3);
    while modifiers_down() {
        if Instant::now() > deadline {
            return Err("Release Ctrl, Alt, Shift and the Windows key, then try again.".into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    std::thread::sleep(Duration::from_millis(60));
    let moved = "Stopped typing: another window came to the front.";
    for step in steps {
        if !is_foreground(target) {
            return Err(moved.into());
        }
        let ok = match step {
            Step::Tab => press(VK_TAB),
            Step::Enter => press(VK_RETURN),
            Step::Delay(ms) => {
                std::thread::sleep(Duration::from_millis(u64::from(ms.min(MAX_DELAY_MS))));
                true
            }
            Step::Text(text) => {
                let mut ok = true;
                for c in text.chars() {
                    if !is_foreground(target) {
                        return Err(moved.into());
                    }
                    ok &= match c {
                        '\n' => press(VK_RETURN),
                        '\r' => true,
                        '\t' => press(VK_TAB),
                        c => {
                            let mut units = [0u16; 2];
                            let mut all = true;
                            for u in c.encode_utf16(&mut units).iter().copied() {
                                all &= send(&mut [
                                    key(VIRTUAL_KEY(0), u, KEYEVENTF_UNICODE),
                                    key(VIRTUAL_KEY(0), u, KEYEVENTF_UNICODE | KEYEVENTF_KEYUP),
                                ]);
                            }
                            all
                        }
                    };
                    std::thread::sleep(Duration::from_millis(6));
                }
                ok
            }
        };
        if !ok {
            return Err("Windows blocked the typing. The target window may be protected.".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}

/// Turns a parsed sequence into steps for one item, decrypting its secrets
/// only now. `now` is the Unix time used for the TOTP code.
pub fn steps_for(item: &Item, tokens: &[Token], now: u64) -> Result<Vec<Step>, String> {
    let mut steps = Vec::with_capacity(tokens.len());
    for t in tokens {
        steps.push(match t {
            Token::Text(s) => Step::Text(crate::secret::secret_string(s)),
            Token::Username => Step::Text(crate::secret::secret_string(&item.username)),
            Token::Password => Step::Text(item.password.open_str()),
            Token::Totp => {
                let seed = item.totp.open_str();
                let totp = crate::totp::Totp::parse(&seed).map_err(|e| e.to_string())?;
                Step::Text(zeroize::Zeroizing::new(totp.code_at(now)))
            }
            Token::Tab => Step::Tab,
            Token::Enter => Step::Enter,
            Token::Delay(ms) => Step::Delay(*ms),
        });
    }
    Ok(steps)
}

/// The sequence an item uses: its own, or the default.
pub fn sequence_of(item: &Item) -> &str {
    if item.autotype.trim().is_empty() {
        DEFAULT_SEQUENCE
    } else {
        &item.autotype
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Kind;
    use crate::secret::{Protected, SessionKey};

    #[test]
    fn sequence_parser() {
        assert_eq!(
            parse_sequence(DEFAULT_SEQUENCE).unwrap(),
            vec![Token::Username, Token::Tab, Token::Password, Token::Enter]
        );
        assert_eq!(
            parse_sequence("{username}{ tab }{Password}{DELAY 200}{enter}").unwrap(),
            vec![
                Token::Username,
                Token::Tab,
                Token::Password,
                Token::Delay(200),
                Token::Enter
            ]
        );
        assert_eq!(
            parse_sequence("id: {USERNAME}{{x}} ü{TOTP}").unwrap(),
            vec![
                Token::Text("id: ".into()),
                Token::Username,
                Token::Text("{x} ü".into()),
                Token::Totp
            ]
        );
        assert_eq!(
            parse_sequence("{DELAY5000}").unwrap(),
            vec![Token::Delay(5000)]
        );
        for bad in [
            "",
            "{USERNAME",
            "PASSWORD}",
            "{NOPE}",
            "{DELAY}",
            "{DELAY x}",
            "{DELAY 5001}",
            "{}",
        ] {
            assert!(parse_sequence(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn window_matching() {
        let mut item = Item::new(Kind::Login, 0);
        item.title = "Example Mail".into();
        item.urls = vec!["https://mail.example.com/login".into()];
        assert!(match_score("Example Mail - Sign in — Web Browser", &item) > 0);
        assert!(match_score("Sign in · mail.example.com", &item) > 0);
        assert!(match_score("Welcome to Example | Browser", &item) > 0);
        assert_eq!(match_score("Untitled - Text Editor", &item), 0);
        assert_eq!(match_score("Counterexamples in topology", &item), 0);
        // A better match scores higher.
        assert!(
            match_score("Example Mail", &item) > match_score("Welcome to Example | Browser", &item)
        );
        let mut short = Item::new(Kind::Login, 0);
        short.title = "X".into();
        assert_eq!(match_score("X marks the spot", &short), 0);
    }

    #[test]
    fn steps_decrypt_only_when_built() {
        let s = SessionKey::new();
        let mut item = Item::new(Kind::Login, 0);
        item.username = "alex".into();
        item.password = Protected::seal_str(&s, "pw!");
        item.totp = Protected::seal_str(&s, "JBSWY3DPEHPK3PXP");
        let tokens = parse_sequence("{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}").unwrap();
        let steps = steps_for(&item, &tokens, 59).unwrap();
        assert_eq!(steps.len(), 6);
        match (&steps[0], &steps[2], &steps[4]) {
            (Step::Text(u), Step::Text(p), Step::Text(code)) => {
                assert_eq!(u.as_str(), "alex");
                assert_eq!(p.as_str(), "pw!");
                assert_eq!(code.len(), 6);
            }
            _ => panic!("unexpected steps"),
        }
        item.totp = Protected::default();
        assert!(steps_for(&item, &tokens, 59).is_err());
        assert_eq!(sequence_of(&item), DEFAULT_SEQUENCE);
        // Our own window and stale handles are refused.
        assert_eq!(reachability(0), Reach::Gone);
        assert!(reach_message(Reach::Own).is_some());
        assert!(reach_message(Reach::Elevated).is_some());
        assert!(reach_message(Reach::Ok).is_none());
    }
}
