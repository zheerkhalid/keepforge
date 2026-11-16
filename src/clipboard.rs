//! The Windows clipboard, used carefully: secrets are marked so that
//! clipboard history and cloud sync leave them alone, and they are cleared
//! again after a delay, but only if the clipboard still holds our value.

use crate::secret::SecretString;
use windows::core::w;
use windows::Win32::Foundation::{GlobalFree, HANDLE, HGLOBAL, HWND};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardSequenceNumber,
    IsClipboardFormatAvailable, OpenClipboard, RegisterClipboardFormatW, SetClipboardData,
};
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use zeroize::Zeroizing;

const CF_UNICODETEXT: u32 = 13;

// --------------------------------------------------------------------------------------
// The pure part: when to clear
// --------------------------------------------------------------------------------------

/// A secret we put on the clipboard and intend to clear.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pending {
    /// The clipboard sequence number right after we set our value.
    pub sequence: u32,
    /// When we set it (milliseconds on any monotonic clock).
    pub set_at_ms: u64,
    /// Clear after this many seconds; 0 means never.
    pub timeout_secs: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Tick {
    /// Still ours and not yet due: seconds left (`None` when it never times out).
    Keep(Option<f32>),
    /// Still ours and due: clear it now.
    Clear,
    /// Something else replaced our value: leave the clipboard alone.
    Forget,
}

/// Decides what to do with a pending secret. The clipboard is cleared only
/// if its sequence number is still the one we saw after setting our value,
/// which means nobody has put anything else there since.
pub fn decide(p: &Pending, now_ms: u64, current_sequence: u32) -> Tick {
    if current_sequence != p.sequence {
        return Tick::Forget;
    }
    if p.timeout_secs == 0 {
        return Tick::Keep(None);
    }
    let elapsed = now_ms.saturating_sub(p.set_at_ms);
    let total = u64::from(p.timeout_secs) * 1000;
    if elapsed >= total {
        Tick::Clear
    } else {
        Tick::Keep(Some((total - elapsed) as f32 / 1000.0))
    }
}

/// On lock or exit: clear if the clipboard still holds our value.
pub fn should_clear_now(p: &Pending, current_sequence: u32) -> bool {
    current_sequence == p.sequence
}

// --------------------------------------------------------------------------------------
// Win32
// --------------------------------------------------------------------------------------

struct Open;

impl Open {
    fn new() -> Option<Open> {
        // Another program may hold the clipboard for a moment: retry briefly.
        for _ in 0..10 {
            // SAFETY: plain Win32 call; no owner window is needed.
            if unsafe { OpenClipboard(HWND::default()) }.is_ok() {
                return Some(Open);
            }
            std::thread::sleep(std::time::Duration::from_millis(15));
        }
        None
    }
}

impl Drop for Open {
    fn drop(&mut self) {
        // SAFETY: the clipboard was opened by this thread.
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

pub fn sequence() -> u32 {
    // SAFETY: no arguments, no state.
    unsafe { GetClipboardSequenceNumber() }
}

/// Copies `bytes` into a movable global block and hands it to the clipboard.
/// On failure the block is wiped and freed; on success the system owns it.
unsafe fn put(format: u32, bytes: &[u8]) -> bool {
    let Ok(h) = GlobalAlloc(GMEM_MOVEABLE, bytes.len().max(1)) else {
        return false;
    };
    let p = GlobalLock(h) as *mut u8;
    if p.is_null() {
        let _ = GlobalFree(h);
        return false;
    }
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), p, bytes.len());
    let _ = GlobalUnlock(h);
    if SetClipboardData(format, HANDLE(h.0)).is_err() {
        let p = GlobalLock(h) as *mut u8;
        if !p.is_null() {
            std::ptr::write_bytes(p, 0, bytes.len());
            let _ = GlobalUnlock(h);
        }
        let _ = GlobalFree(h);
        return false;
    }
    true
}

/// Puts text on the clipboard. With `secret`, the data is also marked with
/// the formats that keep it out of Windows clipboard history, cloud sync and
/// clipboard monitors. Returns the sequence number to watch.
pub fn set_text(text: &str, secret: bool) -> Result<u32, String> {
    let mut wide: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(text.len() + 1));
    wide.extend(text.encode_utf16());
    wide.push(0);
    // SAFETY: a u16 buffer viewed as bytes; alignment of u8 is 1.
    let bytes = unsafe { std::slice::from_raw_parts(wide.as_ptr() as *const u8, wide.len() * 2) };
    let _open = Open::new().ok_or("The clipboard is busy. Try again.")?;
    // SAFETY: the clipboard is open on this thread for the whole block.
    unsafe {
        EmptyClipboard().map_err(|_| "Could not use the clipboard.")?;
        if secret {
            let exclude =
                RegisterClipboardFormatW(w!("ExcludeClipboardContentFromMonitorProcessing"));
            let history = RegisterClipboardFormatW(w!("CanIncludeInClipboardHistory"));
            let cloud = RegisterClipboardFormatW(w!("CanUploadToCloudClipboard"));
            // Set the markers first, so no monitor sees the text without them.
            put(exclude, &0u32.to_le_bytes());
            put(history, &0u32.to_le_bytes());
            put(cloud, &0u32.to_le_bytes());
        }
        if !put(CF_UNICODETEXT, bytes) {
            return Err("Could not copy to the clipboard.".into());
        }
    }
    drop(_open);
    Ok(sequence())
}

/// The text on the clipboard, if any (used for pasting into KeepForge).
pub fn get_text() -> Option<SecretString> {
    // SAFETY: format id only.
    if unsafe { IsClipboardFormatAvailable(CF_UNICODETEXT) }.is_err() {
        return None;
    }
    let _open = Open::new()?;
    // SAFETY: the clipboard is open; the handle stays valid until it is closed.
    unsafe {
        let h = GetClipboardData(CF_UNICODETEXT).ok()?;
        let hg = HGLOBAL(h.0);
        let p = GlobalLock(hg) as *const u16;
        if p.is_null() {
            return None;
        }
        let max = GlobalSize(hg) / 2;
        let mut len = 0;
        while len < max && *p.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(p, len);
        let mut out = Zeroizing::new(String::with_capacity(len * 3));
        for c in char::decode_utf16(slice.iter().copied()) {
            out.push(c.unwrap_or('\u{FFFD}'));
        }
        let _ = GlobalUnlock(hg);
        Some(out)
    }
}

/// Whether the given registered format is on the clipboard right now.
pub fn has_format(name: &str) -> bool {
    let wide = windows::core::HSTRING::from(name);
    // SAFETY: valid NUL-terminated string; format id only.
    unsafe {
        let id = RegisterClipboardFormatW(&wide);
        IsClipboardFormatAvailable(id).is_ok()
    }
}

/// Empties the clipboard.
pub fn clear() {
    if let Some(_open) = Open::new() {
        // SAFETY: the clipboard is open on this thread.
        unsafe {
            let _ = EmptyClipboard();
        }
    }
}

/// Empties the clipboard if it still holds the value we set.
pub fn clear_if_ours(p: &Pending) -> bool {
    if should_clear_now(p, sequence()) {
        clear();
        true
    } else {
        false
    }
}

/// A manual, careful live check of the clipboard code (`--selftest-clipboard`).
/// It only runs when the clipboard is empty or holds plain text, which it
/// saves first and puts back afterwards.
pub fn live_check() -> Result<Vec<String>, String> {
    let mut log = Vec::new();
    let saved = get_text();
    // SAFETY: no arguments.
    let formats = unsafe { windows::Win32::System::DataExchange::CountClipboardFormats() };
    if saved.is_none() && formats != 0 {
        return Err(
            "The clipboard holds something other than text; skipped so it is not disturbed.".into(),
        );
    }
    let probe = "KeepForge clipboard self-test (not a real secret)";
    let seq = set_text(probe, true)?;
    let ok_text = get_text().map(|t| t.as_str() == probe).unwrap_or(false);
    log.push(format!("set and read back: {ok_text}"));
    let marks = [
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard",
    ];
    let mut all = ok_text;
    for m in marks {
        let present = has_format(m);
        all &= present;
        log.push(format!("format {m}: {present}"));
    }
    let pending = Pending {
        sequence: seq,
        set_at_ms: 0,
        timeout_secs: 1,
    };
    let cleared = clear_if_ours(&pending);
    let empty = get_text().is_none();
    log.push(format!(
        "cleared while still ours: {cleared}, now empty: {empty}"
    ));
    all &= cleared && empty;
    // A value set by "someone else" must not be cleared.
    let other = set_text("someone else's text", false)?;
    let untouched = !clear_if_ours(&pending) && other != seq && get_text().is_some();
    log.push(format!("left a newer value alone: {untouched}"));
    all &= untouched;
    match &saved {
        Some(text) => {
            set_text(text, false)?;
            log.push("previous clipboard text restored".into());
        }
        None => {
            clear();
            log.push("clipboard left empty, as it was".into());
        }
    }
    if all {
        Ok(log)
    } else {
        Err(log.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_clear_logic() {
        let p = Pending {
            sequence: 41,
            set_at_ms: 10_000,
            timeout_secs: 20,
        };
        assert_eq!(decide(&p, 10_000, 41), Tick::Keep(Some(20.0)));
        assert_eq!(decide(&p, 25_000, 41), Tick::Keep(Some(5.0)));
        assert_eq!(decide(&p, 29_999, 41), Tick::Keep(Some(0.001)));
        assert_eq!(decide(&p, 30_000, 41), Tick::Clear);
        assert_eq!(decide(&p, 99_000, 41), Tick::Clear);
        // The user copied something else in the meantime: never clear it.
        assert_eq!(decide(&p, 15_000, 42), Tick::Forget);
        assert_eq!(decide(&p, 99_000, 42), Tick::Forget);
        // A clock that went backwards does not clear early.
        assert_eq!(decide(&p, 5_000, 41), Tick::Keep(Some(20.0)));
        let never = Pending {
            timeout_secs: 0,
            ..p
        };
        assert_eq!(decide(&never, 99_999_999, 41), Tick::Keep(None));
        assert_eq!(decide(&never, 0, 7), Tick::Forget);
        assert!(should_clear_now(&p, 41));
        assert!(!should_clear_now(&p, 40));
    }
}
