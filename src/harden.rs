//! Process hardening on Windows. Every step is best effort: it is tried,
//! its result is recorded, and a failure never stops the program.
//!
//! None of this protects against malware that already runs as the same user
//! with the vault unlocked; it raises the bar for casual snooping (see
//! `docs/SECURITY.md`).

use std::ffi::c_void;
use windows::core::{w, HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL, HWND};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows::Win32::Security::{
    GetTokenInformation, SetKernelObjectSecurity, TokenUser, DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Diagnostics::Debug::{
    SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, SEM_NOOPENFILEERRORBOX,
};
use windows::Win32::System::ErrorReporting::{
    WerAddExcludedApplication, WerSetFlags, WER_FAULT_REPORTING_FLAG_NOHEAP,
};
use windows::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, SetDllDirectoryW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, ProcessDynamicCodePolicy,
    ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy, SetProcessMitigationPolicy,
    PROCESS_MITIGATION_POLICY,
};
use windows::Win32::UI::WindowsAndMessaging::{
    SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE, WDA_MONITOR, WDA_NONE,
};

/// One hardening step and how it went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step {
    pub name: &'static str,
    pub ok: bool,
    pub detail: String,
}

fn step(name: &'static str, result: Result<(), String>) -> Step {
    match result {
        Ok(()) => Step {
            name,
            ok: true,
            detail: "on".into(),
        },
        Err(detail) => Step {
            name,
            ok: false,
            detail,
        },
    }
}

fn skipped(name: &'static str, why: &str) -> Step {
    Step {
        name,
        ok: false,
        detail: why.to_string(),
    }
}

fn win(r: windows::core::Result<()>) -> Result<(), String> {
    r.map_err(|e| e.message())
}

/// The very first thing `main` does, before any other library is loaded:
/// only load DLLs by name from System32, never from the current folder or
/// the PATH; and never show crash dialogs.
///
/// `strict == false` (compatibility mode, used automatically after a start
/// that failed to bring up the window) leaves the DLL search order alone.
pub fn early(strict: bool) -> Vec<Step> {
    let mut steps = Vec::new();
    // SAFETY: plain Win32 calls with constant arguments.
    unsafe {
        if strict {
            steps.push(step(
                "Load libraries from System32 only",
                win(SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)),
            ));
        } else {
            steps.push(skipped(
                "Load libraries from System32 only",
                "off (compatibility mode)",
            ));
        }
        steps.push(step(
            "Remove the current folder from the library search path",
            win(SetDllDirectoryW(w!(""))),
        ));
        SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
        steps.push(step(
            "No crash dialogs or error reports for this process",
            Ok(()),
        ));
    }
    steps
}

unsafe fn mitigation(policy: PROCESS_MITIGATION_POLICY, flags: u32) -> Result<(), String> {
    // Each of these policies is a single DWORD of flags.
    win(SetProcessMitigationPolicy(
        policy,
        &flags as *const u32 as *const c_void,
        std::mem::size_of::<u32>(),
    ))
}

/// Limits what other programs of the same user can do with this process:
/// they may see that it exists, wait for it and end it, but not read or
/// write its memory. Administrators and the system keep full access.
fn restrict_process_access() -> Result<(), String> {
    // SAFETY: handles and buffers are checked; allocations are freed.
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).map_err(|e| e.message())?;
        let mut needed = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut needed);
        let mut buf = vec![0u8; needed as usize];
        let got = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            needed,
            &mut needed,
        );
        let _ = CloseHandle(token);
        got.map_err(|e| e.message())?;
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut sid_text = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut sid_text).map_err(|e| e.message())?;
        let sid = sid_text.to_string().unwrap_or_default();
        let _ = LocalFree(HLOCAL(sid_text.0 as *mut c_void));
        if sid.is_empty() {
            return Err("could not read the user's SID".into());
        }
        // SY = system, BA = administrators: everything.
        // The user: PROCESS_TERMINATE (0x1) | PROCESS_QUERY_LIMITED_INFORMATION
        // (0x1000) | SYNCHRONIZE (0x100000) only.
        let sddl = HSTRING::from(format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x101001;;;{sid})"));
        let mut sd = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(&sddl, 1, &mut sd, None)
            .map_err(|e| e.message())?;
        let result = SetKernelObjectSecurity(GetCurrentProcess(), DACL_SECURITY_INFORMATION, sd);
        let _ = LocalFree(HLOCAL(sd.0));
        result.map_err(|e| e.message())
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    /// Forbid creating executable memory at run time. Some graphics drivers
    /// need that, so it is a setting, off unless the user turns it on.
    pub block_dynamic_code: bool,
    /// Register the EXE as excluded from Windows Error Reporting (per user).
    pub exclude_from_error_reporting: bool,
    pub strict: bool,
}

/// Hardening that can wait until `main` has read its settings.
pub fn apply(options: Options) -> Vec<Step> {
    let mut steps = Vec::new();
    // SAFETY: plain Win32 calls with constant or checked arguments.
    unsafe {
        // Legacy extension points: AppInit DLLs, Winsock LSPs, global hook DLLs, legacy IMEs.
        steps.push(step(
            "Block legacy extension points (injected DLLs)",
            mitigation(ProcessExtensionPointDisablePolicy, 0x1),
        ));
        // NoRemoteImages (1) | NoLowMandatoryLabelImages (2) | PreferSystem32Images (4).
        steps.push(step(
            "Prefer System32 libraries; no libraries from network shares",
            mitigation(ProcessImageLoadPolicy, 0x1 | 0x2 | 0x4),
        ));
        if options.block_dynamic_code && options.strict {
            steps.push(step(
                "Block dynamically generated code",
                mitigation(ProcessDynamicCodePolicy, 0x1),
            ));
        } else {
            steps.push(skipped(
                "Block dynamically generated code",
                if options.block_dynamic_code {
                    "off (compatibility mode)"
                } else {
                    "off (optional, see Settings)"
                },
            ));
        }
        steps.push(step(
            "Other programs of this user cannot read this process's memory",
            restrict_process_access(),
        ));
        let _ = WerSetFlags(WER_FAULT_REPORTING_FLAG_NOHEAP);
        if options.exclude_from_error_reporting {
            let exe = std::env::current_exe()
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_string()))
                .unwrap_or_else(|| "KeepForge.exe".into());
            let exe = HSTRING::from(exe);
            steps.push(step(
                "Excluded from Windows Error Reporting (no crash dumps uploaded)",
                win(WerAddExcludedApplication(PCWSTR(exe.as_ptr()), false)),
            ));
        } else {
            steps.push(skipped(
                "Excluded from Windows Error Reporting (no crash dumps uploaded)",
                "not registered in this mode",
            ));
        }
    }
    steps
}

/// Asks Windows to leave the window out of screenshots, screen recordings
/// and screen sharing (or to show it again).
pub fn set_capture_protection(hwnd: isize, on: bool) -> Step {
    let h = HWND(hwnd as *mut c_void);
    // SAFETY: a window handle of this process.
    let result = unsafe {
        if on {
            // Windows 10 2004+: excluded entirely. Older: shown as a black box.
            SetWindowDisplayAffinity(h, WDA_EXCLUDEFROMCAPTURE)
                .or_else(|_| SetWindowDisplayAffinity(h, WDA_MONITOR))
        } else {
            SetWindowDisplayAffinity(h, WDA_NONE)
        }
    };
    let mut s = step("Hide the window from screen capture", win(result));
    if !on && s.ok {
        s.detail = "off".into();
        s.ok = false;
    }
    s
}

/// Formats steps for the log file.
pub fn log_lines(steps: &[Step]) -> Vec<String> {
    steps
        .iter()
        .map(|s| {
            format!(
                "[{}] {}: {}",
                if s.ok { "ok" } else { "--" },
                s.name,
                s.detail
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_format() {
        let steps = vec![
            step("A", Ok(())),
            step("B", Err("access denied".into())),
            skipped("C", "off"),
        ];
        assert_eq!(
            log_lines(&steps),
            vec!["[ok] A: on", "[--] B: access denied", "[--] C: off"]
        );
    }
}
