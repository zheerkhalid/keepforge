//! A minimal HTTPS GET client on top of WinHTTP (the TLS stack that ships
//! with Windows). KeepForge makes no network request unless the user starts
//! one of the optional online checks; every call goes through here.
//!
//! TLS only, certificate validation left at the system defaults (never
//! weakened), no redirects, no cookies, fixed timeouts, capped response size.

use std::ffi::c_void;
use std::time::{Duration, Instant};
use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Networking::WinHttp::*;

pub const USER_AGENT: &str = "KeepForge";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u32,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetError {
    /// Could not connect, TLS failed, or the request timed out.
    Unreachable(String),
    /// The response was larger than the caller allows.
    TooLarge,
}

impl std::fmt::Display for NetError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetError::Unreachable(e) => write!(
                f,
                "Could not reach the service. Check your internet connection. ({e})"
            ),
            NetError::TooLarge => f.write_str("The service sent an unexpectedly large answer."),
        }
    }
}

struct Handle(*mut c_void);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the handle came from WinHTTP and is closed once.
            unsafe {
                let _ = WinHttpCloseHandle(self.0);
            }
        }
    }
}

fn last_error(what: &str) -> NetError {
    NetError::Unreachable(format!(
        "{what}: {}",
        windows::core::Error::from_win32().message()
    ))
}

/// `GET https://{host}{path}` with extra request headers (`"Name: value"`).
pub fn https_get(
    host: &str,
    path: &str,
    headers: &[&str],
    max_body: usize,
) -> Result<Response, NetError> {
    let host = HSTRING::from(host);
    let path = HSTRING::from(path);
    let agent = HSTRING::from(USER_AGENT);
    // SAFETY: every pointer passed below outlives the call it is passed to,
    // and every handle is closed by its guard.
    unsafe {
        let session = Handle(WinHttpOpen(
            &agent,
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(),
            PCWSTR::null(),
            0,
        ));
        if session.0.is_null() {
            return Err(last_error("open"));
        }
        // 10 s to resolve and connect, 15 s to send and to receive.
        let _ = WinHttpSetTimeouts(session.0, 10_000, 10_000, 15_000, 15_000);
        let protocols = (WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
            .to_le_bytes();
        if WinHttpSetOption(
            Some(session.0),
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            Some(&protocols),
        )
        .is_err()
        {
            // Older Windows without TLS 1.3: ask for TLS 1.2 only.
            let tls12 = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2.to_le_bytes();
            let _ = WinHttpSetOption(
                Some(session.0),
                WINHTTP_OPTION_SECURE_PROTOCOLS,
                Some(&tls12),
            );
        }
        let connect = Handle(WinHttpConnect(session.0, &host, 443, 0));
        if connect.0.is_null() {
            return Err(last_error("connect"));
        }
        let request = Handle(WinHttpOpenRequest(
            connect.0,
            w!("GET"),
            &path,
            PCWSTR::null(),
            PCWSTR::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        ));
        if request.0.is_null() {
            return Err(last_error("request"));
        }
        let never = WINHTTP_OPTION_REDIRECT_POLICY_NEVER.to_le_bytes();
        let _ = WinHttpSetOption(
            Some(request.0),
            WINHTTP_OPTION_REDIRECT_POLICY,
            Some(&never),
        );
        let no_cookies = WINHTTP_DISABLE_COOKIES.to_le_bytes();
        let _ = WinHttpSetOption(
            Some(request.0),
            WINHTTP_OPTION_DISABLE_FEATURE,
            Some(&no_cookies),
        );

        let header_text: Vec<u16> = headers.join("\r\n").encode_utf16().collect();
        let header_arg = (!header_text.is_empty()).then_some(&header_text[..]);
        WinHttpSendRequest(request.0, header_arg, None, 0, 0, 0)
            .map_err(|e| NetError::Unreachable(format!("send: {}", e.message())))?;
        WinHttpReceiveResponse(request.0, std::ptr::null_mut())
            .map_err(|e| NetError::Unreachable(format!("receive: {}", e.message())))?;

        let mut status: u32 = 0;
        let mut size = 4u32;
        WinHttpQueryHeaders(
            request.0,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            PCWSTR::null(),
            Some(&mut status as *mut u32 as *mut c_void),
            &mut size,
            std::ptr::null_mut(),
        )
        .map_err(|e| NetError::Unreachable(format!("status: {}", e.message())))?;

        let started = Instant::now();
        let mut body = Vec::new();
        let mut chunk = vec![0u8; 16 * 1024];
        loop {
            let mut read = 0u32;
            WinHttpReadData(
                request.0,
                chunk.as_mut_ptr() as *mut c_void,
                chunk.len() as u32,
                &mut read,
            )
            .map_err(|e| NetError::Unreachable(format!("read: {}", e.message())))?;
            if read == 0 {
                break;
            }
            if body.len() + read as usize > max_body {
                return Err(NetError::TooLarge);
            }
            body.extend_from_slice(&chunk[..read as usize]);
            if started.elapsed() > Duration::from_secs(45) {
                return Err(NetError::Unreachable("the download took too long".into()));
            }
        }
        Ok(Response { status, body })
    }
}

/// Spaces requests to one service at least `gap` apart.
#[derive(Clone, Copy, Debug)]
pub struct Throttle {
    gap: Duration,
    last: Option<Instant>,
}

impl Throttle {
    pub fn new(gap: Duration) -> Throttle {
        Throttle { gap, last: None }
    }

    /// How long to wait before the next request may start.
    pub fn wait_needed(&self, now: Instant) -> Duration {
        match self.last {
            Some(last) => self.gap.saturating_sub(now.saturating_duration_since(last)),
            None => Duration::ZERO,
        }
    }

    pub fn mark(&mut self, now: Instant) {
        self.last = Some(now);
    }

    /// Sleeps as needed, then records the start of a request.
    pub fn pace(&mut self) {
        let wait = self.wait_needed(Instant::now());
        if !wait.is_zero() {
            std::thread::sleep(wait);
        }
        self.mark(Instant::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_spacing() {
        let mut t = Throttle::new(Duration::from_millis(1500));
        let t0 = Instant::now();
        assert_eq!(t.wait_needed(t0), Duration::ZERO);
        t.mark(t0);
        assert_eq!(t.wait_needed(t0), Duration::from_millis(1500));
        assert_eq!(
            t.wait_needed(t0 + Duration::from_millis(400)),
            Duration::from_millis(1100)
        );
        assert_eq!(t.wait_needed(t0 + Duration::from_secs(5)), Duration::ZERO);
    }
}
