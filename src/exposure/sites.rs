//! "Where is this user name registered?": asks the public profile page of
//! each site in the WhatsMyName list whether an account with the user's own
//! user name exists there.
//!
//! The site list is a pinned copy of WhatsMyName's `wmn-data.json`
//! (https://github.com/WebBreacher/WhatsMyName), Copyright (C) 2015-2026
//! Micah Hoffman, licensed under CC BY-SA 4.0. It is bundled unchanged as
//! `res/wmn-data.json`; see NOTICE.
//!
//! Politeness: one request per site, a few at a time, an honest User-Agent,
//! no retries, nothing that needs a login, a CAPTCHA or a POST, and no site
//! that the list marks as bot-protected.

use super::Transport;
use crate::totp::percent_encode;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

pub const DATA: &str = include_str!("../../res/wmn-data.json");
pub const ATTRIBUTION: &str =
    "Site list: WhatsMyName by Micah Hoffman and contributors (CC BY-SA 4.0)";
pub const PROJECT: &str = "https://github.com/WebBreacher/WhatsMyName";
/// Requests in flight at once.
pub const WORKERS: usize = 6;
const MAX_BODY: usize = 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
pub struct Site {
    pub name: String,
    pub uri_check: String,
    #[serde(default)]
    pub uri_pretty: String,
    pub e_code: u32,
    pub e_string: String,
    pub m_code: u32,
    #[serde(default)]
    pub m_string: String,
    #[serde(default)]
    pub cat: String,
    #[serde(default)]
    pub valid: Option<bool>,
    #[serde(default)]
    pub post_body: Option<String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub strip_bad_char: String,
    #[serde(default)]
    pub protection: Vec<String>,
}

#[derive(Deserialize)]
struct WmnFile {
    sites: Vec<Site>,
}

pub fn parse(json: &str) -> Vec<Site> {
    serde_json::from_str::<WmnFile>(json)
        .map(|f| f.sites)
        .unwrap_or_default()
}

pub const ADULT: &str = "xx NSFW xx";

impl Site {
    /// Whether KeepForge asks this site at all.
    pub fn usable(&self, adult: bool) -> bool {
        self.valid != Some(false)
            && self.post_body.is_none()
            && self.protection.is_empty()
            && self.uri_check.starts_with("https://")
            && self.uri_check.contains("{account}")
            && !self.e_string.is_empty()
            && self.cat != "archived"
            && (adult || self.cat != ADULT)
            && self.request("probe").is_some()
    }

    fn account(&self, username: &str) -> String {
        let cleaned: String = username
            .chars()
            .filter(|c| !self.strip_bad_char.contains(*c))
            .collect();
        percent_encode(&cleaned)
    }

    /// (host, path and query) to ask for `username`.
    pub fn request(&self, username: &str) -> Option<(String, String)> {
        let url = self.uri_check.replace("{account}", &self.account(username));
        let rest = url.strip_prefix("https://")?;
        let (host, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let host_ok = !host.is_empty()
            && host.len() <= 253
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
        let path_ok = !path.chars().any(|c| c.is_whitespace() || c.is_control());
        (host_ok && path_ok).then(|| (host.to_string(), path.to_string()))
    }

    /// The page a person would open to see the profile.
    pub fn profile_url(&self, username: &str) -> String {
        let pattern = if self.uri_pretty.starts_with("https://") {
            &self.uri_pretty
        } else {
            &self.uri_check
        };
        pattern.replace("{account}", &self.account(username))
    }

    /// Extra request headers the list asks for, minus anything that would
    /// change who KeepForge says it is.
    pub fn header_lines(&self) -> Vec<String> {
        self.headers
            .iter()
            .filter(|(k, _)| {
                !k.eq_ignore_ascii_case("user-agent") && !k.eq_ignore_ascii_case("cookie")
            })
            .filter(|(k, v)| {
                let ok = |s: &str| s.len() <= 200 && !s.chars().any(|c| c.is_control());
                ok(k) && ok(v) && !k.contains(':')
            })
            .map(|(k, v)| format!("{k}: {v}"))
            .collect()
    }

    pub fn classify(&self, status: u32, body: &str) -> SiteState {
        if status == self.e_code && body.contains(&self.e_string) {
            SiteState::Found
        } else if status == self.m_code
            && (self.m_string.is_empty() || body.contains(&self.m_string))
        {
            SiteState::Missing
        } else {
            SiteState::Unknown
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SiteState {
    Found,
    Missing,
    /// No clear answer (blocked, changed page, timeout): not reported.
    Unknown,
}

/// A site where an account with that name seems to exist.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteHit {
    pub name: String,
    pub category: String,
    pub url: String,
}

/// The result of one scan, kept with the user name's record.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteScan {
    pub when: i64,
    pub asked: usize,
    pub unclear: usize,
    pub found: Vec<SiteHit>,
    /// False when it was cancelled part way.
    pub complete: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteEvent {
    Progress {
        done: usize,
        total: usize,
    },
    Hit(SiteHit),
    Done {
        asked: usize,
        unclear: usize,
        complete: bool,
    },
}

/// Asks every site about `username`, `WORKERS` at a time. Blocks until done.
pub fn scan(
    username: &str,
    sites: Vec<Site>,
    t: Arc<dyn Transport>,
    cancel: Arc<AtomicBool>,
    workers: usize,
    emit: Arc<dyn Fn(SiteEvent) + Send + Sync>,
) {
    let total = sites.len();
    let queue = Arc::new(Mutex::new(sites.into_iter().rev().collect::<Vec<Site>>()));
    let done = Arc::new(AtomicUsize::new(0));
    let unclear = Arc::new(AtomicUsize::new(0));
    let mut threads = Vec::new();
    for _ in 0..workers.max(1) {
        let (queue, done, unclear, t, cancel, emit) = (
            queue.clone(),
            done.clone(),
            unclear.clone(),
            t.clone(),
            cancel.clone(),
            emit.clone(),
        );
        let username = username.to_string();
        threads.push(std::thread::spawn(move || loop {
            if cancel.load(Ordering::Relaxed) {
                break;
            }
            let Some(site) = queue.lock().ok().and_then(|mut q| q.pop()) else {
                break;
            };
            let state = match site.request(&username) {
                Some((host, path)) => {
                    let lines = site.header_lines();
                    let headers: Vec<&str> = lines.iter().map(String::as_str).collect();
                    match t.get(&host, &path, &headers, MAX_BODY) {
                        Ok(r) => site.classify(r.status, &String::from_utf8_lossy(&r.body)),
                        Err(_) => SiteState::Unknown,
                    }
                }
                None => SiteState::Unknown,
            };
            match state {
                SiteState::Found => emit(SiteEvent::Hit(SiteHit {
                    name: util::clean_remote(&site.name, 60),
                    category: util::clean_remote(&site.cat, 30),
                    url: site.profile_url(&username),
                })),
                SiteState::Unknown => {
                    unclear.fetch_add(1, Ordering::Relaxed);
                }
                SiteState::Missing => {}
            }
            let n = done.fetch_add(1, Ordering::Relaxed) + 1;
            emit(SiteEvent::Progress { done: n, total });
        }));
    }
    for th in threads {
        let _ = th.join();
    }
    let asked = done.load(Ordering::Relaxed);
    emit(SiteEvent::Done {
        asked,
        unclear: unclear.load(Ordering::Relaxed),
        complete: asked == total,
    });
}

#[cfg(test)]
mod tests {
    use super::super::testing::Recorded;
    use super::*;

    #[test]
    fn bundled_list_loads() {
        let all = parse(DATA);
        assert!(all.len() > 500, "{}", all.len());
        let usable: Vec<&Site> = all.iter().filter(|s| s.usable(false)).collect();
        assert!(usable.len() > 400, "{}", usable.len());
        assert!(usable
            .iter()
            .all(|s| s.cat != ADULT && s.post_body.is_none()));
        assert!(all.iter().filter(|s| s.usable(true)).count() > usable.len());
        // Every usable site makes a well-formed request. (A name with "_"
        // cannot be a host name, so sites that put it there are skipped.)
        let blog = all
            .iter()
            .find(|s| s.uri_check.starts_with("https://{account}."))
            .unwrap();
        assert!(blog.request("alex_m").is_none());
        for s in &usable {
            let (host, path) = s.request("alexm").unwrap();
            assert!(host.contains('.'), "{}", s.name);
            assert!(path.starts_with('/'), "{}", s.name);
        }
    }

    fn site(json: &str) -> Site {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn requests_and_classification() {
        let s = site(
            r#"{"name":"Example","uri_check":"https://api.example.com/users/{account}?x=1","uri_pretty":"https://example.com/@{account}",
            "e_code":200,"e_string":"\"profile\"","m_code":404,"m_string":"not found","cat":"social",
            "headers":{"Accept":"application/json","User-Agent":"Pretend/1.0","X-Bad":"a\r\nb"},"strip_bad_char":"."}"#,
        );
        assert!(s.usable(false));
        assert_eq!(
            s.request("al.ex m").unwrap(),
            (
                "api.example.com".to_string(),
                "/users/alex%20m?x=1".to_string()
            )
        );
        assert_eq!(s.profile_url("alex"), "https://example.com/@alex");
        assert_eq!(s.header_lines(), vec!["Accept: application/json"]);
        assert_eq!(s.classify(200, r#"{"profile":{}}"#), SiteState::Found);
        assert_eq!(
            s.classify(200, "<html>Sign in</html>"),
            SiteState::Unknown,
            "status alone is not enough"
        );
        assert_eq!(s.classify(404, "user not found"), SiteState::Missing);
        assert_eq!(s.classify(403, "blocked"), SiteState::Unknown);
        for bad in [
            r#"{"name":"a","uri_check":"http://plain.example/{account}","e_code":200,"e_string":"x","m_code":404}"#,
            r#"{"name":"a","uri_check":"https://x.example/{account}","e_code":200,"e_string":"x","m_code":404,"post_body":"{}"}"#,
            r#"{"name":"a","uri_check":"https://x.example/{account}","e_code":200,"e_string":"x","m_code":404,"protection":["cloudflare"]}"#,
            r#"{"name":"a","uri_check":"https://x.example/{account}","e_code":200,"e_string":"x","m_code":404,"valid":false}"#,
            r#"{"name":"a","uri_check":"https://x.example:8443/{account}","e_code":200,"e_string":"x","m_code":404}"#,
            r#"{"name":"a","uri_check":"https://x.example/fixed","e_code":200,"e_string":"x","m_code":404}"#,
        ] {
            assert!(!site(bad).usable(true), "{bad}");
        }
        let adult = site(
            r#"{"name":"a","uri_check":"https://x.example/{account}","e_code":200,"e_string":"x","m_code":404,"cat":"xx NSFW xx"}"#,
        );
        assert!(!adult.usable(false) && adult.usable(true));
    }

    #[test]
    fn scan_reports_hits_and_unclear_sites() {
        let mk = |name: &str, host: &str| {
            site(&format!(
                r#"{{"name":"{name}","uri_check":"https://{host}/u/{{account}}","e_code":200,"e_string":"profile-of","m_code":404,"m_string":"","cat":"social"}}"#
            ))
        };
        let sites = vec![
            mk("One", "one.example"),
            mk("Two", "two.example"),
            mk("Three", "three.example"),
            mk("Four", "four.example"),
        ];
        let t = Recorded::new()
            .with("one.example", "/u/alex", 200, "<div>profile-of alex</div>")
            .with("two.example", "/u/alex", 404, "")
            .with("three.example", "/u/alex", 503, "busy");
        let t = Arc::new(t);
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        scan(
            "alex",
            sites,
            t.clone(),
            Arc::new(AtomicBool::new(false)),
            3,
            Arc::new(move |e| sink.lock().unwrap().push(e)),
        );
        let events = events.lock().unwrap().clone();
        let hits: Vec<&SiteHit> = events
            .iter()
            .filter_map(|e| match e {
                SiteEvent::Hit(h) => Some(h),
                _ => None,
            })
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "One");
        assert_eq!(hits[0].url, "https://one.example/u/alex");
        assert_eq!(
            events.last(),
            Some(&SiteEvent::Done {
                asked: 4,
                unclear: 2,
                complete: true
            })
        );
        assert_eq!(t.seen().len(), 4, "one request per site");
    }
}
