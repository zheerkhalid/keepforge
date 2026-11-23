//! Password health: weak, reused and old passwords, housekeeping, expiry,
//! and an overall score. Runs on a worker thread over copies of the items
//! (whose secrets are still encrypted) and decrypts one password at a time.

use crate::model::{Id, Item, Kind};
use crate::strength;
use crate::util::DAY;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Debug, Default, PartialEq)]
pub struct Report {
    /// Items with a password that were looked at.
    pub checked: usize,
    /// (item, zxcvbn score 0–2)
    pub weak: Vec<(Id, u8)>,
    /// Groups of items that share one password.
    pub reused: Vec<Vec<Id>>,
    /// Items whose password is older than the limit.
    pub old: Vec<Id>,
    /// Logins without a password.
    pub empty: Vec<Id>,
    /// Logins without a web address.
    pub no_url: Vec<Id>,
    /// Logins whose password goes to a web address without encryption.
    pub insecure: Vec<Id>,
    /// (item, expiry) within the next 30 days.
    pub expiring: Vec<(Id, i64)>,
    /// (item, expiry) already past.
    pub expired: Vec<(Id, i64)>,
    /// The analysis was cancelled before it finished.
    pub cancelled: bool,
}

pub const EXPIRY_WINDOW_DAYS: i64 = 30;

/// Whether a web address sends what is typed into it without encryption:
/// a plain `http://` address on the internet. Devices at home (a router or
/// printer page, `localhost`, private addresses) are left alone, because
/// they often offer nothing else and never leave the local network.
pub fn is_insecure_url(url: &str) -> bool {
    let url = url.trim();
    let Some(scheme) = url.get(..7) else {
        return false;
    };
    if !scheme.eq_ignore_ascii_case("http://") {
        return false;
    }
    let rest = &url[7..];
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = authority.rsplit('@').next().unwrap_or("");
    if let Some(inner) = host.strip_prefix('[') {
        // An IPv6 literal: loopback, link-local and unique-local stay home.
        let inner = inner.split(']').next().unwrap_or("").to_ascii_lowercase();
        return !(inner == "::1"
            || inner.starts_with("fe80:")
            || inner.starts_with("fc")
            || inner.starts_with("fd"));
    }
    let host = host.split(':').next().unwrap_or("").to_ascii_lowercase();
    if host.is_empty() {
        return false;
    }
    let octets: Vec<u8> = host.split('.').filter_map(|p| p.parse().ok()).collect();
    if octets.len() == 4 && host.split('.').count() == 4 {
        return !matches!(
            (octets[0], octets[1]),
            (10, _) | (127, _) | (192, 168) | (169, 254) | (172, 16..=31)
        );
    }
    let local = host == "localhost"
        || !host.contains('.')
        || [
            ".local",
            ".lan",
            ".home",
            ".internal",
            ".localhost",
            ".home.arpa",
        ]
        .iter()
        .any(|s| host.ends_with(s));
    !local
}

/// Whether an item's password is one a person chose (and so can be weak).
fn has_chosen_password(item: &Item) -> bool {
    matches!(item.kind, Kind::Login | Kind::Wifi)
}

pub fn analyse(
    items: &[Item],
    old_months: u32,
    now: i64,
    cancel: &AtomicBool,
    mut progress: impl FnMut(usize, usize),
) -> Report {
    let mut report = Report::default();
    let live: Vec<&Item> = items.iter().filter(|i| !i.in_trash()).collect();
    // Passwords are grouped by a keyed hash, so no plaintext is kept around.
    let key = crate::secret::random_array::<32>();
    let mut groups: HashMap<[u8; 32], Vec<Id>> = HashMap::new();
    let old_limit = now - i64::from(old_months) * 30 * DAY;
    for (n, item) in live.iter().enumerate() {
        if cancel.load(Ordering::Relaxed) {
            report.cancelled = true;
            break;
        }
        progress(n, live.len());
        if let Some(when) = item.expiry() {
            if when <= now {
                report.expired.push((item.id, when));
            } else if when <= now + EXPIRY_WINDOW_DAYS * DAY {
                report.expiring.push((item.id, when));
            }
        }
        if item.kind == Kind::Login {
            if item.password.is_empty() {
                report.empty.push(item.id);
            }
            if item.urls.iter().all(|u| u.trim().is_empty()) {
                report.no_url.push(item.id);
            }
            if !item.password.is_empty() && item.urls.iter().any(|u| is_insecure_url(u)) {
                report.insecure.push(item.id);
            }
        }
        if !has_chosen_password(item) || item.password.is_empty() {
            continue;
        }
        report.checked += 1;
        let password = item.password.open_str();
        let s = strength::estimate(&password, &[&item.title, &item.username]);
        if s.score <= 2 {
            report.weak.push((item.id, s.score));
        }
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key).expect("any key length");
        mac.update(password.as_bytes());
        groups
            .entry(mac.finalize().into_bytes().into())
            .or_default()
            .push(item.id);
        if item.password_changed < old_limit {
            report.old.push(item.id);
        }
    }
    report.reused = groups.into_values().filter(|g| g.len() > 1).collect();
    report.reused.sort_by_key(|g| std::cmp::Reverse(g.len()));
    report.weak.sort_by_key(|(_, score)| *score);
    report.expiring.sort_by_key(|(_, when)| *when);
    report.expired.sort_by_key(|(_, when)| *when);
    report
}

impl Report {
    pub fn reused_count(&self) -> usize {
        self.reused.iter().map(Vec::len).sum()
    }

    /// 0–100. `breached` is the number of items whose password is in a known
    /// breach or whose site was breached after the password was last changed.
    pub fn score(&self, breached: usize) -> u32 {
        if self.checked == 0 {
            return 100;
        }
        let n = self.checked as f64;
        let share = |count: usize| (count as f64 / n).min(1.0);
        let penalty = 40.0 * share(self.weak.len())
            + 25.0 * share(self.reused_count())
            + 25.0 * share(breached)
            + 7.0 * share(self.old.len())
            + 3.0 * share(self.expired.len() + self.empty.len());
        (100.0 - penalty).round().clamp(0.0, 100.0) as u32
    }
}

pub fn score_label(score: u32) -> &'static str {
    match score {
        90..=100 => "Excellent",
        75..=89 => "Good",
        50..=74 => "Needs attention",
        _ => "At risk",
    }
}

/// Key-stretching strength in plain words, from how long one unlock took.
pub fn kdf_words(seconds: f64) -> String {
    let grade = if seconds >= 0.4 {
        "Strong"
    } else if seconds >= 0.1 {
        "Reasonable"
    } else {
        "Light"
    };
    format!("{grade}: about {seconds:.1} s per guess on this PC")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Vault;
    use crate::secret::{Protected, SessionKey};

    fn login(s: &std::sync::Arc<SessionKey>, title: &str, pw: &str, changed: i64) -> Item {
        let mut i = Item::new(Kind::Login, 0);
        i.title = title.into();
        i.urls = vec![format!("https://{title}.example")];
        i.password = Protected::seal_str(s, pw);
        i.password_changed = changed;
        i
    }

    #[test]
    fn finds_weak_reused_old_and_expiring() {
        let s = SessionKey::new();
        let now = 2_000_000_000;
        let year = 365 * DAY;
        let mut v = Vault::new("h", 0);
        v.items.push(login(&s, "a", "password1", now));
        v.items.push(login(&s, "b", "vK7#qPz!m2Lx9@Tn", now));
        v.items
            .push(login(&s, "c", "vK7#qPz!m2Lx9@Tn", now - 3 * year));
        v.items.push(login(&s, "d", "wT4$hNc^8RbY1&Ue", now));
        let mut blank = login(&s, "e", "", now);
        blank.urls.clear();
        v.items.push(blank);
        let mut trashed = login(&s, "f", "password1", now);
        trashed.deleted = Some(1);
        v.items.push(trashed);
        let mut card = Item::new(Kind::Card, 0);
        card.expires = Some(now + 10 * DAY);
        v.items.push(card);
        let mut lapsed = Item::new(Kind::Licence, 0);
        lapsed.password = Protected::seal_str(&s, "AAAA-BBBB");
        lapsed.expires = Some(now - DAY);
        v.items.push(lapsed);
        let ids: Vec<Id> = v.items.iter().map(|i| i.id).collect();

        let mut ticks = 0;
        let r = analyse(&v.items, 12, now, &AtomicBool::new(false), |_, _| {
            ticks += 1
        });
        assert_eq!(ticks, 7);
        assert_eq!(r.checked, 4);
        assert_eq!(r.weak.len(), 1);
        assert_eq!(r.weak[0].0, ids[0]);
        assert_eq!(r.reused.len(), 1);
        let mut group = r.reused[0].clone();
        group.sort();
        let mut expect = vec![ids[1], ids[2]];
        expect.sort();
        assert_eq!(group, expect);
        assert_eq!(r.old, vec![ids[2]]);
        assert_eq!(r.empty, vec![ids[4]]);
        assert_eq!(r.no_url, vec![ids[4]]);
        assert!(r.insecure.is_empty());
        assert_eq!(r.expiring, vec![(ids[6], now + 10 * DAY)]);
        assert_eq!(r.expired, vec![(ids[7], now - DAY)]);
        assert!(!r.cancelled);

        let score = r.score(0);
        assert!(score < 100 && score > 40, "{score}");
        assert!(r.score(2) < score);
        assert_eq!(Report::default().score(0), 100);
        let cancelled = analyse(&v.items, 12, now, &AtomicBool::new(true), |_, _| {});
        assert!(cancelled.cancelled);
        assert_eq!(cancelled.checked, 0);
        assert_eq!(score_label(95), "Excellent");
        assert_eq!(score_label(10), "At risk");
        assert!(kdf_words(1.23).starts_with("Strong: about 1.2 s"));
        assert!(kdf_words(0.05).starts_with("Light"));
    }

    #[test]
    fn plain_http_addresses_are_listed_but_home_devices_are_not() {
        for url in [
            "http://forum.example/login",
            "HTTP://Shop.Example",
            "http://user@forum.example:8080/a?b#c",
            "http://93.184.216.34/admin",
            "http://172.32.0.1",
            "http://[2001:db8::1]:8080/",
            "  http://forum.example ",
        ] {
            assert!(is_insecure_url(url), "{url}");
        }
        for url in [
            "https://forum.example",
            "forum.example",
            "",
            "http://",
            "http",
            "ftp://files.example",
            "http://localhost:3000",
            "http://192.168.1.1/",
            "http://10.0.0.138",
            "http://172.16.4.2",
            "http://127.0.0.1:8384",
            "http://169.254.10.10",
            "http://router",
            "http://printer.local/status",
            "http://nas.lan",
            "http://[::1]:8080",
            "http://[fe80::1]",
            "http://[fd12:3456::1]/",
            "بانک",
        ] {
            assert!(!is_insecure_url(url), "{url}");
        }
        let s = SessionKey::new();
        let mut v = Vault::new("h", 0);
        let mut a = login(&s, "a", "vK7#qPz!m2Lx9@Tn", 5);
        a.urls = vec!["https://a.example".into(), "http://a.example/old".into()];
        v.items.push(a);
        let mut b = login(&s, "b", "", 5);
        b.urls = vec!["http://b.example".into()];
        v.items.push(b);
        let mut c = login(&s, "c", "wT4$hNc^8RbY1&Ue", 5);
        c.urls = vec!["http://192.168.0.1".into()];
        v.items.push(c);
        let r = analyse(&v.items, 12, 10, &AtomicBool::new(false), |_, _| {});
        assert_eq!(
            r.insecure,
            vec![v.items[0].id],
            "only a saved password counts"
        );
    }
}
