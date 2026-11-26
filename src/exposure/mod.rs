//! The Exposure check: is an email address, user name, phone number or
//! domain of the user's own in known data breaches, pastes or infostealer
//! logs, and which of their saved logins does that concern?
//!
//! Every online source is opt-in (Settings › Online checks) and only ever
//! asked when the user presses Check. Sources live behind [`Transport`] so
//! that tests run on recorded answers and never touch the network.
//!
//! Everything a source sends back is untrusted text: parsed strictly,
//! cleaned of control characters, cut to length and only shown as text.

pub mod password;
pub mod sites;
pub mod sources;

pub use sources::Answer;

use crate::model::{Id, Kind, Vault};
use crate::net::{NetError, Response};
use crate::util;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// --------------------------------------------------------------------------------------
// Transport
// --------------------------------------------------------------------------------------

/// HTTPS requests. The real implementation is [`Https`]; tests use recorded answers.
pub trait Transport: Send + Sync {
    fn get(
        &self,
        host: &str,
        path: &str,
        headers: &[&str],
        max_body: usize,
    ) -> Result<Response, NetError>;

    fn post(
        &self,
        host: &str,
        path: &str,
        headers: &[&str],
        body: &[u8],
        max_body: usize,
    ) -> Result<Response, NetError>;
}

/// The real network, through [`crate::net::https_get`].
pub struct Https;

impl Transport for Https {
    fn get(
        &self,
        host: &str,
        path: &str,
        headers: &[&str],
        max_body: usize,
    ) -> Result<Response, NetError> {
        crate::net::https_get(host, path, headers, max_body)
    }

    fn post(
        &self,
        host: &str,
        path: &str,
        headers: &[&str],
        body: &[u8],
        max_body: usize,
    ) -> Result<Response, NetError> {
        crate::net::https_post(host, path, headers, body, max_body)
    }
}

// --------------------------------------------------------------------------------------
// What can be looked up, and by whom
// --------------------------------------------------------------------------------------

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum QueryKind {
    #[default]
    Email,
    Username,
    Phone,
    Domain,
}

impl QueryKind {
    pub const ALL: [QueryKind; 4] = [
        QueryKind::Email,
        QueryKind::Username,
        QueryKind::Phone,
        QueryKind::Domain,
    ];

    pub fn label(self) -> &'static str {
        match self {
            QueryKind::Email => "Email",
            QueryKind::Username => "User name",
            QueryKind::Phone => "Phone",
            QueryKind::Domain => "Domain",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            QueryKind::Email => "name@example.com",
            QueryKind::Username => "your user name",
            QueryKind::Phone => "+44 7700 900123",
            QueryKind::Domain => "example.com",
        }
    }

    /// Cleans up what was typed, or says what is wrong with it.
    pub fn normalize(self, text: &str) -> Result<String, &'static str> {
        let t = text.trim();
        match self {
            QueryKind::Email => {
                let e = t.to_lowercase();
                if crate::model::looks_like_email(&e) {
                    Ok(e)
                } else {
                    Err("That does not look like an email address.")
                }
            }
            QueryKind::Username => {
                let ok = (2..=64).contains(&t.chars().count())
                    && !t.chars().any(|c| c.is_whitespace() || c.is_control())
                    && !t.contains('@')
                    && !t.contains('/');
                if ok {
                    Ok(t.to_string())
                } else {
                    Err("A user name here is 2 to 64 characters, without spaces, @ or /. For an email address, use the Email tab.")
                }
            }
            QueryKind::Phone => normalize_phone(t)
                .ok_or("Type the full number with its country code, for example +44 7700 900123."),
            QueryKind::Domain => {
                let host = util::host_of(t);
                let ok = host.contains('.')
                    && host.len() <= 253
                    && !host.starts_with('.')
                    && !host.ends_with('.')
                    && host
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
                if ok {
                    Ok(host)
                } else {
                    Err("That does not look like a domain such as example.com.")
                }
            }
        }
    }
}

/// `+` followed by 8 to 15 digits (E.164), from text with spaces, dashes,
/// dots or brackets. A leading `00` counts as `+`.
pub fn normalize_phone(text: &str) -> Option<String> {
    let t = text.trim();
    let (plus, rest) = if let Some(r) = t.strip_prefix('+') {
        (true, r)
    } else if let Some(r) = t.strip_prefix("00") {
        (true, r)
    } else {
        (false, t)
    };
    if !plus {
        return None;
    }
    let mut digits = String::new();
    for c in rest.chars() {
        match c {
            '0'..='9' => digits.push(c),
            ' ' | '-' | '.' | '(' | ')' => {}
            _ => return None,
        }
    }
    (8..=15)
        .contains(&digits.len())
        .then(|| format!("+{digits}"))
}

/// The services KeepForge can ask. Codes are stored in settings and in the
/// vault's cached results; unknown codes (from a newer version) are ignored.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub enum SourceId {
    /// XposedOrNot: free, no key.
    XposedOrNot,
    /// LeakCheck public API: free, no key; breach names and dates only.
    LeakCheck,
    /// Hudson Rock Cavalier free OSINT API: infostealer infections.
    HudsonRock,
    /// Have I Been Pwned breach list by domain: free, no key.
    HibpDomain,
    /// Have I Been Pwned breached accounts and pastes: the user's own API key.
    Hibp,
    /// Leak-Lookup: the user's own API key; breach names only.
    LeakLookup,
    #[default]
    #[serde(other)]
    Unknown,
}

impl SourceId {
    /// The sources in the order they are shown and asked.
    pub const ALL: [SourceId; 6] = [
        SourceId::XposedOrNot,
        SourceId::LeakCheck,
        SourceId::HudsonRock,
        SourceId::HibpDomain,
        SourceId::Hibp,
        SourceId::LeakLookup,
    ];

    pub fn code(self) -> &'static str {
        match self {
            SourceId::XposedOrNot => "xposedornot",
            SourceId::LeakCheck => "leakcheck",
            SourceId::HudsonRock => "hudsonrock",
            SourceId::HibpDomain => "hibp-domain",
            SourceId::Hibp => "hibp",
            SourceId::LeakLookup => "leaklookup",
            SourceId::Unknown => "unknown",
        }
    }

    pub fn from_code(code: &str) -> Option<SourceId> {
        SourceId::ALL.into_iter().find(|s| s.code() == code)
    }

    pub fn name(self) -> &'static str {
        match self {
            SourceId::XposedOrNot => "XposedOrNot",
            SourceId::LeakCheck => "LeakCheck",
            SourceId::HudsonRock => "Hudson Rock",
            SourceId::HibpDomain => "Have I Been Pwned (sites)",
            SourceId::Hibp => "Have I Been Pwned",
            SourceId::LeakLookup => "Leak-Lookup",
            SourceId::Unknown => "Unknown source",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            SourceId::XposedOrNot => "XposedOrNot",
            SourceId::LeakCheck => "LeakCheck",
            SourceId::HudsonRock => "Hudson Rock",
            SourceId::HibpDomain | SourceId::Hibp => "HIBP",
            SourceId::LeakLookup => "Leak-Lookup",
            SourceId::Unknown => "?",
        }
    }

    pub fn home(self) -> &'static str {
        match self {
            SourceId::XposedOrNot => "https://xposedornot.com",
            SourceId::LeakCheck => "https://leakcheck.io",
            SourceId::HudsonRock => "https://www.hudsonrock.com/free-tools",
            SourceId::HibpDomain | SourceId::Hibp => "https://haveibeenpwned.com",
            SourceId::LeakLookup => "https://leak-lookup.com",
            SourceId::Unknown => "",
        }
    }

    pub fn host(self) -> &'static str {
        match self {
            SourceId::XposedOrNot => sources::XON_HOST,
            SourceId::LeakCheck => sources::LEAKCHECK_HOST,
            SourceId::HudsonRock => sources::HUDSON_HOST,
            SourceId::HibpDomain | SourceId::Hibp => sources::HIBP_HOST,
            SourceId::LeakLookup => sources::LEAKLOOKUP_HOST,
            SourceId::Unknown => "",
        }
    }

    /// What this source can look up.
    pub fn kinds(self) -> &'static [QueryKind] {
        match self {
            SourceId::XposedOrNot => &[QueryKind::Email],
            SourceId::LeakCheck => &[QueryKind::Email, QueryKind::Username],
            SourceId::HudsonRock => &[QueryKind::Email, QueryKind::Username, QueryKind::Domain],
            SourceId::HibpDomain => &[QueryKind::Domain],
            SourceId::Hibp => &[QueryKind::Email],
            SourceId::LeakLookup => &[
                QueryKind::Email,
                QueryKind::Username,
                QueryKind::Phone,
                QueryKind::Domain,
            ],
            SourceId::Unknown => &[],
        }
    }

    pub fn supports(self, kind: QueryKind) -> bool {
        self.kinds().contains(&kind)
    }

    /// The name under which the user's API key is kept in the vault, for
    /// sources that need one.
    pub fn key_name(self) -> Option<&'static str> {
        match self {
            SourceId::Hibp => Some("hibp-api-key"),
            SourceId::LeakLookup => Some("leaklookup-api-key"),
            _ => None,
        }
    }

    /// Where the user gets a key.
    pub fn key_page(self) -> &'static str {
        match self {
            SourceId::Hibp => "https://haveibeenpwned.com/API/Key",
            SourceId::LeakLookup => "https://leak-lookup.com/api",
            _ => "",
        }
    }

    /// Plain words: what is sent, to whom.
    pub fn sends(self) -> &'static str {
        match self {
            SourceId::XposedOrNot => "Sends the email address you check to api.xposedornot.com.",
            SourceId::LeakCheck => "Sends the email address or user name you check to leakcheck.io (its free public API: it answers with breach names and dates only).",
            SourceId::HudsonRock => "Sends the email address, user name or domain you check to cavalier.hudsonrock.com (its free infostealer lookup).",
            SourceId::HibpDomain => "Sends the domain you check to haveibeenpwned.com. \"Compare my saved sites\" (Domain tab) instead downloads the public list of all breached sites once and sends nothing about you.",
            SourceId::Hibp => "Sends the email address you check and your own API key to haveibeenpwned.com.",
            SourceId::LeakLookup => "Sends the email address, user name, phone number or domain you check and your own API key to leak-lookup.com. Only breach names are used. The free key allows 10 lookups a day.",
            SourceId::Unknown => "",
        }
    }

    /// Plain words: what comes back.
    pub fn returns(self) -> &'static str {
        match self {
            SourceId::XposedOrNot => "Breach names, years, sites, what was exposed, how passwords were stored.",
            SourceId::LeakCheck => "Breach names (usually the site) and month.",
            SourceId::HudsonRock => "Whether malware stole saved logins from a computer linked to it, and when.",
            SourceId::HibpDomain => "Which known breaches happened at that site, when, and what was exposed.",
            SourceId::Hibp => "Breaches with full details and pastes. Stealer-log sites too, with a Pro plan and an address on a domain you verified with HIBP.",
            SourceId::LeakLookup => "Breach names.",
            SourceId::Unknown => "",
        }
    }

    /// The shortest gap between two requests to this source.
    pub fn gap(self) -> Duration {
        Duration::from_millis(match self {
            SourceId::XposedOrNot => 2_500,
            SourceId::LeakCheck => 1_500,
            SourceId::HudsonRock => 1_500,
            SourceId::HibpDomain => 1_500,
            // The smallest HIBP plan allows 10 requests a minute.
            SourceId::Hibp => 6_500,
            // The free key allows 5 a minute and 10 a day.
            SourceId::LeakLookup => 13_000,
            SourceId::Unknown => 5_000,
        })
    }
}

// --------------------------------------------------------------------------------------
// Findings and results
// --------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FindingKind {
    #[default]
    Breach,
    Paste,
    /// Malware on a computer copied its saved logins.
    Stealer,
    /// A site whose login for this value was found in infostealer logs.
    StealerSite,
    /// Not about the user: a breach at a site (domain lookups).
    SiteBreach,
    #[serde(other)]
    Other,
}

/// One thing one source reported.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Finding {
    pub source: SourceId,
    pub kind: FindingKind,
    /// Breach or site name.
    pub name: String,
    /// The breached site's domain, without `www.`, when known.
    pub domain: String,
    /// `YYYY`, `YYYY-MM` or `YYYY-MM-DD`, or empty.
    pub date: String,
    pub records: u64,
    /// Kinds of data exposed ("Passwords", "Phone numbers", ...).
    pub data: Vec<String>,
    pub description: String,
    /// An https link to more details, or empty.
    pub link: String,
    /// Extra short facts (for infostealer infections: system, antivirus...).
    pub facts: Vec<String>,
    /// How the site stored passwords, when the source says ("plaintext", ...).
    pub password_risk: String,
}

/// The source failed, or could not be asked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceError {
    RateLimited,
    NeedsKey,
    BadKey,
    /// The key works but its plan does not include this lookup.
    NotInPlan,
    Unsupported,
    Malformed,
    Service(u32),
    Net(String),
    Cancelled,
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceError::RateLimited => f.write_str("Too many lookups for now; try again later."),
            SourceError::NeedsKey => f.write_str("Needs your API key (Settings › Online checks)."),
            SourceError::BadKey => f.write_str("The API key was not accepted."),
            SourceError::NotInPlan => f.write_str("Your API plan does not include this lookup."),
            SourceError::Unsupported => f.write_str("Cannot look this kind of value up."),
            SourceError::Malformed => f.write_str("Sent an answer KeepForge could not read."),
            SourceError::Service(code) => write!(f, "Answered with error {code}."),
            SourceError::Net(e) => f.write_str(e),
            SourceError::Cancelled => f.write_str("Cancelled."),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutcomeState {
    Found,
    #[default]
    Clean,
    Failed,
    #[serde(other)]
    Other,
}

/// How one source did for one value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Outcome {
    pub source: SourceId,
    pub state: OutcomeState,
    pub count: usize,
    /// Why it failed, in plain words.
    pub message: String,
}

/// Everything known about one checked value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Record {
    pub kind: QueryKind,
    pub value: String,
    /// When it was last checked (Unix time).
    pub checked: i64,
    pub outcomes: Vec<Outcome>,
    pub findings: Vec<Finding>,
    /// The "where is this user name registered" scan, when run.
    pub sites: Option<sites::SiteScan>,
}

impl Record {
    pub fn new(kind: QueryKind, value: &str, now: i64) -> Record {
        Record {
            kind,
            value: value.to_string(),
            checked: now,
            ..Default::default()
        }
    }

    /// Replaces what `source` said before with a new answer.
    pub fn apply(&mut self, source: SourceId, result: Result<Answer, SourceError>) {
        self.findings.retain(|f| f.source != source);
        self.outcomes.retain(|o| o.source != source);
        let outcome = match result {
            Ok(a) if a.findings.is_empty() => Outcome {
                source,
                state: OutcomeState::Clean,
                count: 0,
                message: a.note,
            },
            Ok(a) => {
                let count = a.findings.len();
                self.findings.extend(a.findings);
                Outcome {
                    source,
                    state: OutcomeState::Found,
                    count,
                    message: a.note,
                }
            }
            Err(e) => Outcome {
                source,
                state: OutcomeState::Failed,
                count: 0,
                message: e.to_string(),
            },
        };
        self.outcomes.push(outcome);
        self.outcomes.sort_by_key(|o| o.source);
    }

    pub fn exposures(&self) -> Vec<Exposure> {
        merge(&self.findings)
    }

    pub fn failed(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| o.state == OutcomeState::Failed)
            .count()
    }
}

/// All cached results, kept (as JSON) inside the encrypted vault.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cache {
    pub records: Vec<Record>,
    /// When "Check all" last finished.
    pub last_all: i64,
    /// Known breaches at sites saved in the vault (from the public HIBP list).
    pub site_breaches: Vec<Finding>,
    /// When the saved sites were last compared with that list.
    pub sites_checked: i64,
}

/// At most this many values are remembered.
pub const CACHE_LIMIT: usize = 500;

impl Cache {
    /// Reads the cache from the vault. A damaged or newer, unreadable cache
    /// is simply empty: it only holds results that can be fetched again.
    pub fn load(vault: &Vault) -> Cache {
        if vault.exposure.trim().is_empty() {
            return Cache::default();
        }
        serde_json::from_str(&vault.exposure).unwrap_or_default()
    }

    pub fn store(&self, vault: &mut Vault) {
        vault.exposure = serde_json::to_string(self).unwrap_or_default();
    }

    pub fn record(&self, kind: QueryKind, value: &str) -> Option<&Record> {
        self.records
            .iter()
            .find(|r| r.kind == kind && r.value == value)
    }

    /// The record for a value, created (at the front) when missing.
    pub fn record_mut(&mut self, kind: QueryKind, value: &str, now: i64) -> &mut Record {
        let pos = match self
            .records
            .iter()
            .position(|r| r.kind == kind && r.value == value)
        {
            Some(p) => p,
            None => {
                self.records.insert(0, Record::new(kind, value, now));
                self.records.truncate(CACHE_LIMIT);
                0
            }
        };
        &mut self.records[pos]
    }

    pub fn remove(&mut self, kind: QueryKind, value: &str) {
        self.records
            .retain(|r| !(r.kind == kind && r.value == value));
    }

    /// Every exposure about the user (not site lists), with the value it concerns.
    pub fn all_exposures(&self) -> Vec<(QueryKind, String, Exposure)> {
        let mut out = Vec::new();
        for r in &self.records {
            for e in r.exposures() {
                if e.kind != FindingKind::SiteBreach {
                    out.push((r.kind, r.value.clone(), e));
                }
            }
        }
        out
    }

    /// Merges another copy of the cache (from a merged vault file): the
    /// newer result for each value wins.
    pub fn merge_from(&mut self, other: Cache) {
        for r in other.records {
            match self
                .records
                .iter_mut()
                .find(|m| m.kind == r.kind && m.value == r.value)
            {
                Some(m) if r.checked > m.checked => *m = r,
                Some(_) => {}
                None => self.records.push(r),
            }
        }
        self.records.sort_by_key(|r| std::cmp::Reverse(r.checked));
        self.records.truncate(CACHE_LIMIT);
        if other.sites_checked > self.sites_checked {
            self.sites_checked = other.sites_checked;
            self.site_breaches = other.site_breaches;
        }
        self.last_all = self.last_all.max(other.last_all);
    }
}

// --------------------------------------------------------------------------------------
// Merging findings from several sources
// --------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Low => "Low risk",
            Severity::Medium => "Medium risk",
            Severity::High => "High risk",
            Severity::Critical => "Act now",
        }
    }
}

/// One breach (or paste, or infection) with what every source said about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Exposure {
    pub kind: FindingKind,
    pub name: String,
    pub domain: String,
    pub date: String,
    pub records: u64,
    pub data: Vec<String>,
    pub description: String,
    /// Detail links, one per source that gave one.
    pub links: Vec<(SourceId, String)>,
    pub sources: Vec<SourceId>,
    pub facts: Vec<String>,
    pub password_risk: String,
}

/// Lower case letters and digits only.
pub fn squash(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// A breach name such as "Wattpad.com" or "forums.example.org" is a domain.
fn domain_from_name(name: &str) -> Option<String> {
    let n = name.trim().to_lowercase();
    let labels: Vec<&str> = n.split('.').collect();
    let tld = labels.last()?;
    let ok = labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-'))
        && tld.len() >= 2
        && tld.chars().all(|c| c.is_ascii_alphabetic());
    ok.then(|| util::base_domain(&n))
}

/// The breach name without suffixes such as "-2024" or "-Scraped".
fn name_key(name: &str) -> String {
    squash(name.split(['-', '(']).next().unwrap_or(""))
}

fn year_of(date: &str) -> Option<i64> {
    let y: i64 = date.get(..4)?.parse().ok()?;
    (1980..=2100).contains(&y).then_some(y)
}

/// The moment after which a password can no longer have been part of a
/// breach with this date: the end of the day, month or year given.
pub fn cutoff(date: &str) -> Option<i64> {
    let y = year_of(date)?;
    let m: Option<u32> = date.get(5..7).and_then(|m| m.parse().ok());
    let d: Option<u32> = date.get(8..10).and_then(|d| d.parse().ok());
    Some(match (m, d) {
        (Some(m @ 1..=12), Some(d @ 1..=31)) => (util::days_from_civil(y, m, d) + 1) * util::DAY,
        (Some(m @ 1..=11), _) => util::days_from_civil(y, m + 1, 1) * util::DAY,
        (Some(12), _) | (None, _) => util::days_from_civil(y + 1, 1, 1) * util::DAY,
        _ => util::days_from_civil(y + 1, 1, 1) * util::DAY,
    })
}

/// A normalised name for a kind of exposed data, so that "passwords",
/// "Password" and "password" count once.
fn tidy_data(text: &str) -> String {
    let t = text.trim();
    let lower = t.to_lowercase();
    let known = [
        ("password hint", "Password hints"),
        ("password", "Passwords"),
        ("email", "Email addresses"),
        ("phone", "Phone numbers"),
        ("username", "Usernames"),
        ("user name", "Usernames"),
        ("ip", "IP addresses"),
        ("dob", "Dates of birth"),
        ("date of birth", "Dates of birth"),
        ("address", "Physical addresses"),
        ("name", "Names"),
    ];
    for (needle, label) in known {
        let hit = if needle.len() <= 3 {
            lower == needle
                || lower.starts_with(&format!("{needle} "))
                || lower == format!("{needle}s")
        } else {
            lower.contains(needle)
        };
        if hit {
            // "Email addresses" must not become "Physical addresses".
            if label == "Physical addresses" && lower.contains("email") {
                continue;
            }
            if label == "Names"
                && (lower.contains("user")
                    || lower.contains("company")
                    || lower.contains("profile"))
            {
                continue;
            }
            return label.to_string();
        }
    }
    let mut chars = t.chars();
    match chars.next() {
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

fn source_rank(s: SourceId) -> u8 {
    match s {
        SourceId::Hibp | SourceId::HibpDomain => 0,
        SourceId::XposedOrNot => 1,
        SourceId::HudsonRock => 2,
        SourceId::LeakCheck => 3,
        SourceId::LeakLookup => 4,
        SourceId::Unknown => 9,
    }
}

/// Groups what several sources said into one entry per breach: the same
/// site (by domain, or by name) within a year of each other.
pub fn merge(findings: &[Finding]) -> Vec<Exposure> {
    let mut sorted: Vec<&Finding> = findings.iter().collect();
    // The most detailed sources first, so their names and texts are kept.
    sorted.sort_by_key(|f| source_rank(f.source));
    let mut out: Vec<(String, Exposure)> = Vec::new();
    for f in sorted {
        let domain = if !f.domain.is_empty() {
            util::base_domain(&util::host_of(&f.domain))
        } else {
            domain_from_name(&f.name).unwrap_or_default()
        };
        let key = match f.kind {
            FindingKind::Stealer => {
                format!("stealer:{}:{}", domain, f.date.get(..10).unwrap_or(&f.date))
            }
            FindingKind::StealerSite => format!("s:{domain}"),
            FindingKind::Paste => format!("paste:{}:{}", squash(&f.name), f.date),
            _ if !domain.is_empty() => format!("d:{domain}"),
            _ => format!("n:{}", name_key(&f.name)),
        };
        // Different sources sometimes name the same breach differently but
        // agree on the site; others give only a name. Try both.
        let nk = name_key(&f.name);
        let by_name =
            matches!(f.kind, FindingKind::Breach | FindingKind::SiteBreach) && nk.len() >= 4;
        let year = year_of(&f.date);
        let close = |e: &Exposure| match (year, year_of(&e.date)) {
            (Some(a), Some(b)) => (a - b).abs() <= 1,
            _ => true,
        };
        let pos = out.iter().position(|(k, e)| {
            e.kind == f.kind && (*k == key || (by_name && name_key(&e.name) == nk)) && close(e)
        });
        match pos {
            Some(i) => {
                let e = &mut out[i].1;
                if !e.sources.contains(&f.source) {
                    e.sources.push(f.source);
                }
                if e.domain.is_empty() {
                    e.domain = domain.clone();
                }
                if f.date.len() > e.date.len()
                    && (e.date.is_empty() || f.date.starts_with(&e.date[..4.min(e.date.len())]))
                {
                    e.date = f.date.clone();
                }
                e.records = e.records.max(f.records);
                for d in &f.data {
                    let d = tidy_data(d);
                    if !d.is_empty() && !e.data.iter().any(|x| x.eq_ignore_ascii_case(&d)) {
                        e.data.push(d);
                    }
                }
                if e.description.is_empty() {
                    e.description = f.description.clone();
                }
                if e.password_risk.is_empty() {
                    e.password_risk = f.password_risk.clone();
                }
                if !f.link.is_empty() && !e.links.iter().any(|(_, l)| *l == f.link) {
                    e.links.push((f.source, f.link.clone()));
                }
                for fact in &f.facts {
                    if !e.facts.contains(fact) {
                        e.facts.push(fact.clone());
                    }
                }
            }
            None => {
                let mut data: Vec<String> = Vec::new();
                for d in &f.data {
                    let d = tidy_data(d);
                    if !d.is_empty() && !data.iter().any(|x| x.eq_ignore_ascii_case(&d)) {
                        data.push(d);
                    }
                }
                out.push((
                    key,
                    Exposure {
                        kind: f.kind,
                        name: f.name.clone(),
                        domain,
                        date: f.date.clone(),
                        records: f.records,
                        data,
                        description: f.description.clone(),
                        links: if f.link.is_empty() {
                            Vec::new()
                        } else {
                            vec![(f.source, f.link.clone())]
                        },
                        sources: vec![f.source],
                        facts: f.facts.clone(),
                        password_risk: f.password_risk.clone(),
                    },
                ));
            }
        }
    }
    let mut list: Vec<Exposure> = out.into_iter().map(|(_, e)| e).collect();
    for e in &mut list {
        e.sources.sort();
        e.data.sort_by_key(|d| data_rank(d));
    }
    list.sort_by(|a, b| {
        b.severity()
            .cmp(&a.severity())
            .then(b.date.cmp(&a.date))
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    list
}

fn data_rank(d: &str) -> u8 {
    let l = d.to_lowercase();
    if l.contains("password") {
        0
    } else if l.contains("credit") || l.contains("bank") || l.contains("financial") {
        1
    } else if l.contains("phone") || l.contains("address") || l.contains("birth") {
        2
    } else if l.contains("email") {
        4
    } else {
        3
    }
}

fn any_data(e: &Exposure, words: &[&str]) -> bool {
    e.data.iter().any(|d| {
        let l = d.to_lowercase();
        words.iter().any(|w| l.contains(w))
    })
}

impl Exposure {
    pub fn exposes_passwords(&self) -> bool {
        matches!(self.kind, FindingKind::Stealer | FindingKind::StealerSite)
            || any_data(self, &["password"])
    }

    pub fn severity(&self) -> Severity {
        match self.kind {
            FindingKind::Stealer | FindingKind::StealerSite => Severity::Critical,
            FindingKind::Paste => Severity::Medium,
            // The source did not say what leaked: assume the worst likely case.
            _ if self.data.is_empty() => Severity::Medium,
            _ if any_data(
                self,
                &[
                    "password",
                    "credit card",
                    "bank account",
                    "security question",
                ],
            ) =>
            {
                Severity::High
            }
            _ if any_data(
                self,
                &[
                    "phone",
                    "physical address",
                    "birth",
                    "government",
                    "passport",
                    "social security",
                    "financial",
                    "partial credit",
                ],
            ) =>
            {
                Severity::Medium
            }
            _ => Severity::Low,
        }
    }

    /// The site's name for advice texts: the domain when known.
    pub fn site(&self) -> String {
        if self.domain.is_empty() {
            self.name.clone()
        } else {
            self.domain.clone()
        }
    }

    pub fn cutoff(&self) -> Option<i64> {
        cutoff(&self.date)
    }

    /// What to do about it, in plain words, most important first.
    pub fn advice(&self) -> Vec<String> {
        let site = self.site();
        let mut out = Vec::new();
        match self.kind {
            FindingKind::Stealer => {
                out.push("Malware copied the logins saved on a computer you used. Scan that computer with an up-to-date antivirus first (or reset it).".into());
                out.push("Then change the passwords that were saved in browsers on that computer, starting with email, banking and social media, and sign out of all other sessions.".into());
                out.push("Turn on two-step verification wherever you can; stolen session cookies stop working when you sign out everywhere.".into());
                return out;
            }
            FindingKind::StealerSite => {
                out.push(format!("Malware on a computer you used captured your login for {site}. Scan that computer with an up-to-date antivirus first."));
                out.push(format!("Then change your password at {site}, sign out of all sessions there and turn on two-step verification (2FA)."));
                return out;
            }
            FindingKind::Paste => {
                out.push("Your address was posted publicly. If a password was posted with it, change that password everywhere you used it.".into());
                out.push("Expect spam and phishing emails.".into());
                return out;
            }
            FindingKind::SiteBreach => {
                out.push(format!("If you have an account at {site} and have not changed its password since this breach, change it now."));
                return out;
            }
            _ => {}
        }
        if self.data.is_empty() {
            out.push(format!("The source does not say what leaked. To be safe, change your password at {site}, and anywhere you used the same password."));
        }
        if self.exposes_passwords() {
            out.push(format!("Change your password at {site}. If you used the same password anywhere else, change it there too."));
            out.push(format!(
                "Turn on two-step verification (2FA) at {site} if it offers it."
            ));
        }
        if any_data(self, &["security question"]) {
            out.push(
                "Change the answers to your security questions; treat them like passwords.".into(),
            );
        }
        if any_data(self, &["credit card", "bank", "financial", "payment"]) {
            out.push("Watch your bank and card statements, and ask your bank for a new card if card details were included.".into());
        }
        if any_data(self, &["phone"]) {
            out.push("Expect scam calls and text messages that use this breach; never give codes or passwords to callers. Ask your mobile provider for a SIM-swap PIN.".into());
        }
        if any_data(
            self,
            &[
                "physical address",
                "birth",
                "government",
                "passport",
                "social security",
            ],
        ) {
            out.push("Personal details leaked can be used for identity fraud: be wary of unexpected letters and calls, and consider a credit freeze where you live.".into());
        }
        out.push(format!("Be careful with emails that mention {site}: they may be phishing. If you no longer use the account, delete it."));
        out
    }
}

// --------------------------------------------------------------------------------------
// Linking results to the vault
// --------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultMatch {
    pub item: Id,
    pub title: String,
    /// The saved password predates the breach (or its date is unknown).
    pub change_password: bool,
}

/// The logins (outside the trash) that belong to the breached site.
pub fn matching_items(vault: &Vault, e: &Exposure) -> Vec<VaultMatch> {
    if e.kind == FindingKind::Stealer || e.kind == FindingKind::Paste {
        return Vec::new();
    }
    let always = e.kind == FindingKind::StealerSite;
    vault
        .items
        .iter()
        .filter(|i| {
            i.kind == Kind::Login
                && !i.in_trash()
                && crate::breach::site_matches(i, &e.name, &e.domain)
        })
        .map(|i| VaultMatch {
            item: i.id,
            title: i.title.clone(),
            change_password: always
                || match e.cutoff() {
                    Some(c) => i.password_changed < c,
                    None => true,
                },
        })
        .collect()
}

/// Logins that should get a new password, with the reason, over a set of
/// exposures. The first reason found for an item wins.
pub fn items_to_change<'a>(
    vault: &Vault,
    exposures: impl Iterator<Item = &'a Exposure>,
) -> Vec<(Id, String)> {
    let mut out: Vec<(Id, String)> = Vec::new();
    for e in exposures {
        for m in matching_items(vault, e) {
            if m.change_password && !out.iter().any(|(id, _)| *id == m.item) {
                let when = year_of(&e.date)
                    .map(|y| format!(" in {y}"))
                    .unwrap_or_default();
                out.push((
                    m.item,
                    format!("{} breached{when}, after the last password change", e.name),
                ));
            }
        }
    }
    out
}

/// The site's breaches matter to the user only if there is a login for it.
/// From a list of all known breached sites, those that match saved logins.
pub fn breaches_for_vault(vault: &Vault, all: &[Finding]) -> Vec<Finding> {
    let mut hosts: Vec<String> = Vec::new();
    let mut titles: Vec<String> = Vec::new();
    for i in vault
        .items
        .iter()
        .filter(|i| i.kind == Kind::Login && !i.in_trash())
    {
        for u in &i.urls {
            let h = util::base_domain(&util::host_of(u));
            if h.contains('.') && !hosts.contains(&h) {
                hosts.push(h);
            }
        }
        let t = squash(&i.title);
        if t.len() >= 4 && !titles.contains(&t) {
            titles.push(t);
        }
    }
    all.iter()
        .filter(|f| {
            let d = util::base_domain(&util::host_of(&f.domain));
            (!d.is_empty() && hosts.contains(&d)) || {
                let n = name_key(&f.name);
                d.is_empty() && n.len() >= 5 && titles.contains(&n)
            }
        })
        .cloned()
        .collect()
}

// --------------------------------------------------------------------------------------
// Running a check
// --------------------------------------------------------------------------------------

/// One value to look up.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    pub kind: QueryKind,
    pub value: String,
}

/// A source to ask, with the user's key when it needs one.
pub struct Asked {
    pub source: SourceId,
    pub key: Option<zeroize::Zeroizing<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Result {
        kind: QueryKind,
        value: String,
        source: SourceId,
        result: Result<Answer, SourceError>,
    },
    Done,
}

/// How many answers a run will produce.
pub fn planned(tasks: &[Task], asked: &[Asked]) -> usize {
    asked
        .iter()
        .map(|a| tasks.iter().filter(|t| a.source.supports(t.kind)).count())
        .sum()
}

/// Asks every source about every value it supports. Each source runs on its
/// own thread with its own spacing between requests, so a slow or limited
/// service never holds up the others. Blocks until all are done, then emits
/// [`Event::Done`].
pub fn run(
    tasks: Vec<Task>,
    asked: Vec<Asked>,
    transport: Arc<dyn Transport>,
    cancel: Arc<AtomicBool>,
    emit: Arc<dyn Fn(Event) + Send + Sync>,
    pace: bool,
) {
    let mut threads = Vec::new();
    for a in asked {
        let mine: Vec<Task> = tasks
            .iter()
            .filter(|t| a.source.supports(t.kind))
            .cloned()
            .collect();
        if mine.is_empty() {
            continue;
        }
        let (transport, cancel, emit) = (transport.clone(), cancel.clone(), emit.clone());
        threads.push(std::thread::spawn(move || {
            let mut throttle =
                crate::net::Throttle::new(if pace { a.source.gap() } else { Duration::ZERO });
            let mut limited = 0;
            for t in mine {
                let result = if cancel.load(Ordering::Relaxed) {
                    Err(SourceError::Cancelled)
                } else if limited >= 2 {
                    // Twice refused for asking too often: leave the rest.
                    Err(SourceError::RateLimited)
                } else {
                    let key = a.key.as_ref().map(|k| k.as_str());
                    let gap = a.source.gap();
                    let between = move || {
                        if pace {
                            std::thread::sleep(gap);
                        }
                    };
                    throttle.pace();
                    let mut r = sources::check(
                        a.source,
                        transport.as_ref(),
                        t.kind,
                        &t.value,
                        key,
                        &between,
                    );
                    if r == Err(SourceError::RateLimited) && pace && !cancel.load(Ordering::Relaxed)
                    {
                        // One polite retry after a longer pause.
                        std::thread::sleep(gap * 6);
                        throttle.mark(std::time::Instant::now());
                        r = sources::check(
                            a.source,
                            transport.as_ref(),
                            t.kind,
                            &t.value,
                            key,
                            &between,
                        );
                    }
                    if r == Err(SourceError::RateLimited) {
                        limited += 1;
                    }
                    r
                };
                emit(Event::Result {
                    kind: t.kind,
                    value: t.value,
                    source: a.source,
                    result,
                });
            }
        }));
    }
    for t in threads {
        let _ = t.join();
    }
    emit(Event::Done);
}

#[cfg(test)]
pub mod testing {
    //! Recorded answers instead of the network.
    use super::*;
    use std::sync::Mutex;

    pub struct Recorded {
        /// (host, path prefix, status, body)
        pub routes: Vec<(String, String, u32, Vec<u8>)>,
        /// Every request made: "host path | headers".
        pub seen: Mutex<Vec<String>>,
    }

    impl Default for Recorded {
        fn default() -> Self {
            Recorded::new()
        }
    }

    impl Recorded {
        pub fn new() -> Recorded {
            Recorded {
                routes: Vec::new(),
                seen: Mutex::new(Vec::new()),
            }
        }

        pub fn with(mut self, host: &str, path: &str, status: u32, body: &str) -> Recorded {
            self.routes
                .push((host.into(), path.into(), status, body.as_bytes().to_vec()));
            self
        }

        pub fn seen(&self) -> Vec<String> {
            self.seen.lock().unwrap().clone()
        }
    }

    impl Transport for Recorded {
        fn get(
            &self,
            host: &str,
            path: &str,
            headers: &[&str],
            max_body: usize,
        ) -> Result<Response, NetError> {
            self.answer(host, path, &headers.join("; "), max_body)
        }

        fn post(
            &self,
            host: &str,
            path: &str,
            headers: &[&str],
            body: &[u8],
            max_body: usize,
        ) -> Result<Response, NetError> {
            let sent = format!(
                "{} | body {}",
                headers.join("; "),
                String::from_utf8_lossy(body)
            );
            self.answer(host, path, &sent, max_body)
        }
    }

    impl Recorded {
        fn answer(
            &self,
            host: &str,
            path: &str,
            headers: &str,
            max_body: usize,
        ) -> Result<Response, NetError> {
            self.seen
                .lock()
                .unwrap()
                .push(format!("{host}{path} | {headers}"));
            for (h, p, status, body) in &self.routes {
                if h == host && path.starts_with(p.as_str()) {
                    if body.len() > max_body {
                        return Err(NetError::TooLarge);
                    }
                    return Ok(Response {
                        status: *status,
                        body: body.clone(),
                    });
                }
            }
            Err(NetError::Unreachable("no recorded answer".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::Recorded;
    use super::*;
    use crate::model::Item;
    use std::sync::Mutex;

    fn finding(source: SourceId, name: &str, domain: &str, date: &str, data: &[&str]) -> Finding {
        Finding {
            source,
            kind: FindingKind::Breach,
            name: name.into(),
            domain: domain.into(),
            date: date.into(),
            data: data.iter().map(|d| d.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn normalizes_what_is_typed() {
        assert_eq!(
            QueryKind::Email.normalize(" Alex@Example.COM "),
            Ok("alex@example.com".into())
        );
        assert!(QueryKind::Email.normalize("alex").is_err());
        assert_eq!(
            QueryKind::Username.normalize(" alex_m "),
            Ok("alex_m".into())
        );
        assert!(QueryKind::Username.normalize("a b").is_err());
        assert!(QueryKind::Username.normalize("a@b.c").is_err());
        assert_eq!(
            QueryKind::Phone.normalize("+44 7700 900-123"),
            Ok("+447700900123".into())
        );
        assert_eq!(
            QueryKind::Phone.normalize("0044 (7700) 900123"),
            Ok("+447700900123".into())
        );
        assert!(QueryKind::Phone.normalize("07700 900123").is_err());
        assert!(QueryKind::Phone.normalize("+44 7700 abc").is_err());
        assert!(QueryKind::Phone.normalize("+12").is_err());
        assert_eq!(
            QueryKind::Domain.normalize("https://www.Example.com/login"),
            Ok("example.com".into())
        );
        assert!(QueryKind::Domain.normalize("localhost").is_err());
        assert!(QueryKind::Domain.normalize("exa mple.com").is_err());
    }

    #[test]
    fn source_codes_round_trip() {
        for s in SourceId::ALL {
            assert_eq!(SourceId::from_code(s.code()), Some(s));
            assert!(!s.kinds().is_empty());
            assert!(s.home().starts_with("https://"));
            assert!(!s.sends().is_empty());
            assert_eq!(s.key_name().is_some(), !s.key_page().is_empty());
        }
        assert_eq!(SourceId::from_code("nope"), None);
        // A source from a newer version reads as Unknown instead of failing.
        let r: Outcome =
            serde_json::from_str(r#"{"source":"FutureThing","state":"Later"}"#).unwrap();
        assert_eq!(r.source, SourceId::Unknown);
        assert_eq!(r.state, OutcomeState::Other);
    }

    #[test]
    fn merges_the_same_breach_from_several_sources() {
        let findings = vec![
            finding(
                SourceId::LeakCheck,
                "Wattpad.com",
                "",
                "2020-05",
                &["password", "username"],
            ),
            Finding {
                description: "Wattpad lost data.".into(),
                link: "https://xposedornot.com/xposed#Wattpad".into(),
                records: 270_000_000,
                ..finding(
                    SourceId::XposedOrNot,
                    "Wattpad",
                    "wattpad.com",
                    "2020",
                    &["Email addresses", "Passwords"],
                )
            },
            finding(SourceId::LeakCheck, "Canva.com", "", "2019-05", &[]),
            finding(
                SourceId::XposedOrNot,
                "Canva",
                "canva.com",
                "2019",
                &["Email addresses", "Names"],
            ),
            // Same site, years apart: a different breach.
            finding(
                SourceId::XposedOrNot,
                "Twitter",
                "twitter.com",
                "2013",
                &["Email addresses"],
            ),
            finding(
                SourceId::XposedOrNot,
                "Twitter-Scraped",
                "twitter.com",
                "2021",
                &["Email addresses", "Phone numbers"],
            ),
            // Only a name, no domain, on both sides.
            finding(SourceId::LeakCheck, "Collection #1", "", "", &[]),
            finding(SourceId::LeakLookup, "collection #1", "", "", &[]),
        ];
        let merged = merge(&findings);
        assert_eq!(merged.len(), 5, "{merged:#?}");
        let w = merged.iter().find(|e| e.domain == "wattpad.com").unwrap();
        assert_eq!(w.sources, vec![SourceId::XposedOrNot, SourceId::LeakCheck]);
        assert_eq!(w.name, "Wattpad", "the more detailed source names it");
        assert_eq!(w.date, "2020-05", "the more precise date wins");
        assert_eq!(w.records, 270_000_000);
        assert!(w.data.contains(&"Passwords".to_string()));
        assert!(w.data.contains(&"Usernames".to_string()));
        assert_eq!(
            w.data.iter().filter(|d| d.as_str() == "Passwords").count(),
            1
        );
        assert_eq!(w.data[0], "Passwords", "passwords listed first");
        assert_eq!(w.severity(), Severity::High);
        assert_eq!(w.links.len(), 1);
        let c = merged.iter().find(|e| e.domain == "canva.com").unwrap();
        assert_eq!(c.sources.len(), 2);
        assert_eq!(c.severity(), Severity::Low);
        let tw: Vec<&Exposure> = merged
            .iter()
            .filter(|e| e.domain == "twitter.com")
            .collect();
        assert_eq!(tw.len(), 2);
        let coll = merged.iter().find(|e| e.name == "Collection #1").unwrap();
        assert_eq!(
            coll.sources,
            vec![SourceId::LeakCheck, SourceId::LeakLookup]
        );
        // Highest risk first.
        assert_eq!(merged[0].severity(), Severity::High);
    }

    #[test]
    fn severity_and_advice() {
        let mut e = merge(&[finding(
            SourceId::XposedOrNot,
            "Shop",
            "shop.example",
            "2017",
            &["Email addresses", "Phone numbers"],
        )])
        .remove(0);
        assert_eq!(e.severity(), Severity::Medium);
        let advice = e.advice().join(" ");
        assert!(advice.contains("scam calls"));
        assert!(!advice.contains("Change your password"));
        e.data.push("Passwords".into());
        assert_eq!(e.severity(), Severity::High);
        assert!(e.advice()[0].starts_with("Change your password at shop.example"));
        let stealer = Exposure {
            kind: FindingKind::Stealer,
            ..e.clone()
        };
        assert_eq!(stealer.severity(), Severity::Critical);
        assert!(stealer.advice()[0].contains("antivirus"));
    }

    #[test]
    fn cutoffs_follow_the_precision_given() {
        let day = util::DAY;
        assert_eq!(
            cutoff("2019"),
            Some(util::days_from_civil(2020, 1, 1) * day)
        );
        assert_eq!(
            cutoff("2019-06"),
            Some(util::days_from_civil(2019, 7, 1) * day)
        );
        assert_eq!(
            cutoff("2019-12"),
            Some(util::days_from_civil(2020, 1, 1) * day)
        );
        assert_eq!(
            cutoff("2019-06-03"),
            Some(util::days_from_civil(2019, 6, 4) * day)
        );
        assert_eq!(
            cutoff("2019-06-03T10:00:00Z"),
            Some(util::days_from_civil(2019, 6, 4) * day)
        );
        assert_eq!(cutoff(""), None);
        assert_eq!(cutoff("soon"), None);
    }

    fn vault_with(items: &[(&str, &str, (i64, u32, u32))]) -> Vault {
        let mut v = Vault::new("t", 0);
        for (title, url, (y, m, d)) in items {
            let mut i = Item::new(Kind::Login, 0);
            i.title = title.to_string();
            if !url.is_empty() {
                i.urls = vec![url.to_string()];
            }
            i.password_changed = util::days_from_civil(*y, *m, *d) * util::DAY;
            v.items.push(i);
        }
        v
    }

    #[test]
    fn links_exposures_to_saved_logins() {
        let v = vault_with(&[
            ("My Wattpad", "https://www.wattpad.com/login", (2019, 1, 1)),
            ("Wattpad (new)", "https://wattpad.com", (2021, 3, 1)),
            ("Canva", "", (2018, 1, 1)),
            ("Bank", "https://bank.example", (2010, 1, 1)),
        ]);
        let merged = merge(&[
            finding(
                SourceId::LeakCheck,
                "Wattpad.com",
                "",
                "2020-05",
                &["password"],
            ),
            finding(
                SourceId::XposedOrNot,
                "Canva",
                "canva.com",
                "2019",
                &["Passwords"],
            ),
        ]);
        let w = merged.iter().find(|e| e.domain == "wattpad.com").unwrap();
        let m = matching_items(&v, w);
        assert_eq!(m.len(), 2);
        assert!(m[0].change_password);
        assert!(!m[1].change_password, "changed after the breach");
        let change = items_to_change(&v, merged.iter());
        let titles: Vec<&str> = change
            .iter()
            .map(|(id, _)| v.item(*id).unwrap().title.as_str())
            .collect();
        assert_eq!(titles.len(), 2);
        assert!(titles.contains(&"My Wattpad") && titles.contains(&"Canva"));
        assert!(change.iter().any(|(_, why)| why.contains("Wattpad")));
        // A stealer infection is not tied to one site.
        let s = Exposure {
            kind: FindingKind::Stealer,
            ..w.clone()
        };
        assert!(matching_items(&v, &s).is_empty());
    }

    #[test]
    fn site_list_is_matched_locally() {
        let v = vault_with(&[
            ("Adobe", "https://account.adobe.com", (2012, 1, 1)),
            ("Something", "https://other.example", (2012, 1, 1)),
        ]);
        let all = vec![
            Finding {
                kind: FindingKind::SiteBreach,
                ..finding(
                    SourceId::HibpDomain,
                    "Adobe",
                    "adobe.com",
                    "2013-10-04",
                    &["Passwords"],
                )
            },
            Finding {
                kind: FindingKind::SiteBreach,
                ..finding(
                    SourceId::HibpDomain,
                    "Unrelated",
                    "unrelated.example",
                    "2015",
                    &[],
                )
            },
        ];
        let hits = breaches_for_vault(&v, &all);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "Adobe");
    }

    #[test]
    fn cache_round_trips_through_the_vault_and_merges() {
        let mut v = Vault::new("t", 0);
        assert_eq!(Cache::load(&v), Cache::default());
        let mut c = Cache::default();
        let r = c.record_mut(QueryKind::Email, "a@example.com", 100);
        r.apply(
            SourceId::XposedOrNot,
            Ok(Answer {
                findings: vec![finding(
                    SourceId::XposedOrNot,
                    "A",
                    "a.example",
                    "2020",
                    &[],
                )],
                note: String::new(),
            }),
        );
        r.apply(SourceId::LeakCheck, Err(SourceError::RateLimited));
        assert_eq!(r.failed(), 1);
        // A new answer replaces the old one from the same source.
        r.apply(SourceId::XposedOrNot, Ok(Answer::default()));
        assert!(r.findings.is_empty());
        assert_eq!(r.outcomes[0].state, OutcomeState::Clean);
        c.store(&mut v);
        assert_eq!(Cache::load(&v), c);
        // Damaged text reads as empty, never as an error.
        v.exposure = "{not json".into();
        assert_eq!(Cache::load(&v), Cache::default());

        let mut other = Cache::default();
        other.record_mut(QueryKind::Email, "a@example.com", 50);
        other.record_mut(QueryKind::Username, "alex", 200);
        let before = c.record(QueryKind::Email, "a@example.com").unwrap().clone();
        c.merge_from(other);
        assert_eq!(c.records.len(), 2);
        assert_eq!(c.record(QueryKind::Email, "a@example.com"), Some(&before));
        assert_eq!(c.records[0].value, "alex");
    }

    #[test]
    fn runs_every_source_and_reports_failures() {
        let t = Recorded::new()
            .with(sources::XON_HOST, "/v1/breach-analytics", 200, r#"{"ExposedBreaches":{"breaches_details":[{"breach":"PhotoCloud","domain":"photocloud.example","xposed_date":"2019","xposed_data":"Email addresses;Passwords"}]}}"#)
            .with(sources::LEAKCHECK_HOST, "/api/public", 429, "");
        let t = Arc::new(t);
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        let tasks = vec![
            Task {
                kind: QueryKind::Email,
                value: "a@example.com".into(),
            },
            Task {
                kind: QueryKind::Username,
                value: "alex".into(),
            },
            Task {
                kind: QueryKind::Email,
                value: "b@example.com".into(),
            },
        ];
        let asked = vec![
            Asked {
                source: SourceId::XposedOrNot,
                key: None,
            },
            Asked {
                source: SourceId::LeakCheck,
                key: None,
            },
            Asked {
                source: SourceId::Hibp,
                key: None,
            },
        ];
        assert_eq!(planned(&tasks, &asked), 2 + 3 + 2);
        run(
            tasks,
            asked,
            t.clone(),
            Arc::new(AtomicBool::new(false)),
            Arc::new(move |e| sink.lock().unwrap().push(e)),
            false,
        );
        let events = events.lock().unwrap().clone();
        assert_eq!(events.len(), 8);
        assert_eq!(events.last(), Some(&Event::Done));
        let of = |source: SourceId| -> Vec<&Result<Answer, SourceError>> {
            events
                .iter()
                .filter_map(|e| match e {
                    Event::Result {
                        source: s, result, ..
                    } if *s == source => Some(result),
                    _ => None,
                })
                .collect()
        };
        assert!(of(SourceId::XposedOrNot)
            .iter()
            .all(|r| matches!(r, Ok(a) if a.findings.len() == 1)));
        assert!(of(SourceId::LeakCheck)
            .iter()
            .all(|r| **r == Err(SourceError::RateLimited)));
        assert!(of(SourceId::Hibp)
            .iter()
            .all(|r| **r == Err(SourceError::NeedsKey)));
        // LeakCheck refused twice, so the third value was not even sent.
        let seen = t.seen();
        assert_eq!(
            seen.iter()
                .filter(|s| s.starts_with(sources::LEAKCHECK_HOST))
                .count(),
            2
        );
        // Nothing was sent to a source without its key.
        assert!(!seen.iter().any(|s| s.starts_with(sources::HIBP_HOST)));
    }

    #[test]
    fn cancel_stops_before_sending() {
        let t = Arc::new(Recorded::new());
        let events = Arc::new(Mutex::new(Vec::new()));
        let sink = events.clone();
        run(
            vec![Task {
                kind: QueryKind::Email,
                value: "a@example.com".into(),
            }],
            vec![Asked {
                source: SourceId::XposedOrNot,
                key: None,
            }],
            t.clone(),
            Arc::new(AtomicBool::new(true)),
            Arc::new(move |e| sink.lock().unwrap().push(e)),
            false,
        );
        assert!(t.seen().is_empty());
        assert!(matches!(
            events.lock().unwrap()[0],
            Event::Result {
                result: Err(SourceError::Cancelled),
                ..
            }
        ));
    }
}
