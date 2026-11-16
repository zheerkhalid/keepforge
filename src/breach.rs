//! Optional email breach lookup through the XposedOrNot API
//! (https://xposedornot.com). Only ever started by an explicit click.
//!
//! What is sent: the email address being checked, to
//! `api.xposedornot.com`, over HTTPS. Nothing else: no passwords, no vault
//! data. Results are kept in memory for the session only.
//!
//! Everything that comes back is untrusted text: it is parsed strictly,
//! cleaned of control characters, cut to length and only ever shown as text.

use crate::model::{Id, Kind, Vault};
use crate::util;
use serde::Deserialize;

pub const HOST: &str = "api.xposedornot.com";
/// At most one request per this many milliseconds.
pub const GAP_MS: u64 = 1500;
const MAX_BREACHES: usize = 600;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Breach {
    pub name: String,
    pub domain: String,
    /// The year of the breach, when known.
    pub year: Option<i64>,
    pub records: u64,
    /// Kinds of data exposed ("Passwords", "Email addresses", ...).
    pub exposed: Vec<String>,
    pub industry: String,
    pub password_risk: String,
    pub description: String,
}

impl Breach {
    pub fn exposes_passwords(&self) -> bool {
        self.exposed
            .iter()
            .any(|e| e.to_lowercase().contains("password"))
    }

    /// The moment after which a password can no longer have been part of
    /// this breach: the end of the breach year (the service gives years only).
    pub fn cutoff(&self) -> Option<i64> {
        self.year
            .map(|y| util::days_from_civil(y + 1, 1, 1) * util::DAY)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EmailResult {
    Found(Vec<Breach>),
    NotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BreachError {
    /// HTTP 429: too many requests.
    RateLimited,
    /// The answer was not in the expected shape.
    Malformed,
    /// Another HTTP error.
    Service(u32),
    Net(String),
    BadEmail,
}

impl std::fmt::Display for BreachError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BreachError::RateLimited => f.write_str(
                "The breach service allows only a limited number of lookups. Try again later.",
            ),
            BreachError::Malformed => {
                f.write_str("The breach service sent an answer KeepForge could not read.")
            }
            BreachError::Service(code) => {
                write!(f, "The breach service answered with error {code}.")
            }
            BreachError::Net(e) => f.write_str(e),
            BreachError::BadEmail => f.write_str("That does not look like an email address."),
        }
    }
}

#[derive(Deserialize)]
struct Analytics {
    #[serde(rename = "ExposedBreaches")]
    exposed: Option<Exposed>,
    #[serde(rename = "BreachesSummary")]
    summary: Option<Summary>,
    #[serde(rename = "Error")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct Exposed {
    breaches_details: Vec<Detail>,
}

#[derive(Deserialize)]
struct Summary {
    #[serde(default)]
    site: String,
}

#[derive(Deserialize)]
struct Detail {
    breach: String,
    #[serde(default)]
    details: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    industry: String,
    #[serde(default)]
    password_risk: String,
    #[serde(default)]
    xposed_data: String,
    #[serde(default)]
    xposed_date: serde_json::Value,
    #[serde(default)]
    xposed_records: serde_json::Value,
}

fn value_to_u64(v: &serde_json::Value) -> u64 {
    match v {
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
        serde_json::Value::String(s) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

fn value_to_year(v: &serde_json::Value) -> Option<i64> {
    let text = match v {
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::String(s) => s.clone(),
        _ => return None,
    };
    let year: i64 = text.trim().get(..4)?.parse().ok()?;
    (1990..=2100).contains(&year).then_some(year)
}

/// Parses the answer of `GET /v1/breach-analytics?email=...`.
pub fn parse_analytics(status: u32, body: &[u8]) -> Result<EmailResult, BreachError> {
    match status {
        200 => {}
        404 => return Ok(EmailResult::NotFound),
        429 => return Err(BreachError::RateLimited),
        other => return Err(BreachError::Service(other)),
    }
    let parsed: Analytics = serde_json::from_slice(body).map_err(|_| BreachError::Malformed)?;
    if let Some(e) = &parsed.error {
        return if e.to_lowercase().contains("not found") {
            Ok(EmailResult::NotFound)
        } else if e.to_lowercase().contains("rate") || e.to_lowercase().contains("limit") {
            Err(BreachError::RateLimited)
        } else {
            Err(BreachError::Malformed)
        };
    }
    let Some(exposed) = parsed.exposed else {
        // The "nothing found" shape: null details and an empty summary.
        return match parsed.summary {
            Some(s) if s.site.trim().is_empty() => Ok(EmailResult::NotFound),
            _ => Err(BreachError::Malformed),
        };
    };
    let mut breaches: Vec<Breach> = exposed
        .breaches_details
        .into_iter()
        .take(MAX_BREACHES)
        .map(|d| Breach {
            name: util::clean_remote(&d.breach, 80),
            domain: util::host_of(&util::clean_remote(&d.domain, 120)),
            year: value_to_year(&d.xposed_date),
            records: value_to_u64(&d.xposed_records),
            exposed: d
                .xposed_data
                .split(';')
                .map(|s| util::clean_remote(s, 40))
                .filter(|s| !s.is_empty())
                .take(24)
                .collect(),
            industry: util::clean_remote(&d.industry, 60),
            password_risk: util::clean_remote(&d.password_risk, 40),
            description: util::clean_remote(&d.details, 600),
        })
        .filter(|b| !b.name.is_empty())
        .collect();
    if breaches.is_empty() {
        return Ok(EmailResult::NotFound);
    }
    breaches.sort_by(|a, b| b.year.cmp(&a.year).then(a.name.cmp(&b.name)));
    Ok(EmailResult::Found(breaches))
}

/// Looks one email address up. Blocking: call from a worker thread, paced
/// with a [`crate::net::Throttle`] of [`GAP_MS`].
pub fn lookup(email: &str) -> Result<EmailResult, BreachError> {
    let email = email.trim().to_lowercase();
    if !crate::model::looks_like_email(&email) {
        return Err(BreachError::BadEmail);
    }
    let path = format!(
        "/v1/breach-analytics?email={}",
        crate::totp::percent_encode(&email)
    );
    let response =
        crate::net::https_get(HOST, &path, &["Accept: application/json"], 8 * 1024 * 1024)
            .map_err(|e| BreachError::Net(e.to_string()))?;
    parse_analytics(response.status, &response.body)
}

// --------------------------------------------------------------------------------------
// Matching breaches to vault items
// --------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemFlag {
    pub item: Id,
    pub title: String,
    /// The saved password was last changed before the breach (or the breach
    /// year is unknown): it should be changed.
    pub change_password: bool,
}

fn squash(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Whether a login belongs to the breached site: its URL is on the breached
/// domain, or its title is the breach's name.
pub fn item_matches(item: &crate::model::Item, breach: &Breach) -> bool {
    if !breach.domain.is_empty() {
        let target = util::base_domain(&breach.domain);
        if item
            .urls
            .iter()
            .any(|u| util::base_domain(&util::host_of(u)) == target)
        {
            return true;
        }
    }
    // Breach names carry suffixes such as "-2024" or "-Scraped".
    let name = squash(breach.name.split('-').next().unwrap_or(""));
    let title = squash(&item.title);
    name.len() >= 4 && (title == name || (name.len() >= 5 && title.starts_with(&name)))
}

/// The logins that belong to a breached site, with whether the password
/// predates the breach.
pub fn matching_items(vault: &Vault, breach: &Breach) -> Vec<ItemFlag> {
    vault
        .items
        .iter()
        .filter(|i| i.kind == Kind::Login && !i.in_trash() && item_matches(i, breach))
        .map(|i| ItemFlag {
            item: i.id,
            title: i.title.clone(),
            change_password: match breach.cutoff() {
                Some(cutoff) => i.password_changed < cutoff,
                None => true,
            },
        })
        .collect()
}

/// Ids of all logins that should get a new password, over a set of results.
pub fn items_to_change<'a>(vault: &Vault, results: impl Iterator<Item = &'a Breach>) -> Vec<Id> {
    let mut out: Vec<Id> = Vec::new();
    for breach in results {
        for flag in matching_items(vault, breach) {
            if flag.change_password && !out.contains(&flag.item) {
                out.push(flag.item);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Item;

    const FOUND: &str = r#"{"BreachMetrics":{"get_details":[],"risk":[{"risk_label":"High","risk_score":70}]},
      "BreachesSummary":{"site":"PhotoCloud;ExampleShop-2021"},
      "ExposedBreaches":{"breaches_details":[
        {"breach":"PhotoCloud","details":"Photo Cloud, an image host, was breached in 2019.\u0007 <b>Not HTML</b>",
         "domain":"photocloud.example","industry":"Information Technology","logo":"https://example.invalid/x.png",
         "password_risk":"plaintext","references":"","searchable":"Yes","verified":"Yes",
         "xposed_data":"Email addresses;Passwords;Usernames","xposed_date":"2019","xposed_records":1234567,
         "added":"2019-06-01T00:00:00+00:00"},
        {"breach":"ExampleShop-2021","details":"A shop.","domain":"www.shop.example","industry":"Retail",
         "password_risk":"unknown","xposed_data":"Email addresses;Phone numbers","xposed_date":2021,
         "xposed_records":"5000"}
      ]},
      "ExposedPastes":null,"PasteMetrics":null,"PastesSummary":{"cnt":0,"domain":"","tmpstmp":""}}"#;

    #[test]
    fn parses_found() {
        let EmailResult::Found(list) = parse_analytics(200, FOUND.as_bytes()).unwrap() else {
            panic!("expected breaches");
        };
        assert_eq!(list.len(), 2);
        // Newest first.
        assert_eq!(list[0].name, "ExampleShop-2021");
        assert_eq!(list[0].domain, "shop.example");
        assert_eq!(list[0].records, 5000);
        assert_eq!(list[0].year, Some(2021));
        assert!(!list[0].exposes_passwords());
        let p = &list[1];
        assert_eq!(p.name, "PhotoCloud");
        assert_eq!(p.records, 1_234_567);
        assert_eq!(p.exposed, vec!["Email addresses", "Passwords", "Usernames"]);
        assert!(p.exposes_passwords());
        // Control characters are removed; markup stays plain text.
        assert!(!p.description.contains('\u{7}'));
        assert!(p.description.contains("<b>Not HTML</b>"));
        assert_eq!(
            p.cutoff(),
            Some(util::days_from_civil(2020, 1, 1) * util::DAY)
        );
    }

    #[test]
    fn parses_not_found_shapes() {
        // The live service answers 200 with this body for an unknown address.
        let empty = br#"{"BreachMetrics":null,"BreachesSummary":{"site":""},"ExposedBreaches":null,"ExposedPastes":null,"PasteMetrics":null,"PastesSummary":{"cnt":0,"domain":"","tmpstmp":""}}"#;
        assert_eq!(parse_analytics(200, empty), Ok(EmailResult::NotFound));
        assert_eq!(
            parse_analytics(200, br#"{"Error":"Not found","email":null}"#),
            Ok(EmailResult::NotFound)
        );
        assert_eq!(parse_analytics(404, b"whatever"), Ok(EmailResult::NotFound));
        assert_eq!(
            parse_analytics(
                200,
                br#"{"ExposedBreaches":{"breaches_details":[]},"BreachesSummary":{"site":""}}"#
            ),
            Ok(EmailResult::NotFound)
        );
    }

    #[test]
    fn rate_limits_and_malformed() {
        assert_eq!(
            parse_analytics(429, br#"{"detail":"Rate limit exceeded"}"#),
            Err(BreachError::RateLimited)
        );
        assert_eq!(
            parse_analytics(200, br#"{"Error":"Rate limit exceeded"}"#),
            Err(BreachError::RateLimited)
        );
        assert_eq!(parse_analytics(500, b""), Err(BreachError::Service(500)));
        for bad in [
            &b"<html>busy</html>"[..],
            b"",
            b"[]",
            b"{}",
            br#"{"ExposedBreaches":{"breaches_details":"x"}}"#,
            br#"{"ExposedBreaches":{"breaches_details":[{"details":"no name"}]}}"#,
            br#"{"ExposedBreaches":null,"BreachesSummary":{"site":"Something"}}"#,
            br#"{"Error":"Something else"}"#,
        ] {
            assert_eq!(
                parse_analytics(200, bad),
                Err(BreachError::Malformed),
                "{bad:?}"
            );
        }
        assert_eq!(lookup("not an email"), Err(BreachError::BadEmail));
        // Long remote strings are cut.
        let long = format!(
            r#"{{"ExposedBreaches":{{"breaches_details":[{{"breach":"{}","details":"{}"}}]}}}}"#,
            "N".repeat(500),
            "d".repeat(5000)
        );
        let EmailResult::Found(list) = parse_analytics(200, long.as_bytes()).unwrap() else {
            panic!()
        };
        assert_eq!(list[0].name.chars().count(), 80);
        assert_eq!(list[0].description.chars().count(), 600);
        assert_eq!(list[0].year, None);
    }

    #[test]
    fn flags_items_changed_before_the_breach() {
        let EmailResult::Found(list) = parse_analytics(200, FOUND.as_bytes()).unwrap() else {
            panic!()
        };
        let photo = &list[1];
        let mut v = Vault::new("t", 0);
        let mut old = Item::new(Kind::Login, 0);
        old.title = "My photos".into();
        old.urls = vec!["https://app.photocloud.example/login".into()];
        old.password_changed = util::days_from_civil(2018, 5, 1) * util::DAY;
        let mut fresh = Item::new(Kind::Login, 0);
        fresh.title = "Photo Cloud".into();
        fresh.password_changed = util::days_from_civil(2022, 5, 1) * util::DAY;
        let mut other = Item::new(Kind::Login, 0);
        other.title = "Example Mail".into();
        other.urls = vec!["https://mail.example.com".into()];
        let mut trashed = old.clone();
        trashed.id = Id::random();
        trashed.deleted = Some(1);
        let (old_id, fresh_id) = (old.id, fresh.id);
        v.items = vec![old, fresh, other, trashed];
        let flags = matching_items(&v, photo);
        assert_eq!(flags.len(), 2);
        assert_eq!((flags[0].item, flags[0].change_password), (old_id, true));
        assert_eq!((flags[1].item, flags[1].change_password), (fresh_id, false));
        assert_eq!(items_to_change(&v, list.iter()), vec![old_id]);
    }
}
