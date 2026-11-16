//! Optional "torrent exposure check": what BitTorrent activity is publicly
//! associated with an IP address, according to the iknowwhatyoudownload.com
//! Peer API. Meant for checking your OWN connection (home IP, VPN exit).
//!
//! What is sent: the IP address typed in and the user's own API key, to the
//! API host, over HTTPS. Nothing from the vault is sent. The key is stored
//! only inside the encrypted vault. There is no bulk lookup, no history and
//! no monitoring.
//!
//! The data comes from the public DHT and peer exchange; it is unconfirmed,
//! and shared or dynamic addresses and VPNs mean results may belong to
//! other people.

use crate::util;
use serde::Deserialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const DEFAULT_HOST: &str = "api.antitor.com";
pub const API_PAGE: &str = "https://iknowwhatyoudownload.com/en/api/";
/// Name of the vault's service-key entry that holds the API key.
pub const SERVICE_KEY: &str = "torrent-peer-api-key";
/// Name of the vault's service-key entry that holds a non-default API host.
pub const SERVICE_HOST: &str = "torrent-peer-api-host";
/// At most one request per this many milliseconds.
pub const GAP_MS: u64 = 2000;
pub const MAX_DAYS: u32 = 30;
pub const MAX_CONTENTS: u32 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpProblem {
    NotAnAddress,
    Private,
    Loopback,
    LinkLocal,
    Reserved,
}

impl std::fmt::Display for IpProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            IpProblem::NotAnAddress => "That is not an IP address. Example: 203.0.113.7",
            IpProblem::Private => {
                "That is a private address used inside a home or office network. Enter your public IP address instead."
            }
            IpProblem::Loopback => "That address means \"this computer\". Enter your public IP address instead.",
            IpProblem::LinkLocal => {
                "That is a link-local address that only works on your own network. Enter your public IP address instead."
            }
            IpProblem::Reserved => "That address is reserved and is not used on the public internet.",
        })
    }
}

fn check_v4(ip: Ipv4Addr) -> Result<(), IpProblem> {
    let o = ip.octets();
    if ip.is_loopback() {
        return Err(IpProblem::Loopback);
    }
    if ip.is_private() || (o[0] == 100 && (64..128).contains(&o[1])) {
        return Err(IpProblem::Private);
    }
    if ip.is_link_local() {
        return Err(IpProblem::LinkLocal);
    }
    if ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_documentation()
        || o[0] == 0
        || o[0] >= 240
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
    {
        return Err(IpProblem::Reserved);
    }
    Ok(())
}

fn check_v6(ip: Ipv6Addr) -> Result<(), IpProblem> {
    if let Some(v4) = ip.to_ipv4_mapped() {
        return check_v4(v4);
    }
    let s = ip.segments();
    if ip.is_loopback() {
        return Err(IpProblem::Loopback);
    }
    if s[0] & 0xfe00 == 0xfc00 {
        return Err(IpProblem::Private);
    }
    if s[0] & 0xffc0 == 0xfe80 {
        return Err(IpProblem::LinkLocal);
    }
    if ip.is_unspecified()
        || ip.is_multicast()
        || (s[0] == 0x2001 && s[1] == 0x0db8)
        || s[0] & 0xe000 != 0x2000
    {
        // Only 2000::/3 is global unicast.
        return Err(IpProblem::Reserved);
    }
    Ok(())
}

/// Accepts only public IPv4 / IPv6 addresses.
pub fn validate_ip(text: &str) -> Result<IpAddr, IpProblem> {
    let t = text.trim().trim_start_matches('[').trim_end_matches(']');
    let ip: IpAddr = t.parse().map_err(|_| IpProblem::NotAnAddress)?;
    match ip {
        IpAddr::V4(v4) => check_v4(v4)?,
        IpAddr::V6(v6) => check_v6(v6)?,
    }
    Ok(ip)
}

/// A host name the user may enter instead of the default API host.
pub fn valid_host(host: &str) -> bool {
    let h = host.trim();
    !h.is_empty()
        && h.len() <= 253
        && h.contains('.')
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentClass {
    Normal,
    /// Adult content: shown collapsed behind a toggle.
    Adult,
    /// The worst category: the name is never shown.
    Flagged,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerItem {
    /// Empty for flagged items.
    pub name: String,
    pub category: String,
    pub first_seen: String,
    pub last_seen: String,
    pub size: Option<u64>,
    pub class: ContentClass,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerReport {
    pub ip: String,
    pub isp: String,
    pub country: String,
    pub city: String,
    pub items: Vec<PeerItem>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeerError {
    InvalidIp,
    InvalidDays,
    InvalidContents,
    InvalidLanguage,
    KeyUnknown,
    KeySuspended,
    /// An error code this version does not know.
    Other(String),
    RateLimited,
    Service(u32),
    Malformed,
    Net(String),
    NoKey,
}

impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerError::InvalidIp => f.write_str("The service did not accept this IP address."),
            PeerError::InvalidDays => f.write_str("The service did not accept the number of days."),
            PeerError::InvalidContents => {
                f.write_str("The service did not accept the number of results asked for.")
            }
            PeerError::InvalidLanguage => f.write_str("The service did not accept the language."),
            PeerError::KeyUnknown => f.write_str(
                "The service does not know this API key. Check that it was pasted completely.",
            ),
            PeerError::KeySuspended => f.write_str(
                "This API key has been suspended by the service. Ask them for a new one.",
            ),
            PeerError::Other(code) => write!(f, "The service reported an error: {code}"),
            PeerError::RateLimited => {
                f.write_str("Too many requests. Try again in a little while.")
            }
            PeerError::Service(code) => write!(f, "The service answered with error {code}."),
            PeerError::Malformed => {
                f.write_str("The service sent an answer KeepForge could not read.")
            }
            PeerError::Net(e) => f.write_str(e),
            PeerError::NoKey => f.write_str("Add your API key first."),
        }
    }
}

#[derive(Deserialize)]
struct RawReport {
    #[serde(default)]
    ip: Option<String>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default, rename = "geoData")]
    geo: Option<RawGeo>,
    #[serde(default)]
    contents: Option<Vec<RawContent>>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Deserialize)]
struct RawGeo {
    #[serde(default)]
    country: Option<String>,
    #[serde(default)]
    city: Option<String>,
}

#[derive(Deserialize)]
struct RawContent {
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default, rename = "startDate")]
    start: Option<String>,
    #[serde(default, rename = "endDate")]
    end: Option<String>,
    #[serde(default)]
    torrent: Option<RawTorrent>,
}

#[derive(Deserialize)]
struct RawTorrent {
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    name: Option<String>,
}

fn classify(category: &str) -> ContentClass {
    let c: String = category
        .chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();
    if c.contains("child") {
        ContentClass::Flagged
    } else if c == "xxx" || c.contains("porn") || c.contains("adult") {
        ContentClass::Adult
    } else {
        ContentClass::Normal
    }
}

/// `2016-12-17T16:49:04.000Z` → `2016-12-17`.
fn date_only(text: &str) -> String {
    let t = util::clean_remote(text, 40);
    match t.get(..10) {
        Some(d) if d.bytes().all(|b| b.is_ascii_digit() || b == b'-') => d.to_string(),
        _ => String::new(),
    }
}

/// Parses the answer of `GET /history/peer`.
pub fn parse(status: u32, body: &[u8]) -> Result<PeerReport, PeerError> {
    if status == 429 {
        return Err(PeerError::RateLimited);
    }
    let raw: RawReport = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(_) if status != 200 => return Err(PeerError::Service(status)),
        Err(_) => return Err(PeerError::Malformed),
    };
    if let Some(code) = raw.error {
        return Err(match code.trim() {
            "INVALID_IP" => PeerError::InvalidIp,
            "INVALID_DAYS" => PeerError::InvalidDays,
            "INVALID_CONTENTS" => PeerError::InvalidContents,
            "INVALID_LANGUAGE" => PeerError::InvalidLanguage,
            "API_KEY_UNKNOWN" => PeerError::KeyUnknown,
            "API_KEY_SUSPENDED" => PeerError::KeySuspended,
            other => PeerError::Other(util::clean_remote(other, 60)),
        });
    }
    if status != 200 {
        return Err(PeerError::Service(status));
    }
    let (Some(ip), Some(contents)) = (raw.ip, raw.contents) else {
        return Err(PeerError::Malformed);
    };
    let items = contents
        .into_iter()
        .take(MAX_CONTENTS as usize)
        .map(|c| {
            let category = util::clean_remote(c.category.as_deref().unwrap_or(""), 30);
            let class = classify(&category);
            let flagged = class == ContentClass::Flagged;
            let torrent_name = c.torrent.as_ref().and_then(|t| t.name.clone());
            let name = c.name.or(torrent_name).unwrap_or_default();
            PeerItem {
                // Names of flagged items are dropped here, at the parser, so
                // they never reach the rest of the program.
                name: if flagged {
                    String::new()
                } else {
                    util::clean_remote(&name, 160)
                },
                category: if flagged { String::new() } else { category },
                first_seen: date_only(c.start.as_deref().unwrap_or("")),
                last_seen: date_only(c.end.as_deref().unwrap_or("")),
                size: if flagged {
                    None
                } else {
                    c.torrent.as_ref().and_then(|t| t.size)
                },
                class,
            }
        })
        .collect::<Vec<_>>();
    Ok(PeerReport {
        ip: util::clean_remote(&ip, 45),
        isp: util::clean_remote(raw.isp.as_deref().unwrap_or(""), 100),
        country: util::clean_remote(
            raw.geo
                .as_ref()
                .and_then(|g| g.country.as_deref())
                .unwrap_or(""),
            60,
        ),
        city: util::clean_remote(
            raw.geo
                .as_ref()
                .and_then(|g| g.city.as_deref())
                .unwrap_or(""),
            60,
        ),
        items,
    })
}

/// The request path for one lookup (the key goes in the query, as the API requires).
pub fn request_path(ip: IpAddr, days: u32, key: &str) -> String {
    format!(
        "/history/peer?ip={}&days={}&contents={}&lang=en&key={}",
        crate::totp::percent_encode(&ip.to_string()),
        days.clamp(1, MAX_DAYS),
        MAX_CONTENTS,
        crate::totp::percent_encode(key.trim())
    )
}

/// Looks one address up. Blocking: call from a worker thread.
pub fn lookup(host: &str, ip: IpAddr, days: u32, key: &str) -> Result<PeerReport, PeerError> {
    if key.trim().is_empty() {
        return Err(PeerError::NoKey);
    }
    let host = if valid_host(host) {
        host.trim()
    } else {
        DEFAULT_HOST
    };
    let path = zeroize::Zeroizing::new(request_path(ip, days, key));
    let response =
        crate::net::https_get(host, &path, &["Accept: application/json"], 2 * 1024 * 1024)
            .map_err(|e| PeerError::Net(e.to_string()))?;
    parse(response.status, &response.body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_validation_table() {
        for ok in [
            "8.8.8.8",
            " 1.1.1.1 ",
            "93.184.216.34",
            "2606:4700:4700::1111",
            "[2a00:1450:4001:81b::200e]",
        ] {
            assert!(validate_ip(ok).is_ok(), "{ok}");
        }
        let table = [
            ("", IpProblem::NotAnAddress),
            ("example.com", IpProblem::NotAnAddress),
            ("1.2.3", IpProblem::NotAnAddress),
            ("1.2.3.4/24", IpProblem::NotAnAddress),
            ("256.1.1.1", IpProblem::NotAnAddress),
            ("10.0.0.1", IpProblem::Private),
            ("172.16.5.4", IpProblem::Private),
            ("172.31.255.255", IpProblem::Private),
            ("192.168.1.10", IpProblem::Private),
            ("100.64.0.1", IpProblem::Private),
            ("127.0.0.1", IpProblem::Loopback),
            ("169.254.10.10", IpProblem::LinkLocal),
            ("0.0.0.0", IpProblem::Reserved),
            ("255.255.255.255", IpProblem::Reserved),
            ("224.0.0.1", IpProblem::Reserved),
            ("240.0.0.1", IpProblem::Reserved),
            ("192.0.2.1", IpProblem::Reserved),
            ("203.0.113.7", IpProblem::Reserved),
            ("198.18.0.1", IpProblem::Reserved),
            ("::1", IpProblem::Loopback),
            ("::", IpProblem::Reserved),
            ("fe80::1", IpProblem::LinkLocal),
            ("fd12:3456::1", IpProblem::Private),
            ("ff02::1", IpProblem::Reserved),
            ("2001:db8::1", IpProblem::Reserved),
            ("::ffff:192.168.0.1", IpProblem::Private),
        ];
        for (text, problem) in table {
            assert_eq!(validate_ip(text), Err(problem), "{text}");
        }
        assert!(validate_ip("172.32.0.1").is_ok());
        assert!(validate_ip("100.128.0.1").is_ok());
        assert!(valid_host("api.antitor.com"));
        for bad in [
            "",
            "localhost",
            "a..b",
            "-a.com",
            "a.com/x",
            "a b.com",
            "http://a.com",
        ] {
            assert!(!valid_host(bad), "{bad}");
        }
    }

    const OK: &str = r#"{"ip":"93.184.216.34","isp":"Example Net","hasPorno":true,"hasChildPorno":true,
      "geoData":{"country":"Exampleland","city":"Sampletown","latitude":1.5,"longitude":-2.5},
      "contents":[
        {"category":"Movies","imdbId":"tt0000001","name":"Public-domain film (1925)",
         "startDate":"2026-11-01T16:49:04.000Z","endDate":"2026-11-03T10:00:00.000Z",
         "torrent":{"infohash":"00","size":1572610110,"name":"film.avi"}},
        {"category":"XXX","name":"Adult title","startDate":"2026-11-02T00:00:00.000Z","endDate":"bad",
         "torrent":{"size":5,"name":"a"}},
        {"category":"Child Porno","name":"MUST NEVER BE SHOWN","startDate":"2026-11-02T00:00:00.000Z",
         "endDate":"2026-11-02T00:00:00.000Z","torrent":{"name":"MUST NEVER BE SHOWN EITHER","size":9}},
        {"torrent":{"name":"only a torrent name\u0000"}}
      ]}"#;

    #[test]
    fn parses_success_and_hides_flagged_names() {
        let r = parse(200, OK.as_bytes()).unwrap();
        assert_eq!(r.ip, "93.184.216.34");
        assert_eq!(
            (r.isp.as_str(), r.country.as_str(), r.city.as_str()),
            ("Example Net", "Exampleland", "Sampletown")
        );
        assert_eq!(r.items.len(), 4);
        assert_eq!(r.items[0].name, "Public-domain film (1925)");
        assert_eq!(r.items[0].first_seen, "2026-11-01");
        assert_eq!(r.items[0].last_seen, "2026-11-03");
        assert_eq!(r.items[0].size, Some(1_572_610_110));
        assert_eq!(r.items[0].class, ContentClass::Normal);
        assert_eq!(r.items[1].class, ContentClass::Adult);
        assert_eq!(r.items[1].last_seen, "");
        assert_eq!(r.items[2].class, ContentClass::Flagged);
        assert_eq!(r.items[2].name, "");
        assert_eq!(r.items[2].category, "");
        assert_eq!(r.items[2].size, None);
        assert!(!format!("{r:?}").contains("MUST NEVER"));
        assert_eq!(r.items[3].name, "only a torrent name");
    }

    #[test]
    fn parses_empty_errors_and_malformed() {
        let empty = parse(200, br#"{"ip":"8.8.8.8","isp":null,"hasPorno":false,"hasChildPorno":false,"geoData":null,"contents":[]}"#).unwrap();
        assert!(empty.items.is_empty());
        assert_eq!(empty.isp, "");
        let codes = [
            ("INVALID_IP", PeerError::InvalidIp),
            ("INVALID_DAYS", PeerError::InvalidDays),
            ("INVALID_CONTENTS", PeerError::InvalidContents),
            ("INVALID_LANGUAGE", PeerError::InvalidLanguage),
            ("API_KEY_UNKNOWN", PeerError::KeyUnknown),
            ("API_KEY_SUSPENDED", PeerError::KeySuspended),
            ("SOMETHING_NEW", PeerError::Other("SOMETHING_NEW".into())),
        ];
        for (code, expected) in codes {
            let body = format!(r#"{{"error":"{code}","message":"text"}}"#);
            assert_eq!(parse(200, body.as_bytes()), Err(expected.clone()));
            assert_eq!(parse(500, body.as_bytes()), Err(expected));
        }
        assert_eq!(parse(200, b"<html>"), Err(PeerError::Malformed));
        assert_eq!(parse(200, b"{}"), Err(PeerError::Malformed));
        assert_eq!(
            parse(200, br#"{"ip":"8.8.8.8"}"#),
            Err(PeerError::Malformed)
        );
        assert_eq!(
            parse(200, br#"{"ip":"8.8.8.8","contents":"x"}"#),
            Err(PeerError::Malformed)
        );
        assert_eq!(
            parse(500, b"Internal server error"),
            Err(PeerError::Service(500))
        );
        assert_eq!(parse(429, b""), Err(PeerError::RateLimited));
        assert_eq!(
            lookup(DEFAULT_HOST, validate_ip("8.8.8.8").unwrap(), 14, "  "),
            Err(PeerError::NoKey)
        );
    }

    #[test]
    fn request_path_is_encoded_and_clamped() {
        let ip = validate_ip("2606:4700:4700::1111").unwrap();
        assert_eq!(
            request_path(ip, 99, " k&y=1 "),
            "/history/peer?ip=2606%3A4700%3A4700%3A%3A1111&days=30&contents=100&lang=en&key=k%26y%3D1"
        );
    }
}
