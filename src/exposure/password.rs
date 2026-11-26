//! Password checks that never send the password or its full hash: each
//! source gets only the first few characters of a hash, answers with what
//! it knows about that bucket, and the match is made on this PC.

use super::{SourceError, Transport};
use crate::util;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sha3::Keccak512;
use zeroize::Zeroizing;

pub const PWNED_HOST: &str = crate::hibp::HOST;
pub const XON_PASS_HOST: &str = "passwords.xposedornot.com";
pub const ENZOIC_HOST: &str = "api.enzoic.com";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PwSource {
    /// Have I Been Pwned's Pwned Passwords: 5 hex characters of SHA-1.
    PwnedPasswords,
    /// XposedOrNot: 10 hex characters of Keccak-512.
    XposedOrNot,
    /// Enzoic, with the user's own key: 10 hex characters of SHA-256.
    Enzoic,
}

impl PwSource {
    pub const ALL: [PwSource; 3] = [
        PwSource::PwnedPasswords,
        PwSource::XposedOrNot,
        PwSource::Enzoic,
    ];

    /// The settings code. Pwned Passwords keeps its older setting.
    pub fn code(self) -> &'static str {
        match self {
            PwSource::PwnedPasswords => "pw-pwnedpasswords",
            PwSource::XposedOrNot => "pw-xposedornot",
            PwSource::Enzoic => "pw-enzoic",
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            PwSource::PwnedPasswords => "Pwned Passwords",
            PwSource::XposedOrNot => "XposedOrNot passwords",
            PwSource::Enzoic => "Enzoic",
        }
    }

    pub fn home(self) -> &'static str {
        match self {
            PwSource::PwnedPasswords => "https://haveibeenpwned.com/Passwords",
            PwSource::XposedOrNot => "https://xposedornot.com",
            PwSource::Enzoic => "https://www.enzoic.com",
        }
    }

    pub fn key_name(self) -> Option<&'static str> {
        match self {
            PwSource::Enzoic => Some("enzoic-api-key"),
            _ => None,
        }
    }

    pub fn key_page(self) -> &'static str {
        match self {
            PwSource::Enzoic => "https://www.enzoic.com/free-trial/",
            _ => "",
        }
    }

    pub fn sends(self) -> &'static str {
        match self {
            PwSource::PwnedPasswords => "Sends the first 5 characters of the password's SHA-1 hash to api.pwnedpasswords.com (about a million passwords share them). The password never leaves this PC.",
            PwSource::XposedOrNot => "Sends the first 10 characters of the password's Keccak-512 hash to passwords.xposedornot.com. That is more of the hash than Pwned Passwords gets: few passwords share it, so the service could tell whether you checked a common password. The password itself never leaves this PC.",
            PwSource::Enzoic => "Sends the first 10 characters of the password's SHA-256 hash and your own API key to api.enzoic.com. It answers with the full hashes in that bucket; the match is made here. The password never leaves this PC.",
        }
    }

    pub fn gap_ms(self) -> u64 {
        match self {
            PwSource::PwnedPasswords => 120,
            PwSource::XposedOrNot => 600,
            PwSource::Enzoic => 600,
        }
    }
}

/// Keccak-512 (the original padding, as XposedOrNot uses), lower-case hex.
pub fn keccak_hex(password: &str) -> Zeroizing<String> {
    Zeroizing::new(util::hex(&Keccak512::digest(password.as_bytes())))
}

pub fn sha256_hex(password: &str) -> Zeroizing<String> {
    Zeroizing::new(util::hex(&Sha256::digest(password.as_bytes())))
}

/// How many times the password was seen in breaches (0: not found).
pub fn check(
    source: PwSource,
    t: &dyn Transport,
    password: &str,
    key: Option<&str>,
) -> Result<u64, SourceError> {
    if password.is_empty() {
        return Ok(0);
    }
    match source {
        PwSource::PwnedPasswords => {
            let (prefix, suffix) = crate::hibp::hash_parts(password);
            let r = t
                .get(
                    PWNED_HOST,
                    &format!("/range/{prefix}"),
                    &["Add-Padding: true"],
                    4 * 1024 * 1024,
                )
                .map_err(|e| SourceError::Net(e.to_string()))?;
            match r.status {
                200 => Ok(crate::hibp::parse_range(
                    &String::from_utf8_lossy(&r.body),
                    &suffix,
                )),
                429 => Err(SourceError::RateLimited),
                other => Err(SourceError::Service(other)),
            }
        }
        PwSource::XposedOrNot => {
            let full = keccak_hex(password);
            let prefix = &full[..10];
            let r = t
                .get(
                    XON_PASS_HOST,
                    &format!("/api/v1/pass/anon/{prefix}"),
                    &["Accept: application/json"],
                    64 * 1024,
                )
                .map_err(|e| SourceError::Net(e.to_string()))?;
            parse_xon(r.status, &r.body, prefix)
        }
        PwSource::Enzoic => {
            let key = key.map(str::trim).unwrap_or("");
            let Some((id, secret)) = key.split_once(':') else {
                return Err(SourceError::NeedsKey);
            };
            let ok = |s: &str| {
                !s.is_empty() && s.len() <= 200 && s.chars().all(|c| c.is_ascii_graphic())
            };
            if !ok(id) || !ok(secret) {
                return Err(SourceError::BadKey);
            }
            let full = sha256_hex(password);
            let auth = Zeroizing::new(format!(
                "Authorization: Basic {}",
                util::base64(format!("{id}:{secret}").as_bytes())
            ));
            let body = format!(r#"{{"partialSHA256":"{}"}}"#, &full[..10]);
            let r = t
                .post(
                    ENZOIC_HOST,
                    "/v1/passwords",
                    &[
                        auth.as_str(),
                        "Content-Type: application/json",
                        "Accept: application/json",
                    ],
                    body.as_bytes(),
                    4 * 1024 * 1024,
                )
                .map_err(|e| SourceError::Net(e.to_string()))?;
            parse_enzoic(r.status, &r.body, &full)
        }
    }
}

#[derive(Deserialize)]
struct XonAnswer {
    #[serde(rename = "SearchPassAnon")]
    search: Option<XonSearch>,
    #[serde(rename = "Error")]
    error: Option<String>,
}

#[derive(Deserialize)]
struct XonSearch {
    #[serde(default)]
    anon: String,
    #[serde(default)]
    count: serde_json::Value,
}

pub fn parse_xon(status: u32, body: &[u8], prefix: &str) -> Result<u64, SourceError> {
    match status {
        200 => {}
        404 => return Ok(0),
        429 => return Err(SourceError::RateLimited),
        other => return Err(SourceError::Service(other)),
    }
    let a: XonAnswer = serde_json::from_slice(body).map_err(|_| SourceError::Malformed)?;
    if let Some(e) = a.error {
        return if e.to_lowercase().contains("not found") {
            Ok(0)
        } else {
            Err(SourceError::Malformed)
        };
    }
    let s = a.search.ok_or(SourceError::Malformed)?;
    if !s.anon.eq_ignore_ascii_case(prefix) {
        return Err(SourceError::Malformed);
    }
    let count = match &s.count {
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(1),
        serde_json::Value::String(t) => t.trim().parse().unwrap_or(1),
        _ => 1,
    };
    Ok(count.max(1))
}

#[derive(Deserialize)]
struct EnzoicAnswer {
    #[serde(default)]
    candidates: Vec<EnzoicCandidate>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnzoicCandidate {
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    exposure_count: Option<u64>,
    #[serde(default)]
    revealed_in_exposure: Option<bool>,
}

pub fn parse_enzoic(status: u32, body: &[u8], full_sha256: &str) -> Result<u64, SourceError> {
    match status {
        200 => {}
        404 => return Ok(0),
        401 | 403 => return Err(SourceError::BadKey),
        429 => return Err(SourceError::RateLimited),
        other => return Err(SourceError::Service(other)),
    }
    let a: EnzoicAnswer = serde_json::from_slice(body).map_err(|_| SourceError::Malformed)?;
    Ok(a.candidates
        .iter()
        .find(|c| c.sha256.eq_ignore_ascii_case(full_sha256))
        .map(|c| {
            c.exposure_count
                .unwrap_or(0)
                .max(u64::from(c.revealed_in_exposure != Some(false)))
        })
        .unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::super::testing::Recorded;
    use super::*;

    #[test]
    fn hashes_match_published_values() {
        // XposedOrNot's documentation: "123456" -> 808d63ba47...
        assert!(keccak_hex("123456").starts_with("808d63ba47"));
        assert_eq!(
            sha256_hex("password").as_str(),
            "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
        );
    }

    #[test]
    fn pwned_passwords_sends_five_characters() {
        let t = Recorded::new().with(PWNED_HOST, "/range/5BAA6", 200, "1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\n0018A45C4D1DEF81644B54AB7F969B88D65:0\r\n");
        assert_eq!(
            check(PwSource::PwnedPasswords, &t, "password", None),
            Ok(10_434_004)
        );
        assert_eq!(
            t.seen(),
            vec![format!("{PWNED_HOST}/range/5BAA6 | Add-Padding: true")]
        );
    }

    #[test]
    fn xposedornot_sends_ten_characters() {
        let prefix = keccak_hex("123456")[..10].to_string();
        let body = format!(
            r#"{{"SearchPassAnon":{{"anon":"{prefix}","char":"D:6;A:0;S:0;L:6","count":"24230577","wordlist":1}}}}"#
        );
        let t = Recorded::new().with(XON_PASS_HOST, "/api/v1/pass/anon/", 200, &body);
        assert_eq!(
            check(PwSource::XposedOrNot, &t, "123456", None),
            Ok(24_230_577)
        );
        let seen = t.seen();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].starts_with(&format!("{XON_PASS_HOST}/api/v1/pass/anon/{prefix} ")));
        assert!(!seen[0].contains("123456"));
        assert_eq!(parse_xon(404, br#"{"Error":"Not found"}"#, &prefix), Ok(0));
        assert_eq!(parse_xon(200, br#"{"Error":"Not found"}"#, &prefix), Ok(0));
        // An answer for another bucket is not trusted.
        assert_eq!(
            parse_xon(
                200,
                br#"{"SearchPassAnon":{"anon":"0000000000","count":"5"}}"#,
                &prefix
            ),
            Err(SourceError::Malformed)
        );
        assert_eq!(parse_xon(429, b"", &prefix), Err(SourceError::RateLimited));
    }

    #[test]
    fn enzoic_matches_locally() {
        let full = sha256_hex("password");
        let body = format!(
            r#"{{"candidates":[{{"md5":"x","sha1":"y","sha256":"{}","revealedInExposure":true,"exposureCount":12}},{{"sha256":"5e884898da0000","exposureCount":99}}]}}"#,
            full.as_str()
        );
        let t = Recorded::new().with(ENZOIC_HOST, "/v1/passwords", 200, &body);
        assert_eq!(
            check(PwSource::Enzoic, &t, "password", None),
            Err(SourceError::NeedsKey)
        );
        assert_eq!(
            check(PwSource::Enzoic, &t, "password", Some("id-only")),
            Err(SourceError::NeedsKey)
        );
        assert_eq!(
            check(PwSource::Enzoic, &t, "password", Some("id:sec ret")),
            Err(SourceError::BadKey)
        );
        assert!(t.seen().is_empty());
        assert_eq!(
            check(PwSource::Enzoic, &t, "password", Some("myid:mysecret")),
            Ok(12)
        );
        let seen = t.seen();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].contains(r#"body {"partialSHA256":"5e884898da"}"#));
        assert!(seen[0].contains(&format!(
            "Authorization: Basic {}",
            util::base64(b"myid:mysecret")
        )));
        assert!(!seen[0].contains(&full[10..]), "only the prefix is sent");
        assert_eq!(parse_enzoic(404, b"", &full), Ok(0));
        assert_eq!(parse_enzoic(401, b"", &full), Err(SourceError::BadKey));
        assert_eq!(parse_enzoic(200, br#"{"candidates":[]}"#, &full), Ok(0));
    }
}
