//! Optional check of a password against known breaches, using the
//! Pwned Passwords range API with k-anonymity.
//!
//! What is sent: the first 5 hex characters of the password's SHA-1 hash
//! (one of about a million buckets), to `api.pwnedpasswords.com`, over
//! HTTPS, with padding requested so the answer's size reveals nothing.
//! The password and the rest of the hash never leave this PC: the service
//! answers with every hash suffix in the bucket and the match is done here.

use sha1::{Digest, Sha1};
use std::collections::HashMap;
use zeroize::Zeroizing;

pub const HOST: &str = "api.pwnedpasswords.com";

/// (5-character prefix that is sent, 35-character suffix that is kept).
pub fn hash_parts(password: &str) -> (String, Zeroizing<String>) {
    let digest = Sha1::digest(password.as_bytes());
    let hex = Zeroizing::new(crate::util::hex(&digest).to_uppercase());
    (hex[..5].to_string(), Zeroizing::new(hex[5..].to_string()))
}

/// Finds `suffix` in a range response. Lines are `SUFFIX:COUNT`; padded
/// responses contain invented lines with a count of 0, which are discarded.
pub fn parse_range(body: &str, suffix: &str) -> u64 {
    for line in body.lines() {
        let Some((s, count)) = line.trim().split_once(':') else {
            continue;
        };
        if s.len() != 35 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let count: u64 = count.trim().parse().unwrap_or(0);
        if count == 0 {
            continue;
        }
        if s.eq_ignore_ascii_case(suffix) {
            return count;
        }
    }
    0
}

/// Range responses already fetched in this session (memory only).
#[derive(Default)]
pub struct RangeCache {
    ranges: HashMap<String, String>,
}

impl RangeCache {
    pub fn clear(&mut self) {
        self.ranges.clear();
    }

    /// How many times the password appears in known breaches (0 = not found).
    /// Makes at most one request per 5-character prefix per session.
    pub fn check(&mut self, password: &str) -> Result<u64, String> {
        let (prefix, suffix) = hash_parts(password);
        if let Some(body) = self.ranges.get(&prefix) {
            return Ok(parse_range(body, &suffix));
        }
        let body = fetch_range(&prefix)?;
        let count = parse_range(&body, &suffix);
        self.ranges.insert(prefix, body);
        Ok(count)
    }
}

/// Fetches one range. `prefix` must be exactly five hex characters.
pub fn fetch_range(prefix: &str) -> Result<String, String> {
    if prefix.len() != 5 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("Internal error: bad hash prefix.".into());
    }
    let response = crate::net::https_get(
        HOST,
        &format!("/range/{prefix}"),
        &["Add-Padding: true"],
        4 * 1024 * 1024,
    )
    .map_err(|e| e.to_string())?;
    match response.status {
        200 => String::from_utf8(response.body)
            .map_err(|_| "The breach service sent an unreadable answer.".to_string()),
        429 => Err("The breach service is busy. Try again in a minute.".into()),
        other => Err(format!("The breach service answered with error {other}.")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_split() {
        // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        let (prefix, suffix) = hash_parts("password");
        assert_eq!(prefix, "5BAA6");
        assert_eq!(suffix.as_str(), "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(suffix.len(), 35);
    }

    #[test]
    fn response_parsing_with_padding() {
        let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD8:10434004\r\n\
                    1E4C9B93F3F0682250B6CF8331B7EE68FD9:0\r\n\
                    011053FD0102E94D6AE2F8B83D76FAF94F6:0\r\n\
                    garbage line\r\n\
                    TOOSHORT:5\r\n\
                    012A7CA357541F0AC487871FEEC1891C49C:notanumber\r\n";
        assert_eq!(
            parse_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD8"),
            10_434_004
        );
        assert_eq!(
            parse_range(body, "1e4c9b93f3f0682250b6cf8331b7ee68fd8"),
            10_434_004
        );
        assert_eq!(parse_range(body, "0018A45C4D1DEF81644B54AB7F969B88D65"), 1);
        // A padded (count 0) line is never a hit, even when the suffix matches.
        assert_eq!(parse_range(body, "1E4C9B93F3F0682250B6CF8331B7EE68FD9"), 0);
        assert_eq!(parse_range(body, "011053FD0102E94D6AE2F8B83D76FAF94F6"), 0);
        assert_eq!(parse_range(body, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"), 0);
        assert_eq!(parse_range("", "1E4C9B93F3F0682250B6CF8331B7EE68FD8"), 0);
        assert!(fetch_range("5BAA").is_err());
        assert!(fetch_range("../..").is_err());
    }
}
