//! Time-based one-time passwords (RFC 6238) and `otpauth://` URIs.

use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algo {
    Sha1,
    Sha256,
    Sha512,
}

impl Algo {
    pub fn label(self) -> &'static str {
        match self {
            Algo::Sha1 => "SHA1",
            Algo::Sha256 => "SHA256",
            Algo::Sha512 => "SHA512",
        }
    }
}

pub struct Totp {
    pub secret: Zeroizing<Vec<u8>>,
    pub algo: Algo,
    pub digits: u32,
    pub period: u64,
    pub issuer: String,
    pub account: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TotpError {
    Empty,
    BadSecret,
    BadUri,
    Unsupported,
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            TotpError::Empty => "No authenticator secret.",
            TotpError::BadSecret => {
                "The authenticator secret is not valid base32 (letters A–Z and digits 2–7)."
            }
            TotpError::BadUri => "This is not a valid otpauth:// link.",
            TotpError::Unsupported => {
                "This authenticator setting is not supported (only time-based codes with 6–8 digits and a 30 or 60 second period)."
            }
        })
    }
}

/// Decodes RFC 4648 base32, ignoring spaces, dashes, padding and case.
pub fn base32_decode(text: &str) -> Option<Zeroizing<Vec<u8>>> {
    let mut out = Zeroizing::new(Vec::with_capacity(text.len() * 5 / 8 + 1));
    let mut acc: u64 = 0;
    let mut bits = 0u32;
    let mut any = false;
    for c in text.chars() {
        let v = match c {
            'A'..='Z' => c as u64 - 'A' as u64,
            'a'..='z' => c as u64 - 'a' as u64,
            '2'..='7' => c as u64 - '2' as u64 + 26,
            ' ' | '-' | '=' | '\t' | '\r' | '\n' => continue,
            _ => return None,
        };
        any = true;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    (any && !out.is_empty()).then_some(out)
}

/// Encodes bytes as base32 without padding.
pub fn base32_encode(bytes: &[u8]) -> Zeroizing<String> {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = Zeroizing::new(String::with_capacity(bytes.len() * 8 / 5 + 1));
    let mut acc: u32 = 0;
    let mut bits = 0;
    for b in bytes {
        acc = (acc << 8) | *b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[(acc >> bits) as usize & 31] as char);
        }
    }
    if bits > 0 {
        out.push(A[(acc << (5 - bits)) as usize & 31] as char);
    }
    out
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&text[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 3;
                    continue;
                }
                Err(_) => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

impl Totp {
    /// Parses an `otpauth://totp/...` URI or a bare base32 secret
    /// (which means SHA-1, 6 digits, 30 seconds).
    pub fn parse(text: &str) -> Result<Totp, TotpError> {
        let t = text.trim();
        if t.is_empty() {
            return Err(TotpError::Empty);
        }
        if !t.to_ascii_lowercase().starts_with("otpauth://") {
            return Ok(Totp {
                secret: base32_decode(t).ok_or(TotpError::BadSecret)?,
                algo: Algo::Sha1,
                digits: 6,
                period: 30,
                issuer: String::new(),
                account: String::new(),
            });
        }
        let rest = &t["otpauth://".len()..];
        let (kind_and_label, query) = rest.split_once('?').ok_or(TotpError::BadUri)?;
        let (kind, label) = kind_and_label
            .split_once('/')
            .unwrap_or((kind_and_label, ""));
        if !kind.eq_ignore_ascii_case("totp") {
            return Err(TotpError::Unsupported);
        }
        let label = percent_decode(label);
        let (mut issuer, account) = match label.split_once(':') {
            Some((i, a)) => (i.trim().to_string(), a.trim().to_string()),
            None => (String::new(), label.trim().to_string()),
        };
        let mut secret = None;
        let mut algo = Algo::Sha1;
        let mut digits = 6u32;
        let mut period = 30u64;
        for pair in query.split('&') {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let v = percent_decode(v);
            match k.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(base32_decode(&v).ok_or(TotpError::BadSecret)?),
                "issuer" => issuer = v,
                "algorithm" => {
                    algo = match v.to_ascii_uppercase().replace('-', "").as_str() {
                        "SHA1" => Algo::Sha1,
                        "SHA256" => Algo::Sha256,
                        "SHA512" => Algo::Sha512,
                        _ => return Err(TotpError::Unsupported),
                    }
                }
                "digits" => digits = v.parse().map_err(|_| TotpError::BadUri)?,
                "period" => period = v.parse().map_err(|_| TotpError::BadUri)?,
                _ => {}
            }
        }
        if !(6..=8).contains(&digits) || !(period == 30 || period == 60) {
            return Err(TotpError::Unsupported);
        }
        Ok(Totp {
            secret: secret.ok_or(TotpError::BadUri)?,
            algo,
            digits,
            period,
            issuer,
            account,
        })
    }

    /// The code for a Unix time.
    pub fn code_at(&self, unix: u64) -> String {
        let counter = (unix / self.period).to_be_bytes();
        let digest: Zeroizing<Vec<u8>> = Zeroizing::new(match self.algo {
            Algo::Sha1 => {
                let mut m = <Hmac<Sha1> as Mac>::new_from_slice(&self.secret).expect("any key");
                m.update(&counter);
                m.finalize().into_bytes().to_vec()
            }
            Algo::Sha256 => {
                let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.secret).expect("any key");
                m.update(&counter);
                m.finalize().into_bytes().to_vec()
            }
            Algo::Sha512 => {
                let mut m = <Hmac<Sha512> as Mac>::new_from_slice(&self.secret).expect("any key");
                m.update(&counter);
                m.finalize().into_bytes().to_vec()
            }
        });
        let offset = (digest[digest.len() - 1] & 0x0f) as usize;
        let bin = ((digest[offset] as u32 & 0x7f) << 24)
            | ((digest[offset + 1] as u32) << 16)
            | ((digest[offset + 2] as u32) << 8)
            | digest[offset + 3] as u32;
        let code = bin as u64 % 10u64.pow(self.digits);
        format!("{code:0width$}", width = self.digits as usize)
    }

    /// Seconds until the current code changes.
    pub fn remaining(&self, unix: u64) -> u64 {
        self.period - unix % self.period
    }

    /// An `otpauth://` URI for moving the code to another device.
    pub fn to_uri(&self, fallback_label: &str) -> Zeroizing<String> {
        let account = if self.account.is_empty() {
            fallback_label
        } else {
            &self.account
        };
        let label = if self.issuer.is_empty() {
            percent_encode(account)
        } else {
            format!(
                "{}:{}",
                percent_encode(&self.issuer),
                percent_encode(account)
            )
        };
        let mut uri = Zeroizing::new(String::with_capacity(160 + self.secret.len() * 2));
        uri.push_str("otpauth://totp/");
        uri.push_str(&label);
        uri.push_str("?secret=");
        uri.push_str(&base32_encode(&self.secret));
        if !self.issuer.is_empty() {
            uri.push_str("&issuer=");
            uri.push_str(&percent_encode(&self.issuer));
        }
        uri.push_str(&format!(
            "&algorithm={}&digits={}&period={}",
            self.algo.label(),
            self.digits,
            self.period
        ));
        uri
    }
}

/// `123 456` / `1234 5678` for display.
pub fn spaced(code: &str) -> String {
    let mid = code.len() / 2;
    format!("{} {}", &code[..mid], &code[mid..])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn totp(secret: &[u8], algo: Algo) -> Totp {
        Totp {
            secret: Zeroizing::new(secret.to_vec()),
            algo,
            digits: 8,
            period: 30,
            issuer: String::new(),
            account: String::new(),
        }
    }

    #[test]
    fn rfc6238_vectors() {
        let s1 = totp(b"12345678901234567890", Algo::Sha1);
        let s256 = totp(b"12345678901234567890123456789012", Algo::Sha256);
        let s512 = totp(
            b"1234567890123456789012345678901234567890123456789012345678901234",
            Algo::Sha512,
        );
        let table: [(u64, &str, &str, &str); 6] = [
            (59, "94287082", "46119246", "90693936"),
            (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"),
            (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"),
            (20000000000, "65353130", "77737706", "47863826"),
        ];
        for (t, a, b, c) in table {
            assert_eq!(s1.code_at(t), a);
            assert_eq!(s256.code_at(t), b);
            assert_eq!(s512.code_at(t), c);
        }
        assert_eq!(s1.remaining(59), 1);
        assert_eq!(s1.remaining(60), 30);
    }

    #[test]
    fn base32() {
        assert_eq!(
            &base32_decode("JBSWY3DPEHPK3PXP").unwrap()[..],
            b"Hello!\xde\xad\xbe\xef"
        );
        assert_eq!(
            &base32_decode("jbsw y3dp-ehpk 3pxp==").unwrap()[..],
            b"Hello!\xde\xad\xbe\xef"
        );
        assert_eq!(&base32_decode("MZXW6YTBOI").unwrap()[..], b"foobar");
        assert!(base32_decode("JBSWY3DPEHPK3PX1").is_none());
        assert!(base32_decode("").is_none());
        assert_eq!(base32_encode(b"foobar").as_str(), "MZXW6YTBOI");
        assert_eq!(
            base32_encode(b"Hello!\xde\xad\xbe\xef").as_str(),
            "JBSWY3DPEHPK3PXP"
        );
    }

    #[test]
    fn otpauth_parsing() {
        let t = Totp::parse(
            "otpauth://totp/Example%20Mail:alex%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example%20Mail&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(t.issuer, "Example Mail");
        assert_eq!(t.account, "alex@example.com");
        assert_eq!(t.algo, Algo::Sha256);
        assert_eq!((t.digits, t.period), (8, 60));
        assert_eq!(&t.secret[..], b"Hello!\xde\xad\xbe\xef");

        let bare = Totp::parse("  jbsw y3dp ehpk 3pxp ").unwrap();
        assert_eq!((bare.algo, bare.digits, bare.period), (Algo::Sha1, 6, 30));
        assert_eq!(bare.code_at(0).len(), 6);

        let minimal = Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP").unwrap();
        assert_eq!(minimal.account, "x");
        assert_eq!(minimal.issuer, "");

        assert_eq!(Totp::parse("").err(), Some(TotpError::Empty));
        assert_eq!(
            Totp::parse("not base32 !").err(),
            Some(TotpError::BadSecret)
        );
        assert_eq!(
            Totp::parse("otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP&counter=1").err(),
            Some(TotpError::Unsupported)
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=9").err(),
            Some(TotpError::Unsupported)
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&period=45").err(),
            Some(TotpError::Unsupported)
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?issuer=a").err(),
            Some(TotpError::BadUri)
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x").err(),
            Some(TotpError::BadUri)
        );
        assert_eq!(
            Totp::parse("otpauth://totp/x?secret=%%&x").err(),
            Some(TotpError::BadSecret)
        );

        // Round trip through a generated URI.
        let uri = t.to_uri("fallback");
        let again = Totp::parse(&uri).unwrap();
        assert_eq!(again.code_at(1_700_000_000), t.code_at(1_700_000_000));
        assert_eq!(again.issuer, "Example Mail");
        assert_eq!(spaced("123456"), "123 456");
    }
}
