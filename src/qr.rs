//! QR codes: the payload formats and the module matrix (drawn by the UI).

use zeroize::Zeroizing;

fn wifi_escape(text: &str) -> Zeroizing<String> {
    let mut out = Zeroizing::new(String::with_capacity(text.len() * 2));
    for c in text.chars() {
        if matches!(c, '\\' | ';' | ',' | ':' | '"') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// The text a phone camera understands as "join this Wi-Fi network".
pub fn wifi_payload(ssid: &str, password: &str, security: &str) -> Zeroizing<String> {
    let s = security.to_lowercase();
    let kind = if password.is_empty() || s.contains("open") || s.contains("none") {
        "nopass"
    } else if s.contains("wep") {
        "WEP"
    } else {
        "WPA"
    };
    let mut out = Zeroizing::new(String::with_capacity(
        32 + ssid.len() * 2 + password.len() * 2,
    ));
    out.push_str("WIFI:T:");
    out.push_str(kind);
    out.push_str(";S:");
    out.push_str(&wifi_escape(ssid));
    out.push(';');
    if kind != "nopass" {
        out.push_str("P:");
        out.push_str(&wifi_escape(password));
        out.push(';');
    }
    out.push(';');
    out
}

/// A QR code as a square grid of dark (true) and light modules.
/// Wiped when dropped, because the pattern encodes the secret.
pub struct Matrix {
    pub width: usize,
    pub dark: Zeroizing<Vec<bool>>,
}

/// Encodes `data`. `None` when it is too long for a QR code (about 2,900 bytes).
pub fn matrix(data: &[u8]) -> Option<Matrix> {
    let code = qrcode::QrCode::with_error_correction_level(data, qrcode::EcLevel::M).ok()?;
    let width = code.width();
    let dark = code
        .to_colors()
        .into_iter()
        .map(|c| c == qrcode::Color::Dark)
        .collect();
    Some(Matrix {
        width,
        dark: Zeroizing::new(dark),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_format() {
        assert_eq!(
            wifi_payload("Morgan-Home", "maple-kettle", "WPA2").as_str(),
            "WIFI:T:WPA;S:Morgan-Home;P:maple-kettle;;"
        );
        assert_eq!(
            wifi_payload("Caf\u{e9}; \"Net\"", "p:a\\s,s;", "WPA3").as_str(),
            "WIFI:T:WPA;S:Caf\u{e9}\\; \\\"Net\\\";P:p\\:a\\\\s\\,s\\;;;"
        );
        assert_eq!(
            wifi_payload("Old", "abcde", "WEP").as_str(),
            "WIFI:T:WEP;S:Old;P:abcde;;"
        );
        assert_eq!(
            wifi_payload("Guest", "", "").as_str(),
            "WIFI:T:nopass;S:Guest;;"
        );
        assert_eq!(
            wifi_payload("Guest", "x", "Open").as_str(),
            "WIFI:T:nopass;S:Guest;;"
        );
    }

    #[test]
    fn matrix_shape() {
        let m = matrix(b"WIFI:T:WPA;S:Morgan-Home;P:maple-kettle;;").unwrap();
        assert!(m.width >= 21);
        assert_eq!(m.dark.len(), m.width * m.width);
        // The three finder patterns: dark corners top-left, top-right, bottom-left.
        assert!(m.dark[0] && m.dark[m.width - 1] && m.dark[m.width * (m.width - 1)]);
        assert!(matrix(&vec![b'x'; 5000]).is_none());
    }
}
