//! Plaintext export (CSV and JSON). The output contains every secret in
//! the clear, so the UI puts a strong warning in front of it.

use crate::model::{Item, Vault};
use crate::secret::SecretBuf;
use crate::util;

/// Makes one CSV cell. Cells that a spreadsheet would run as a formula
/// (starting with `=`, `+`, `-`, `@`, tab or carriage return) get a leading
/// apostrophe, and so do cells that already start with one, so that the
/// guard can be removed again without ambiguity when importing.
pub fn csv_cell(text: &str) -> String {
    let risky = matches!(
        text.chars().next(),
        Some('=' | '+' | '-' | '@' | '\t' | '\r' | '\'')
    );
    let mut out = String::with_capacity(text.len() + 3);
    let needs_quotes = risky || text.contains([',', '"', '\n', '\r', ';']) || text != text.trim();
    if needs_quotes {
        out.push('"');
    }
    if risky {
        out.push('\'');
    }
    for c in text.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    if needs_quotes {
        out.push('"');
    }
    out
}

pub const CSV_HEADER: &str =
    "type,title,username,password,url,totp,notes,folder,tags,favourite,fields";

fn kind_word(item: &Item) -> &'static str {
    match item.kind {
        crate::model::Kind::Login => "login",
        crate::model::Kind::Card => "card",
        crate::model::Kind::Identity => "identity",
        crate::model::Kind::Note => "note",
        crate::model::Kind::Wifi => "wifi",
        crate::model::Kind::Licence => "licence",
    }
}

fn push_cells(out: &mut SecretBuf, cells: &[&str]) {
    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            out.extend(b",");
        }
        let mut c = csv_cell(cell);
        out.extend(c.as_bytes());
        zeroize::Zeroize::zeroize(&mut c);
    }
    out.extend(b"\r\n");
}

/// All items outside the trash as CSV (UTF-8 with a byte-order mark so
/// spreadsheets read non-English text correctly).
pub fn to_csv(vault: &Vault) -> SecretBuf {
    let mut out = SecretBuf::with_capacity(64 * 1024);
    out.extend("\u{FEFF}".as_bytes());
    out.extend(CSV_HEADER.as_bytes());
    out.extend(b"\r\n");
    for item in vault.items.iter().filter(|i| !i.in_trash()) {
        let password = item.password.open_str();
        let totp = item.totp.open_str();
        let notes = item.notes.open_str();
        let mut fields = zeroize::Zeroizing::new(String::new());
        for f in item.fields.iter().filter(|f| !f.is_blank()) {
            if !fields.is_empty() {
                fields.push('\n');
            }
            fields.push_str(&f.label.replace(['\n', '\r'], " "));
            if f.hidden {
                fields.push_str(" (hidden)");
            }
            fields.push_str(": ");
            fields.push_str(&f.text().replace(['\n', '\r'], " "));
        }
        push_cells(
            &mut out,
            &[
                kind_word(item),
                &item.title,
                &item.username,
                &password,
                &item.urls.join("\n"),
                &totp,
                &notes,
                vault.folder_name(item.folder).unwrap_or(""),
                &item.tags.join(";"),
                if item.favourite { "1" } else { "" },
                &fields,
            ],
        );
    }
    out
}

/// All items outside the trash as JSON. This keeps everything except
/// attachment contents (their names are listed).
pub fn to_json(vault: &Vault) -> SecretBuf {
    use serde_json::{json, Value};
    let items: Vec<Value> = vault
        .items
        .iter()
        .filter(|i| !i.in_trash())
        .map(|i| {
            json!({
                "type": kind_word(i),
                "title": i.title,
                "username": i.username,
                "password": i.password.open_str().as_str(),
                "urls": i.urls,
                "totp": i.totp.open_str().as_str(),
                "notes": i.notes.open_str().as_str(),
                "folder": vault.folder_name(i.folder).unwrap_or(""),
                "tags": i.tags,
                "favourite": i.favourite,
                "created": util::fmt_iso_date(i.created),
                "modified": util::fmt_iso_date(i.modified),
                "password_changed": util::fmt_iso_date(i.password_changed),
                "expires": i.expires.map(util::fmt_iso_date),
                "fields": i.fields.iter().filter(|f| !f.is_blank()).map(|f| json!({
                    "label": f.label, "hidden": f.hidden, "value": f.text().as_str(),
                })).collect::<Vec<_>>(),
                "password_history": i.history.iter().map(|h| json!({
                    "password": h.password.open_str().as_str(),
                    "replaced": util::fmt_iso_date(h.replaced),
                })).collect::<Vec<_>>(),
                "recovery_codes": i.recovery_codes.iter().map(|c| json!({
                    "code": c.code.open_str().as_str(), "used": c.used,
                })).collect::<Vec<_>>(),
                "attachments": i.attachments.iter().map(|a| a.name.clone()).collect::<Vec<_>>(),
                "autotype": i.autotype,
            })
        })
        .collect();
    let doc = json!({
        "format": "KeepForge plaintext export",
        "version": 1,
        "vault": vault.name,
        "exported": util::fmt_iso_date(util::now()),
        "items": items,
    });
    let mut out = SecretBuf::with_capacity(64 * 1024);
    // Writing into the wiping buffer; the intermediate JSON values are
    // ordinary heap strings that are freed but not wiped (see SECURITY.md).
    let _ = serde_json::to_writer_pretty(&mut out, &doc);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::import;
    use crate::model::{CustomField, Kind};
    use crate::secret::{Protected, SessionKey};

    #[test]
    fn escaping_and_formula_injection() {
        assert_eq!(csv_cell("plain"), "plain");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_cell("two\nlines"), "\"two\nlines\"");
        assert_eq!(csv_cell(" padded "), "\" padded \"");
        for risky in [
            "=1+1",
            "+cmd|' /C calc'!A0",
            "-2+3",
            "@SUM(A1)",
            "\tx",
            "\rx",
            "'quoted",
        ] {
            let cell = csv_cell(risky);
            assert!(cell.starts_with("\"'"), "{risky} -> {cell}");
        }
        assert_eq!(
            csv_cell("=HYPERLINK(\"http://x\")"),
            "\"'=HYPERLINK(\"\"http://x\"\")\""
        );
        assert_eq!(csv_cell(""), "");
    }

    #[test]
    fn csv_round_trip_through_the_importer() {
        let s = SessionKey::new();
        let mut v = Vault::new("Round", 0);
        let work = v.folder_id("Work");
        let mut a = Item::new(Kind::Login, 0);
        a.title = "=Evil, \"Title\"".into();
        a.username = "-alex@example.com".into();
        a.password = Protected::seal_str(&s, "+pa,ss\"wörd'");
        a.urls = vec!["https://a.example".into(), "https://b.example".into()];
        a.totp = Protected::seal_str(&s, "JBSWY3DPEHPK3PXP");
        a.notes = Protected::seal_str(&s, "'note\r\nsecond @line");
        a.folder = work;
        a.tags = vec!["x".into(), "y".into()];
        a.favourite = true;
        a.fields.push(CustomField::hidden(&s, "PIN", "=1234"));
        a.fields.push(CustomField::plain("Plan", "Family"));
        let mut gone = Item::new(Kind::Login, 0);
        gone.title = "In the trash".into();
        gone.deleted = Some(1);
        let mut note = Item::new(Kind::Note, 0);
        note.title = "Note".into();
        note.notes = Protected::seal_str(&s, "@home");
        v.items = vec![a, gone, note];

        let csv = to_csv(&v);
        let text = std::str::from_utf8(csv.as_slice()).unwrap();
        assert!(text.starts_with('\u{FEFF}'));
        assert!(!text.contains("In the trash"));
        // No cell starts with a formula character.
        for row in import::parse_csv(text).iter().skip(1) {
            for cell in row {
                assert!(
                    !cell.starts_with(['=', '+', '-', '@', '\t', '\r']),
                    "{cell}"
                );
            }
        }
        let loaded = import::load(text).unwrap();
        assert_eq!(loaded.format, import::Format::KeepForge);
        let mut back = Vault::new("Back", 0);
        assert_eq!(import::apply(&mut back, &s, &loaded.drafts, &[], 9), 2);
        let b = &back.items[0];
        assert_eq!(b.title, "=Evil, \"Title\"");
        assert_eq!(b.username, "-alex@example.com");
        assert_eq!(b.password.open_str().as_str(), "+pa,ss\"wörd'");
        assert_eq!(b.urls.len(), 2);
        assert_eq!(b.notes.open_str().as_str(), "'note\r\nsecond @line");
        assert_eq!(back.folder_name(b.folder), Some("Work"));
        assert_eq!(b.tags, vec!["x", "y"]);
        assert!(b.favourite);
        assert_eq!(b.fields.len(), 2);
        assert!(b.fields[0].hidden);
        assert_eq!(b.fields[0].text().as_str(), "=1234");
        assert_eq!(back.items[1].kind, Kind::Note);
        assert_eq!(back.items[1].notes.open_str().as_str(), "@home");
    }

    #[test]
    fn json_export_is_valid_and_complete() {
        let s = SessionKey::new();
        let mut v = Vault::new("J", 0);
        let mut a = Item::new(Kind::Login, 0);
        a.title = "Quote \" and \\ slash".into();
        a.set_password(&s, "old", 10);
        a.set_password(&s, "new\n\u{1}", 20);
        v.items.push(a);
        let json = to_json(&v);
        let doc: serde_json::Value = serde_json::from_slice(json.as_slice()).unwrap();
        assert_eq!(doc["items"][0]["title"], "Quote \" and \\ slash");
        assert_eq!(doc["items"][0]["password"], "new\n\u{1}");
        assert_eq!(doc["items"][0]["password_history"][0]["password"], "old");
        assert_eq!(doc["vault"], "J");
    }
}
