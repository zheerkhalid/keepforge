//! Importing from CSV and JSON exports of browsers and other password
//! managers. Everything is parsed in memory; plaintext cells are wiped when
//! the parsed table is dropped.

use crate::model::{CustomField, Item, Kind, Vault};
use crate::secret::{secret_string, Protected, SecretString, SessionKey};
use crate::util;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

// --------------------------------------------------------------------------------------
// CSV
// --------------------------------------------------------------------------------------

/// A parsed CSV file. Cells are wiped on drop.
pub struct Table {
    pub header: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

impl Drop for Table {
    fn drop(&mut self) {
        for row in &mut self.rows {
            for cell in row {
                cell.zeroize();
            }
        }
    }
}

/// Parses CSV (RFC 4180): quoted cells, doubled quotes, line breaks inside
/// quotes, CRLF or LF, an optional byte-order mark. The separator is the
/// one (comma, semicolon or tab) the header line uses most outside quotes.
pub fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let sep = sniff_separator(text);
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut cell = String::new();
    let mut quoted = false;
    let mut was_quoted = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if quoted {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    cell.push('"');
                } else {
                    quoted = false;
                }
            } else {
                cell.push(c);
            }
            continue;
        }
        match c {
            '"' if cell.is_empty() && !was_quoted => {
                quoted = true;
                was_quoted = true;
            }
            c if c == sep => {
                row.push(std::mem::take(&mut cell));
                was_quoted = false;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' | '\r' => {
                row.push(std::mem::take(&mut cell));
                was_quoted = false;
                // Skip completely empty lines.
                if row.len() > 1 || !row[0].is_empty() {
                    rows.push(std::mem::take(&mut row));
                } else {
                    row.clear();
                }
            }
            other => cell.push(other),
        }
    }
    if !cell.is_empty() || was_quoted || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows
}

/// Picks the separator from the first non-empty line, counting only the
/// candidates that stand outside quoted cells. A comma wins a tie.
fn sniff_separator(text: &str) -> char {
    let (mut commas, mut semicolons, mut tabs) = (0usize, 0usize, 0usize);
    let mut quoted = false;
    let mut seen_any = false;
    for c in text.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                seen_any = true;
            }
            _ if quoted => {}
            '\n' | '\r' => {
                if seen_any {
                    break;
                }
            }
            ',' => commas += 1,
            ';' => semicolons += 1,
            '\t' => tabs += 1,
            _ => {}
        }
        if c != '\n' && c != '\r' {
            seen_any = true;
        }
    }
    if commas >= semicolons && commas >= tabs {
        ','
    } else if semicolons >= tabs {
        ';'
    } else {
        '\t'
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// name, url, username, password[, note]
    BrowserNameFirst,
    /// url, username, password, httpRealm, formActionOrigin, ...
    BrowserUrlFirst,
    /// folder, favorite, type, name, notes, fields, reprompt, login_uri, ...
    ManagerFolderType,
    /// Account, Login Name, Password, Web Site, Comments
    ManagerAccount,
    /// Group, Title, Username, Password, URL, Notes[, TOTP ...]
    ManagerGroupTitle,
    /// Title, Url, Username, Password, OTPAuth, Favorite, Archived, Tags, Notes
    ManagerOtpAuth,
    /// KeepForge's own CSV export.
    KeepForge,
    /// Anything else: the user maps the columns.
    Generic,
    /// JSON export with "items" and "folders".
    ManagerJson,
    /// url, username, password, totp, extra, name, grouping, fav
    ManagerGrouping,
    /// type, name, url, email, username, password, note, totp, createTime,
    /// modifyTime, vault
    ManagerVaultType,
    /// name, url, username, password, note, cardholdername, cardnumber, cvc,
    /// expirydate, zipcode, folder, full_name, phone_number, email, ...
    ManagerCards,
}

impl Format {
    /// A neutral description for the import screen.
    pub fn label(self) -> &'static str {
        match self {
            Format::BrowserNameFirst => "Browser password export (name, url, username, password)",
            Format::BrowserUrlFirst => "Browser password export (url, username, password)",
            Format::ManagerFolderType => "Password manager CSV (folder, type, name, login columns)",
            Format::ManagerAccount => "Password manager CSV (account, login name, web site)",
            Format::ManagerGroupTitle => "Password manager CSV (group, title, username, URL)",
            Format::ManagerOtpAuth => "Password manager CSV (title, url, one-time password, tags)",
            Format::KeepForge => "KeepForge CSV export",
            Format::Generic => "Other CSV file (choose the columns below)",
            Format::ManagerJson => "Password manager JSON export (items and folders)",
            Format::ManagerGrouping => {
                "Password manager CSV (url, username, extra, name, grouping)"
            }
            Format::ManagerVaultType => "Password manager CSV (type, name, email, vault)",
            Format::ManagerCards => {
                "Password manager CSV (logins, cards and addresses in one table)"
            }
        }
    }
}

fn norm(h: &str) -> String {
    h.trim().to_lowercase().replace([' ', '_', '-'], "")
}

/// Recognises the common export shapes by their header row.
pub fn detect(header: &[String]) -> Format {
    let h: Vec<String> = header.iter().map(|x| norm(x)).collect();
    let has = |name: &str| h.iter().any(|x| x == name);
    if has("loginuri") && has("loginusername") && has("loginpassword") {
        Format::ManagerFolderType
    } else if has("otpauth") && has("title") && has("password") {
        Format::ManagerOtpAuth
    } else if has("account") && has("loginname") && has("password") {
        Format::ManagerAccount
    } else if has("group") && has("title") && has("username") && has("password") {
        Format::ManagerGroupTitle
    } else if h.first().map(String::as_str) == Some("type")
        && has("title")
        && has("fields")
        && has("favourite")
    {
        Format::KeepForge
    } else if has("httprealm") || has("formactionorigin") {
        Format::BrowserUrlFirst
    } else if h.first().map(String::as_str) == Some("name")
        && has("url")
        && has("username")
        && has("password")
        && h.len() <= 5
    {
        Format::BrowserNameFirst
    } else if has("cardholdername") && has("cardnumber") && has("name") && has("password") {
        Format::ManagerCards
    } else if h.first().map(String::as_str) == Some("type")
        && has("name")
        && has("email")
        && has("password")
        && has("vault")
    {
        Format::ManagerVaultType
    } else if has("grouping") && has("extra") && has("name") && has("url") && has("password") {
        Format::ManagerGrouping
    } else {
        Format::Generic
    }
}

/// Which column feeds which field, for generic CSV files.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Mapping {
    pub title: Option<usize>,
    pub username: Option<usize>,
    pub password: Option<usize>,
    pub url: Option<usize>,
    pub notes: Option<usize>,
    pub totp: Option<usize>,
    pub folder: Option<usize>,
}

/// A first guess at the mapping from the header names.
pub fn guess_mapping(header: &[String]) -> Mapping {
    let h: Vec<String> = header.iter().map(|x| norm(x)).collect();
    let names: [&[&str]; 7] = [
        &["title", "name", "account", "site", "service", "entry"],
        &["username", "user", "login", "loginname", "email"],
        &["password", "pass", "pwd"],
        &["url", "website", "uri", "link", "address"],
        &["notes", "note", "comments", "comment", "extra"],
        &["totp", "otpauth", "otp", "2fa"],
        &["folder", "group", "category", "grouping"],
    ];
    // Exact header names first, for every field; only then partial matches,
    // which never take a column another field already has (otherwise
    // "username" would also become the title, through "name").
    let mut picked: [Option<usize>; 7] =
        names.map(|list| list.iter().find_map(|n| h.iter().position(|x| x == n)));
    for (slot, list) in names.iter().enumerate() {
        if picked[slot].is_none() {
            let found = list.iter().find_map(|n| {
                h.iter()
                    .enumerate()
                    .position(|(i, x)| x.contains(n) && !picked.contains(&Some(i)))
            });
            picked[slot] = found;
        }
    }
    Mapping {
        title: picked[0],
        username: picked[1],
        password: picked[2],
        url: picked[3],
        notes: picked[4],
        totp: picked[5],
        folder: picked[6],
    }
}

// --------------------------------------------------------------------------------------
// Drafts
// --------------------------------------------------------------------------------------

/// An item about to be imported.
pub struct Draft {
    pub kind: Kind,
    pub title: String,
    pub username: String,
    pub password: SecretString,
    pub urls: Vec<String>,
    pub totp: SecretString,
    pub notes: SecretString,
    pub folder: String,
    pub favourite: bool,
    pub tags: Vec<String>,
    /// (label, value, hidden)
    pub fields: Vec<(String, SecretString, bool)>,
    pub password_changed: Option<i64>,
}

impl Draft {
    fn new(kind: Kind) -> Draft {
        Draft {
            kind,
            title: String::new(),
            username: String::new(),
            password: Zeroizing::new(String::new()),
            urls: Vec::new(),
            totp: Zeroizing::new(String::new()),
            notes: Zeroizing::new(String::new()),
            folder: String::new(),
            favourite: false,
            tags: Vec::new(),
            fields: Vec::new(),
            password_changed: None,
        }
    }

    fn finish(mut self) -> Draft {
        self.urls.retain(|u| !u.trim().is_empty());
        if self.title.trim().is_empty() {
            self.title = self
                .urls
                .first()
                .map(|u| util::host_of(u))
                .filter(|h| !h.is_empty())
                .unwrap_or_else(|| "Untitled".to_string());
        }
        self
    }

    fn is_blank(&self) -> bool {
        self.title.trim().is_empty()
            && self.username.trim().is_empty()
            && self.password.is_empty()
            && self.urls.iter().all(|u| u.trim().is_empty())
            && self.notes.is_empty()
            && self.fields.is_empty()
    }
}

fn truthy(text: &str) -> bool {
    matches!(
        text.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "y"
    )
}

fn kind_from(text: &str) -> Kind {
    match norm(text).as_str() {
        "card" => Kind::Card,
        "identity" => Kind::Identity,
        "note" | "securenote" => Kind::Note,
        "wifi" => Kind::Wifi,
        "licence" | "license" | "licenceorapikey" => Kind::Licence,
        _ => Kind::Login,
    }
}

/// Undoes the formula guard KeepForge's CSV export adds (see `export`).
fn unguard(cell: &str) -> &str {
    cell.strip_prefix('\'').unwrap_or(cell)
}

/// Adds a custom field unless the value is empty.
fn push_field(d: &mut Draft, label: &str, value: String, hidden: bool) {
    if !value.trim().is_empty() {
        d.fields
            .push((label.to_string(), Zeroizing::new(value), hidden));
    }
}

/// Joins the non-empty parts with `sep`.
fn join_parts(parts: &[String], sep: &str) -> String {
    parts
        .iter()
        .map(|p| p.trim())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(sep)
}

/// "3/2029", "03/29" and "03-2029" all become "03/29"; anything else is
/// kept as written.
fn card_expiry(text: &str) -> String {
    let text = text.trim();
    if let Some((m, y)) = text.split_once(['/', '-']) {
        let (m, y) = (m.trim(), y.trim());
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        if digits(m) && digits(y) && m.len() <= 2 && (y.len() == 2 || y.len() == 4) {
            return format!("{m:0>2}/{}", &y[y.len() - 2..]);
        }
    }
    text.to_string()
}

/// A cell holding several addresses: a JSON list of strings, or addresses
/// separated by commas, semicolons, spaces or line breaks.
fn split_urls(cell: &str) -> Vec<String> {
    let cell = cell.trim();
    if cell.starts_with('[') {
        if let Ok(list) = serde_json::from_str::<Vec<String>>(cell) {
            return list;
        }
    }
    cell.split([',', ';', ' ', '\n', '\r'])
        .map(|u| u.trim().to_string())
        .filter(|u| !u.is_empty())
        .collect()
}

/// A "custom fields" cell: a JSON list of `{label, type, value}` objects
/// becomes one field each; anything else is kept whole as one hidden field,
/// so nothing is lost.
fn push_custom_fields(d: &mut Draft, cell: String) {
    if cell.trim().is_empty() {
        return;
    }
    if let Ok(serde_json::Value::Array(list)) =
        serde_json::from_str::<serde_json::Value>(cell.trim())
    {
        let parsed: Vec<(String, String, bool)> = list
            .iter()
            .map(|f| {
                let label = [jstr(f, "label"), jstr(f, "name")]
                    .into_iter()
                    .find(|l| !l.trim().is_empty())
                    .unwrap_or_else(|| "Field".to_string());
                let hidden = jstr(f, "type").eq_ignore_ascii_case("hidden");
                (label, jstr(f, "value"), hidden)
            })
            .collect();
        if !parsed.is_empty() && parsed.iter().all(|(_, value, _)| !value.is_empty()) {
            for (label, value, hidden) in parsed {
                push_field(d, &label, value, hidden);
            }
            return;
        }
    }
    push_field(d, "Custom fields", cell, true);
}

/// Seconds since 1970, if the cell holds a plausible time (before 2100).
fn unix_seconds(cell: &str) -> Option<i64> {
    cell.trim()
        .parse::<i64>()
        .ok()
        .filter(|t| *t > 0 && *t < 4_102_444_800)
}

/// Turns CSV rows into drafts according to the detected format (or the
/// user's mapping for generic files).
pub fn drafts_from_csv(table: &Table, format: Format, mapping: &Mapping) -> Vec<Draft> {
    let h: Vec<String> = table.header.iter().map(|x| norm(x)).collect();
    let col = |name: &str| h.iter().position(|x| x == name);
    let get = |row: &[String], i: Option<usize>| -> String {
        i.and_then(|i| row.get(i)).cloned().unwrap_or_default()
    };
    let mut out = Vec::new();
    for row in &table.rows {
        let mut d = Draft::new(Kind::Login);
        match format {
            Format::BrowserNameFirst => {
                d.title = get(row, col("name"));
                d.urls = vec![get(row, col("url"))];
                d.username = get(row, col("username"));
                d.password = Zeroizing::new(get(row, col("password")));
                d.notes = Zeroizing::new(get(row, col("note").or(col("notes"))));
            }
            Format::BrowserUrlFirst => {
                d.urls = vec![get(row, col("url"))];
                d.username = get(row, col("username"));
                d.password = Zeroizing::new(get(row, col("password")));
                // Milliseconds since 1970.
                d.password_changed = get(row, col("timepasswordchanged"))
                    .trim()
                    .parse::<i64>()
                    .ok()
                    .filter(|ms| *ms > 0)
                    .map(|ms| ms / 1000);
            }
            Format::ManagerFolderType => {
                d.kind = kind_from(&get(row, col("type")));
                d.folder = get(row, col("folder"));
                d.favourite = truthy(&get(row, col("favorite")));
                d.title = get(row, col("name"));
                d.notes = Zeroizing::new(get(row, col("notes")));
                d.urls = get(row, col("loginuri"))
                    .split(',')
                    .map(|u| u.trim().to_string())
                    .collect();
                d.username = get(row, col("loginusername"));
                d.password = Zeroizing::new(get(row, col("loginpassword")));
                d.totp = Zeroizing::new(get(row, col("logintotp")));
                for line in get(row, col("fields")).lines() {
                    if let Some((k, v)) = line.split_once(':') {
                        d.fields
                            .push((k.trim().to_string(), secret_string(v.trim()), false));
                    }
                }
            }
            Format::ManagerAccount => {
                d.title = get(row, col("account"));
                d.username = get(row, col("loginname"));
                d.password = Zeroizing::new(get(row, col("password")));
                d.urls = vec![get(row, col("website"))];
                d.notes = Zeroizing::new(get(row, col("comments")));
            }
            Format::ManagerGroupTitle => {
                d.folder = get(row, col("group"))
                    .rsplit('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
                if d.folder.eq_ignore_ascii_case("root") {
                    d.folder.clear();
                }
                d.title = get(row, col("title"));
                d.username = get(row, col("username"));
                d.password = Zeroizing::new(get(row, col("password")));
                d.urls = vec![get(row, col("url"))];
                d.notes = Zeroizing::new(get(row, col("notes")));
                d.totp = Zeroizing::new(get(row, col("totp")));
            }
            Format::ManagerOtpAuth => {
                d.title = get(row, col("title"));
                d.urls = vec![get(row, col("url").or(col("website")))];
                d.username = get(row, col("username"));
                d.password = Zeroizing::new(get(row, col("password")));
                d.totp = Zeroizing::new(get(row, col("otpauth")));
                d.favourite = truthy(&get(row, col("favorite")));
                d.tags = get(row, col("tags"))
                    .split([';', ','])
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                d.notes = Zeroizing::new(get(row, col("notes")));
            }
            Format::KeepForge => {
                let cell = |name: &str| unguard(&get(row, col(name))).to_string();
                d.kind = kind_from(&cell("type"));
                d.title = cell("title");
                d.username = cell("username");
                d.password = Zeroizing::new(cell("password"));
                d.urls = cell("url").lines().map(str::to_string).collect();
                d.totp = Zeroizing::new(cell("totp"));
                d.notes = Zeroizing::new(cell("notes"));
                d.folder = cell("folder");
                d.tags = cell("tags")
                    .split(';')
                    .map(|t| t.trim().to_string())
                    .filter(|t| !t.is_empty())
                    .collect();
                d.favourite = truthy(&cell("favourite"));
                for line in cell("fields").lines() {
                    if let Some((k, v)) = line.split_once(": ") {
                        let (label, hidden) = match k.strip_suffix(" (hidden)") {
                            Some(l) => (l, true),
                            None => (k, false),
                        };
                        d.fields.push((label.to_string(), secret_string(v), hidden));
                    }
                }
            }
            Format::ManagerGrouping => {
                let url = get(row, col("url"));
                d.title = get(row, col("name"));
                d.username = get(row, col("username"));
                d.password = Zeroizing::new(get(row, col("password")));
                d.totp = Zeroizing::new(get(row, col("totp")));
                d.notes = Zeroizing::new(get(row, col("extra")));
                d.folder = get(row, col("grouping"));
                d.favourite = truthy(&get(row, col("fav")));
                // This placeholder address marks a secure note.
                if url.trim() == "http://sn" {
                    d.kind = Kind::Note;
                } else {
                    d.urls = vec![url];
                }
            }
            Format::ManagerVaultType => {
                // Cards, identities and aliases have no columns of their
                // own here: they come in as logins with their note kept.
                if norm(&get(row, col("type"))) == "note" {
                    d.kind = Kind::Note;
                }
                d.title = get(row, col("name"));
                d.urls = vec![get(row, col("url"))];
                let email = get(row, col("email"));
                d.username = get(row, col("username"));
                if d.username.trim().is_empty() {
                    d.username = email;
                } else if email.trim() != d.username.trim() {
                    push_field(&mut d, "Email", email, false);
                }
                d.password = Zeroizing::new(get(row, col("password")));
                d.notes = Zeroizing::new(get(row, col("note")));
                d.totp = Zeroizing::new(get(row, col("totp")));
                d.folder = get(row, col("vault"));
                d.password_changed = unix_seconds(&get(row, col("modifytime")));
            }
            Format::ManagerCards => {
                let kind_text = norm(&get(row, col("type")));
                if kind_text == "folder" {
                    continue;
                }
                let cell = |name: &str| get(row, col(name));
                let url = cell("url");
                let password = cell("password");
                let card_number = cell("cardnumber");
                let full_name = cell("fullname");
                let email = cell("email");
                let zip = cell("zipcode");
                let address = [
                    cell("address1"),
                    cell("address2"),
                    cell("city"),
                    cell("state"),
                    zip.clone(),
                    cell("country"),
                ];
                let has_address = !join_parts(&address[..4], "").is_empty();
                d.title = cell("name");
                d.username = cell("username");
                d.notes = Zeroizing::new(cell("note"));
                d.folder = cell("folder");
                if !card_number.trim().is_empty() || kind_text == "creditcard" {
                    d.kind = Kind::Card;
                    push_field(&mut d, "Cardholder name", cell("cardholdername"), false);
                    push_field(&mut d, "Card number", card_number, true);
                    push_field(
                        &mut d,
                        crate::model::CARD_EXPIRY_LABEL,
                        card_expiry(&cell("expirydate")),
                        false,
                    );
                    push_field(&mut d, "Security code", cell("cvc"), true);
                    push_field(&mut d, "PIN", cell("pin"), true);
                    push_field(&mut d, "Postcode", zip, false);
                } else if kind_text == "identity"
                    || (kind_text != "note"
                        && password.is_empty()
                        && (!full_name.trim().is_empty() || has_address))
                {
                    d.kind = Kind::Identity;
                    push_field(&mut d, "Full name", full_name, false);
                    push_field(&mut d, "Email", email, false);
                    push_field(&mut d, "Phone", cell("phonenumber"), false);
                    push_field(&mut d, "Address", join_parts(&address, ", "), false);
                } else {
                    let only_note = !d.notes.trim().is_empty()
                        && d.username.trim().is_empty()
                        && password.is_empty()
                        && url.trim().is_empty();
                    if kind_text == "note" || only_note {
                        d.kind = Kind::Note;
                    }
                    if d.username.trim().is_empty() {
                        d.username = email;
                    } else if email.trim() != d.username.trim() {
                        push_field(&mut d, "Email", email, false);
                    }
                    d.urls = vec![url];
                    d.urls.extend(split_urls(&cell("additionalurls")));
                    d.password = Zeroizing::new(password);
                    push_field(&mut d, "PIN", cell("pin"), true);
                }
                push_custom_fields(&mut d, cell("customfields"));
            }
            Format::Generic | Format::ManagerJson => {
                d.title = get(row, mapping.title);
                d.username = get(row, mapping.username);
                d.password = Zeroizing::new(get(row, mapping.password));
                d.urls = vec![get(row, mapping.url)];
                d.notes = Zeroizing::new(get(row, mapping.notes));
                d.totp = Zeroizing::new(get(row, mapping.totp));
                d.folder = get(row, mapping.folder);
            }
        }
        if !d.is_blank() {
            out.push(d.finish());
        }
    }
    out
}

// --------------------------------------------------------------------------------------
// JSON
// --------------------------------------------------------------------------------------

fn jstr(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

/// Parses an unencrypted password-manager JSON export
/// (`{"folders":[...],"items":[...]}` with numeric item types 1–4).
pub fn drafts_from_json(text: &str) -> Result<Vec<Draft>, String> {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let root: serde_json::Value =
        serde_json::from_str(text).map_err(|_| "This file is not valid JSON.".to_string())?;
    if root.get("encrypted").and_then(|e| e.as_bool()) == Some(true) {
        return Err(
            "This export is encrypted. Export again from the other manager as unencrypted JSON, import it here, then delete the file."
                .into(),
        );
    }
    let items = root
        .get("items")
        .and_then(|i| i.as_array())
        .ok_or("This JSON file has no \"items\" list, so it is not an export KeepForge knows.")?;
    let folders: Vec<(String, String)> = root
        .get("folders")
        .and_then(|f| f.as_array())
        .map(|list| {
            list.iter()
                .map(|f| (jstr(f, "id"), jstr(f, "name")))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for it in items {
        let kind = match it.get("type").and_then(|t| t.as_u64()) {
            Some(2) => Kind::Note,
            Some(3) => Kind::Card,
            Some(4) => Kind::Identity,
            _ => Kind::Login,
        };
        let mut d = Draft::new(kind);
        d.title = jstr(it, "name");
        d.notes = Zeroizing::new(jstr(it, "notes"));
        d.favourite = it
            .get("favorite")
            .and_then(|f| f.as_bool())
            .unwrap_or(false);
        let folder_id = jstr(it, "folderId");
        if let Some((_, name)) = folders
            .iter()
            .find(|(id, _)| !id.is_empty() && *id == folder_id)
        {
            d.folder = name.clone();
        }
        if let Some(login) = it.get("login") {
            d.username = jstr(login, "username");
            d.password = Zeroizing::new(jstr(login, "password"));
            d.totp = Zeroizing::new(jstr(login, "totp"));
            if let Some(uris) = login.get("uris").and_then(|u| u.as_array()) {
                d.urls = uris.iter().map(|u| jstr(u, "uri")).collect();
            }
        }
        let mut push = |label: &str, value: String, hidden: bool| {
            if !value.trim().is_empty() {
                d.fields
                    .push((label.to_string(), Zeroizing::new(value), hidden));
            }
        };
        if let Some(card) = it.get("card") {
            push("Cardholder name", jstr(card, "cardholderName"), false);
            push("Card number", jstr(card, "number"), true);
            let (m, y) = (jstr(card, "expMonth"), jstr(card, "expYear"));
            if !m.is_empty() && !y.is_empty() {
                let yy = if y.len() == 4 { y[2..].to_string() } else { y };
                push(
                    crate::model::CARD_EXPIRY_LABEL,
                    format!("{m:0>2}/{yy}"),
                    false,
                );
            }
            push("Security code", jstr(card, "code"), true);
            push("Brand", jstr(card, "brand"), false);
        }
        if let Some(id) = it.get("identity") {
            let name = [
                jstr(id, "firstName"),
                jstr(id, "middleName"),
                jstr(id, "lastName"),
            ]
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
            push("Full name", name, false);
            push("Email", jstr(id, "email"), false);
            push("Phone", jstr(id, "phone"), false);
            let address = [
                jstr(id, "address1"),
                jstr(id, "address2"),
                jstr(id, "city"),
                jstr(id, "state"),
                jstr(id, "postalCode"),
                jstr(id, "country"),
            ]
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(", ");
            push("Address", address, false);
            push("Company", jstr(id, "company"), false);
            push("ID number", jstr(id, "ssn"), true);
            push("Passport number", jstr(id, "passportNumber"), true);
            push("Licence number", jstr(id, "licenseNumber"), true);
        }
        if let Some(fields) = it.get("fields").and_then(|f| f.as_array()) {
            for f in fields {
                // Field type 1 is "hidden".
                let hidden = f.get("type").and_then(|t| t.as_u64()) == Some(1);
                let name = jstr(f, "name");
                push(
                    if name.is_empty() { "Field" } else { &name },
                    jstr(f, "value"),
                    hidden,
                );
            }
        }
        if !d.is_blank() {
            out.push(d.finish());
        }
    }
    Ok(out)
}

// --------------------------------------------------------------------------------------
// Loading, duplicates, applying
// --------------------------------------------------------------------------------------

pub struct Loaded {
    pub format: Format,
    /// Present for CSV files (needed to re-map generic files).
    pub table: Option<Table>,
    pub mapping: Mapping,
    pub drafts: Vec<Draft>,
}

/// Parses the text of an import file (JSON if it starts with `{`, else CSV).
pub fn load(text: &str) -> Result<Loaded, String> {
    let trimmed = text.trim_start_matches('\u{FEFF}').trim_start();
    if trimmed.starts_with('{') {
        return Ok(Loaded {
            format: Format::ManagerJson,
            table: None,
            mapping: Mapping::default(),
            drafts: drafts_from_json(text)?,
        });
    }
    let mut rows = parse_csv(text);
    if rows.len() < 2 {
        return Err(
            "This file has no rows to import. It needs a header line and at least one entry."
                .into(),
        );
    }
    let header = rows.remove(0);
    let table = Table { header, rows };
    let format = detect(&table.header);
    let mapping = guess_mapping(&table.header);
    let drafts = drafts_from_csv(&table, format, &mapping);
    Ok(Loaded {
        format,
        table: Some(table),
        mapping,
        drafts,
    })
}

/// For each draft: is the same entry already in the vault, or earlier in
/// this import? "Same" means same type, title, user name and password.
///
/// Entries are compared through a keyed hash (the key lives only for this
/// call), so each vault password is opened once and no plaintext password
/// is kept in a lookup table.
pub fn find_duplicates(vault: &Vault, drafts: &[Draft]) -> Vec<bool> {
    let key = Zeroizing::new(crate::secret::random_array::<32>());
    // Every part is framed by its length, so no two different entries
    // produce the same input.
    fn part(mac: &mut Hmac<Sha256>, bytes: &[u8]) {
        mac.update(&(bytes.len() as u64).to_le_bytes());
        mac.update(bytes);
    }
    let identity = |kind: Kind, title: &str, user: &str, pw: &str| -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&key[..]).expect("any key length");
        mac.update(&[kind as u8]);
        part(&mut mac, title.trim().to_ascii_lowercase().as_bytes());
        part(&mut mac, user.trim().as_bytes());
        part(&mut mac, pw.as_bytes());
        mac
    };
    let digest = |mac: Hmac<Sha256>| -> [u8; 32] { mac.finalize().into_bytes().into() };

    let in_vault: HashSet<[u8; 32]> = vault
        .items
        .iter()
        .filter(|i| !i.in_trash())
        .map(|i| {
            let pw = i.password.open_str();
            digest(identity(i.kind, &i.title, &i.username, &pw))
        })
        .collect();
    // Earlier entries of this import must also have the same addresses.
    let mut earlier: HashSet<[u8; 32]> = HashSet::with_capacity(drafts.len());
    drafts
        .iter()
        .map(|d| {
            let mac = identity(d.kind, &d.title, &d.username, &d.password);
            let mut with_urls = mac.clone();
            part(&mut with_urls, &(d.urls.len() as u64).to_le_bytes());
            for url in &d.urls {
                part(&mut with_urls, url.as_bytes());
            }
            // Always record the entry, even when the vault already has it.
            let repeated = !earlier.insert(digest(with_urls));
            in_vault.contains(&digest(mac)) || repeated
        })
        .collect()
}

/// Adds the drafts to the vault (skipping those marked in `skip`).
/// Returns how many items were added.
pub fn apply(
    vault: &mut Vault,
    session: &Arc<SessionKey>,
    drafts: &[Draft],
    skip: &[bool],
    now: i64,
) -> usize {
    let mut added = 0;
    for (n, d) in drafts.iter().enumerate() {
        if skip.get(n).copied().unwrap_or(false) {
            continue;
        }
        let mut item = Item::new(d.kind, now);
        item.title = d.title.trim().to_string();
        item.username = d.username.trim().to_string();
        item.password = Protected::seal_str(session, &d.password);
        item.password_changed = d.password_changed.unwrap_or(now);
        item.urls = d.urls.iter().map(|u| u.trim().to_string()).collect();
        item.totp = Protected::seal_str(session, d.totp.trim());
        item.notes = Protected::seal_str(session, &d.notes);
        item.favourite = d.favourite;
        item.tags = d.tags.clone();
        item.folder = vault.folder_id(&d.folder);
        for (label, value, hidden) in &d.fields {
            // Fill the template field of the same name, or add a new field.
            let field = if *hidden {
                CustomField::hidden(session, label, value)
            } else {
                CustomField::plain(label, value)
            };
            match item
                .fields
                .iter_mut()
                .find(|f| f.label.eq_ignore_ascii_case(label) && f.is_blank())
            {
                Some(slot) => *slot = field,
                None => item.fields.push(field),
            }
        }
        vault.items.push(item);
        added += 1;
    }
    added
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_quotes_newlines_bom_non_ascii() {
        let text = "\u{FEFF}name,url,username,password,note\r\n\
                    \"Café, \"\"Zür\"\" ☕\",https://cafe.example,ålex,\"p,w\"\"x\",\"line 1\r\nline 2\"\r\n\
                    \r\n\
                    Plain,,user,,\n\
                    Last,https://l.example,u,p";
        let rows = parse_csv(text);
        assert_eq!(rows.len(), 4);
        assert_eq!(rows[0], vec!["name", "url", "username", "password", "note"]);
        assert_eq!(
            rows[1],
            vec![
                "Café, \"Zür\" ☕",
                "https://cafe.example",
                "ålex",
                "p,w\"x",
                "line 1\r\nline 2"
            ]
        );
        assert_eq!(rows[2], vec!["Plain", "", "user", "", ""]);
        assert_eq!(rows[3], vec!["Last", "https://l.example", "u", "p"]);
        // Semicolon-separated files and a quoted empty last cell.
        let rows = parse_csv("a;b;c\n1;\"2;2\";\"\"");
        assert_eq!(rows[1], vec!["1", "2;2", ""]);
        assert!(parse_csv("").is_empty());
        assert_eq!(parse_csv("one"), vec![vec!["one"]]);
    }

    fn header(text: &str) -> Vec<String> {
        text.split(',').map(str::to_string).collect()
    }

    #[test]
    fn detects_formats() {
        assert_eq!(
            detect(&header("name,url,username,password")),
            Format::BrowserNameFirst
        );
        assert_eq!(
            detect(&header("name,url,username,password,note")),
            Format::BrowserNameFirst
        );
        assert_eq!(
            detect(&header("url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged")),
            Format::BrowserUrlFirst
        );
        assert_eq!(
            detect(&header("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp")),
            Format::ManagerFolderType
        );
        assert_eq!(
            detect(&header("Account,Login Name,Password,Web Site,Comments")),
            Format::ManagerAccount
        );
        assert_eq!(
            detect(&header(
                "Group,Title,Username,Password,URL,Notes,TOTP,Icon,Last Modified,Created"
            )),
            Format::ManagerGroupTitle
        );
        assert_eq!(
            detect(&header(
                "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes"
            )),
            Format::ManagerOtpAuth
        );
        assert_eq!(
            detect(&header(
                "type,title,username,password,url,totp,notes,folder,tags,favourite,fields"
            )),
            Format::KeepForge
        );
        assert_eq!(detect(&header("Site,User,Pass,Remark")), Format::Generic);
        let m = guess_mapping(&header("Site,User,Pass,Remark,Web address,Category"));
        assert_eq!(
            (m.title, m.username, m.password),
            (Some(0), Some(1), Some(2))
        );
        assert_eq!((m.url, m.folder, m.notes), (Some(4), Some(5), None));
    }

    #[test]
    fn imports_each_csv_shape() {
        let chrome = load("name,url,username,password,note\nExample Mail,https://mail.example.com,alex@example.com,pw1,hello\n,https://photo.example/login,alex,pw2,\n").unwrap();
        assert_eq!(chrome.format, Format::BrowserNameFirst);
        assert_eq!(chrome.drafts.len(), 2);
        assert_eq!(chrome.drafts[0].title, "Example Mail");
        assert_eq!(chrome.drafts[0].notes.as_str(), "hello");
        assert_eq!(chrome.drafts[1].title, "photo.example");

        let firefox = load("\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\"https://shop.example\",\"alex\",\"pw\",,\"https://shop.example\",\"{g}\",\"1600000000000\",\"1600000000000\",\"1650000000000\"\n").unwrap();
        assert_eq!(firefox.format, Format::BrowserUrlFirst);
        assert_eq!(firefox.drafts[0].title, "shop.example");
        assert_eq!(firefox.drafts[0].password_changed, Some(1_650_000_000));

        let bw = load("folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,Example VPN,note,\"Site: A\nPIN: 12\",0,\"https://vpn.example,https://alt.example\",alex,pw,JBSWY3DPEHPK3PXP\n,,note,Shed code,2468,,0,,,,\n").unwrap();
        assert_eq!(bw.format, Format::ManagerFolderType);
        let d = &bw.drafts[0];
        assert_eq!(
            (d.folder.as_str(), d.favourite, d.kind),
            ("Work", true, Kind::Login)
        );
        assert_eq!(d.urls, vec!["https://vpn.example", "https://alt.example"]);
        assert_eq!(d.totp.as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(d.fields.len(), 2);
        assert_eq!(d.fields[1].0, "PIN");
        assert_eq!(bw.drafts[1].kind, Kind::Note);
        assert_eq!(bw.drafts[1].notes.as_str(), "2468");

        let kp = load("\"Account\",\"Login Name\",\"Password\",\"Web Site\",\"Comments\"\n\"Example Bank\",\"alex\",\"pw\",\"https://bank.example\",\"c\"\n").unwrap();
        assert_eq!(kp.format, Format::ManagerAccount);
        assert_eq!(kp.drafts[0].title, "Example Bank");
        assert_eq!(kp.drafts[0].urls, vec!["https://bank.example"]);

        let kx = load("\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\"Root/Internet\",\"Forum\",\"alex\",\"pw\",\"https://forum.example\",\"\",\"\"\n\"Root\",\"Top\",\"a\",\"b\",\"\",\"\",\"\"\n").unwrap();
        assert_eq!(kx.format, Format::ManagerGroupTitle);
        assert_eq!(kx.drafts[0].folder, "Internet");
        assert_eq!(kx.drafts[1].folder, "");

        let op = load("Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nStreaming,https://tv.example,alex,pw,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP,true,false,fun;home,n\n").unwrap();
        assert_eq!(op.format, Format::ManagerOtpAuth);
        assert!(op.drafts[0].favourite);
        assert_eq!(op.drafts[0].tags, vec!["fun", "home"]);
        assert!(op.drafts[0].totp.starts_with("otpauth://"));

        let generic = load("Site,User,Pass,Remark\nExample Wiki,alex,pw,r\n").unwrap();
        assert_eq!(generic.format, Format::Generic);
        assert_eq!(generic.drafts[0].title, "Example Wiki");
        assert_eq!(generic.drafts[0].password.as_str(), "pw");
        // Re-mapping by hand.
        let mapping = Mapping {
            title: Some(3),
            ..generic.mapping.clone()
        };
        let again = drafts_from_csv(generic.table.as_ref().unwrap(), Format::Generic, &mapping);
        assert_eq!(again[0].title, "r");

        assert!(load("just a header\n").is_err());
        assert!(load("").is_err());
    }

    const JSON: &str = r#"{"encrypted":false,"folders":[{"id":"f1","name":"Finance"}],
      "items":[
        {"type":1,"name":"Example Bank","notes":"n","favorite":true,"folderId":"f1",
         "login":{"username":"alex","password":"pw\"q","totp":"JBSWY3DPEHPK3PXP",
                  "uris":[{"match":null,"uri":"https://bank.example"},{"uri":"https://m.bank.example"}]},
         "fields":[{"name":"Memorable word","value":"Zürich","type":1},{"name":"Branch","value":"12","type":0}]},
        {"type":2,"name":"Note","notes":"multi\nline","secureNote":{"type":0}},
        {"type":3,"name":"Travel card","card":{"cardholderName":"Alex Morgan","brand":"Visa",
          "number":"4111111111111111","expMonth":"3","expYear":"2029","code":"123"}},
        {"type":4,"name":"Me","identity":{"firstName":"Alex","lastName":"Morgan","email":"alex@example.com",
          "address1":"1 Sample St","city":"Sampletown","ssn":"000-00-0000"}}
      ]}"#;

    #[test]
    fn imports_json() {
        let loaded = load(JSON).unwrap();
        assert_eq!(loaded.format, Format::ManagerJson);
        let d = &loaded.drafts;
        assert_eq!(d.len(), 4);
        assert_eq!(
            (d[0].kind, d[0].folder.as_str(), d[0].favourite),
            (Kind::Login, "Finance", true)
        );
        assert_eq!(d[0].password.as_str(), "pw\"q");
        assert_eq!(d[0].urls.len(), 2);
        assert_eq!(d[0].fields[0].0, "Memorable word");
        assert_eq!(d[0].fields[0].1.as_str(), "Zürich");
        assert!(d[0].fields[0].2 && !d[0].fields[1].2);
        assert_eq!(d[1].kind, Kind::Note);
        assert_eq!(d[1].notes.as_str(), "multi\nline");
        assert_eq!(d[2].kind, Kind::Card);
        assert!(d[2]
            .fields
            .iter()
            .any(|f| f.0 == crate::model::CARD_EXPIRY_LABEL && f.1.as_str() == "03/29"));
        assert!(d[2].fields.iter().any(|f| f.0 == "Card number" && f.2));
        assert_eq!(d[3].kind, Kind::Identity);
        assert!(d[3]
            .fields
            .iter()
            .any(|f| f.0 == "Full name" && f.1.as_str() == "Alex Morgan"));
        assert!(d[3]
            .fields
            .iter()
            .any(|f| f.0 == "Address" && f.1.as_str() == "1 Sample St, Sampletown"));

        assert!(drafts_from_json("{\"encrypted\":true,\"items\":[]}")
            .err()
            .unwrap()
            .contains("encrypted"));
        assert!(drafts_from_json("{\"nothing\":1}").is_err());
        assert!(drafts_from_json("{broken").is_err());
    }

    #[test]
    fn duplicates_and_apply() {
        let s = SessionKey::new();
        let mut v = Vault::new("t", 0);
        let loaded = load(JSON).unwrap();
        assert_eq!(find_duplicates(&v, &loaded.drafts), vec![false; 4]);
        assert_eq!(apply(&mut v, &s, &loaded.drafts, &[], 50), 4);
        assert_eq!(v.items.len(), 4);
        assert_eq!(v.folders.len(), 1);
        let bank = &v.items[0];
        assert_eq!(v.folder_name(bank.folder), Some("Finance"));
        assert_eq!(bank.password.open_str().as_str(), "pw\"q");
        assert_eq!(bank.fields[0].text().as_str(), "Zürich");
        // The card's template fields were filled in, not duplicated.
        let card = &v.items[2];
        assert_eq!(
            card.field("Card number").unwrap().text().as_str(),
            "4111111111111111"
        );
        assert_eq!(
            card.fields
                .iter()
                .filter(|f| f.label == "Card number")
                .count(),
            1
        );
        assert!(card.expiry().is_some());

        // Importing the same file again: everything is a duplicate.
        let again = load(JSON).unwrap();
        let dups = find_duplicates(&v, &again.drafts);
        assert_eq!(dups, vec![true; 4]);
        assert_eq!(apply(&mut v, &s, &again.drafts, &dups, 60), 0);
        // Duplicates inside one file.
        let twice = load("name,url,username,password\nA,https://a.example,u,p\nA,https://a.example,u,p\nA,https://a.example,u,other\n").unwrap();
        assert_eq!(
            find_duplicates(&Vault::new("x", 0), &twice.drafts),
            vec![false, true, false]
        );
    }

    #[test]
    fn detects_new_shapes_without_disturbing_old_ones() {
        assert_eq!(
            detect(&header(
                "url,username,password,totp,extra,name,grouping,fav"
            )),
            Format::ManagerGrouping
        );
        assert_eq!(
            detect(&header(
                "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault"
            )),
            Format::ManagerVaultType
        );
        assert_eq!(
            detect(&header("name,url,username,password,note,cardholdername,cardnumber,cvc,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state")),
            Format::ManagerCards
        );
        assert_eq!(
            detect(&header("name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,pin,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields")),
            Format::ManagerCards
        );
        // The labels describe columns and are all different.
        let all = [
            Format::ManagerGrouping,
            Format::ManagerVaultType,
            Format::ManagerCards,
            Format::Generic,
            Format::BrowserNameFirst,
        ];
        for (n, a) in all.iter().enumerate() {
            assert!(a.label().contains('('));
            assert!(all[..n].iter().all(|b| b.label() != a.label()));
        }
        // Three user-name columns and a one-time-password column: the
        // generic mapping finds every field, whichever name the last has.
        for last in ["otpSecret", "otpUrl"] {
            let h = header(&format!(
                "username,username2,username3,title,password,note,url,category,{last}"
            ));
            assert_eq!(detect(&h), Format::Generic);
            let m = guess_mapping(&h);
            assert_eq!(
                (m.username, m.title, m.password, m.notes),
                (Some(0), Some(3), Some(4), Some(5))
            );
            assert_eq!((m.url, m.folder, m.totp), (Some(6), Some(7), Some(8)));
        }
    }

    #[test]
    fn imports_grouping_shape_with_secure_notes() {
        let loaded = load(
            "url,username,password,totp,extra,name,grouping,fav\n\
             https://mail.example.com,alex@example.com,pw1,JBSWY3DPEHPK3PXP,remember me,Example Mail,Work,1\n\
             http://sn,,,,\"Shed code\n2468\",Shed,Home\\Garden,0\n\
             https://plain.example.com,sam,pw2,,,,,\n",
        )
        .unwrap();
        assert_eq!(loaded.format, Format::ManagerGrouping);
        let d = &loaded.drafts;
        assert_eq!(d.len(), 3);
        assert_eq!(
            (d[0].kind, d[0].title.as_str(), d[0].folder.as_str()),
            (Kind::Login, "Example Mail", "Work")
        );
        assert!(d[0].favourite);
        assert_eq!(d[0].urls, vec!["https://mail.example.com"]);
        assert_eq!(d[0].username, "alex@example.com");
        assert_eq!(d[0].password.as_str(), "pw1");
        assert_eq!(d[0].totp.as_str(), "JBSWY3DPEHPK3PXP");
        assert_eq!(d[0].notes.as_str(), "remember me");
        // The secure note: no address, the text lands in the notes.
        assert_eq!(
            (d[1].kind, d[1].title.as_str(), d[1].folder.as_str()),
            (Kind::Note, "Shed", "Home\\Garden")
        );
        assert!(d[1].urls.is_empty() && !d[1].favourite);
        assert_eq!(d[1].notes.as_str(), "Shed code\n2468");
        // No name: titled after the site.
        assert_eq!(
            (d[2].kind, d[2].title.as_str()),
            (Kind::Login, "plain.example.com")
        );
    }

    #[test]
    fn imports_vault_type_shape_with_email_fallback() {
        let loaded = load(
            "type,name,url,email,username,password,note,totp,createTime,modifyTime,vault\n\
             login,Example Shop,https://shop.example.com,alex@example.com,,pw1,n1,,1700000000,1710000000,Personal\n\
             login,Example Forum,https://forum.example.com,alex@example.com,alexm,pw2,,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP,1700000000,,Personal\n\
             login,Same Both,https://same.example.com,sam@example.com,sam@example.com,pw3,,,,not-a-time,Work\n\
             note,Shed,,,,,code 2468,,1700000000,-5,Work\n\
             alias,Newsletter alias,,alias.one@example.com,,,for newsletters,,,,Personal\n\
             creditCard,Travel card,,,,,card kept as note,,,99999999999999,Personal\n\
             identity,Me,,,,,identity note,,,,Personal\n",
        )
        .unwrap();
        assert_eq!(loaded.format, Format::ManagerVaultType);
        let d = &loaded.drafts;
        assert_eq!(d.len(), 7);
        // User name empty: the e-mail address takes its place.
        assert_eq!(d[0].username, "alex@example.com");
        assert!(d[0].fields.is_empty());
        assert_eq!(
            (d[0].kind, d[0].folder.as_str(), d[0].password_changed),
            (Kind::Login, "Personal", Some(1_710_000_000))
        );
        assert_eq!(d[0].notes.as_str(), "n1");
        // Both present and different: the address is kept as a field.
        assert_eq!(d[1].username, "alexm");
        assert_eq!(d[1].fields.len(), 1);
        assert_eq!(
            (
                d[1].fields[0].0.as_str(),
                d[1].fields[0].1.as_str(),
                d[1].fields[0].2
            ),
            ("Email", "alex@example.com", false)
        );
        assert!(d[1].totp.starts_with("otpauth://"));
        assert_eq!(d[1].password_changed, None);
        // Both present and equal: nothing extra; a bad time is ignored.
        assert_eq!(d[2].username, "sam@example.com");
        assert!(d[2].fields.is_empty());
        assert_eq!(
            (d[2].password_changed, d[2].folder.as_str()),
            (None, "Work")
        );
        assert_eq!((d[3].kind, d[3].title.as_str()), (Kind::Note, "Shed"));
        assert_eq!(d[3].notes.as_str(), "code 2468");
        assert_eq!(d[3].password_changed, None);
        // The other types come in as logins and keep their note.
        assert_eq!(
            (d[4].kind, d[4].username.as_str()),
            (Kind::Login, "alias.one@example.com")
        );
        assert_eq!(d[4].notes.as_str(), "for newsletters");
        assert_eq!(d[5].kind, Kind::Login);
        assert_eq!(d[5].notes.as_str(), "card kept as note");
        assert_eq!(d[5].password_changed, None);
        assert_eq!(d[6].kind, Kind::Login);
        assert_eq!(d[6].notes.as_str(), "identity note");
    }

    #[test]
    fn imports_cards_shape_with_cards_identities_and_notes() {
        let text = "name,url,additional_urls,username,password,note,cardholdername,cardnumber,cvc,pin,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state,type,custom_fields\n\
            Example Mail,https://mail.example.com,\"[\"\"https://m.example.com\"\",\"\"https://alt.example.com\"\"]\",alex,pw1,hello,,,,,,,Work,,,,,,,,,password,\"[{\"\"label\"\":\"\"Memorable word\"\",\"\"type\"\":\"\"hidden\"\",\"\"value\"\":\"\"lighthouse\"\"}]\"\n\
            Travel card,,,,,card note,Alex Morgan,4111111111111111,123,9876,3/2029,AB1 2CD,Finance,,,,,,,,,credit_card,\n\
            Me,,,,,,,,,,,AB1 2CD,,Alex Morgan,555-0100,alex@example.com,1 Sample St,Flat 2,Sampletown,Exampleland,Sampleshire,identity,\n\
            Shed,,,,,code 2468,,,,,,,Home,,,,,,,,,note,\n\
            Work,,,,,,,,,,,,,,,,,,,,,folder,\n\
            Old style,https://old.example.com,,sam,pw2,,,,,,,,,,,,,,,,,,\n";
        let loaded = load(text).unwrap();
        assert_eq!(loaded.format, Format::ManagerCards);
        let d = &loaded.drafts;
        // The folder row is not an entry.
        assert_eq!(d.len(), 5);
        let field = |d: &Draft, label: &str| -> Option<(String, bool)> {
            d.fields
                .iter()
                .find(|f| f.0 == label)
                .map(|f| (f.1.to_string(), f.2))
        };

        assert_eq!(
            (d[0].kind, d[0].title.as_str(), d[0].folder.as_str()),
            (Kind::Login, "Example Mail", "Work")
        );
        assert_eq!(
            d[0].urls,
            vec![
                "https://mail.example.com",
                "https://m.example.com",
                "https://alt.example.com"
            ]
        );
        assert_eq!(
            (d[0].username.as_str(), d[0].password.as_str()),
            ("alex", "pw1")
        );
        assert_eq!(d[0].notes.as_str(), "hello");
        assert_eq!(
            field(&d[0], "Memorable word"),
            Some(("lighthouse".to_string(), true))
        );

        assert_eq!(
            (d[1].kind, d[1].title.as_str(), d[1].folder.as_str()),
            (Kind::Card, "Travel card", "Finance")
        );
        // Exactly the card template's labels and hidden flags.
        for (label, hidden) in Kind::Card.template() {
            assert_eq!(field(&d[1], label).map(|f| f.1), Some(*hidden), "{label}");
        }
        assert_eq!(field(&d[1], "Cardholder name").unwrap().0, "Alex Morgan");
        assert_eq!(field(&d[1], "Card number").unwrap().0, "4111111111111111");
        assert_eq!(
            field(&d[1], crate::model::CARD_EXPIRY_LABEL).unwrap().0,
            "03/29"
        );
        assert_eq!(field(&d[1], "Security code").unwrap().0, "123");
        assert_eq!(field(&d[1], "PIN").unwrap().0, "9876");
        assert_eq!(d[1].notes.as_str(), "card note");
        assert!(d[1].urls.is_empty() && d[1].password.is_empty());

        assert_eq!((d[2].kind, d[2].title.as_str()), (Kind::Identity, "Me"));
        assert_eq!(field(&d[2], "Full name").unwrap().0, "Alex Morgan");
        assert_eq!(field(&d[2], "Email").unwrap().0, "alex@example.com");
        assert_eq!(field(&d[2], "Phone").unwrap().0, "555-0100");
        assert_eq!(
            field(&d[2], "Address").unwrap().0,
            "1 Sample St, Flat 2, Sampletown, Sampleshire, AB1 2CD, Exampleland"
        );
        assert!(d[2].username.is_empty());

        assert_eq!(
            (d[3].kind, d[3].title.as_str(), d[3].folder.as_str()),
            (Kind::Note, "Shed", "Home")
        );
        assert_eq!(d[3].notes.as_str(), "code 2468");
        assert_eq!((d[4].kind, d[4].username.as_str()), (Kind::Login, "sam"));

        // Without the type column the row's contents decide.
        let bare = load(
            "name,url,username,password,note,cardholdername,cardnumber,cvc,expirydate,zipcode,folder,full_name,phone_number,email,address1,address2,city,country,state\n\
             Card,,,,,Alex Morgan,4111111111111111,123,12/30,,,,,,,,,,\n\
             Home,,,,,,,,,,,Alex Morgan,,,1 Sample St,,Sampletown,,\n\
             Just text,,,,only a note,,,,,,,,,,,,,,\n\
             Site,https://site.example.com,,pw,,,,,,,,,,alex@example.com,,,,,\n",
        )
        .unwrap();
        assert_eq!(bare.format, Format::ManagerCards);
        let kinds: Vec<Kind> = bare.drafts.iter().map(|d| d.kind).collect();
        assert_eq!(
            kinds,
            vec![Kind::Card, Kind::Identity, Kind::Note, Kind::Login]
        );
        assert_eq!(
            field(&bare.drafts[0], crate::model::CARD_EXPIRY_LABEL)
                .unwrap()
                .0,
            "12/30"
        );
        assert_eq!(
            field(&bare.drafts[1], "Address").unwrap().0,
            "1 Sample St, Sampletown"
        );
        // A login with only an e-mail address uses it as the user name.
        assert_eq!(bare.drafts[3].username, "alex@example.com");

        // The card's template fields are filled in, not duplicated.
        let s = SessionKey::new();
        let mut v = Vault::new("t", 0);
        assert_eq!(apply(&mut v, &s, &loaded.drafts, &[], 50), 5);
        let card = &v.items[1];
        assert_eq!(
            card.field("Card number").unwrap().text().as_str(),
            "4111111111111111"
        );
        assert_eq!(card.fields.iter().filter(|f| f.label == "PIN").count(), 1);
        assert!(card.expiry().is_some());
    }

    #[test]
    fn separator_is_sniffed_outside_quotes() {
        // A quoted comma in a semicolon-separated header.
        let rows = parse_csv("\"Name, full\";user;pass\nExample;alex;pw\n");
        assert_eq!(rows[0], vec!["Name, full", "user", "pass"]);
        assert_eq!(rows[1], vec!["Example", "alex", "pw"]);
        // A quoted semicolon in a tab-separated header.
        let rows = parse_csv("\"a;b\"\tc\n1\t2\n");
        assert_eq!(rows, vec![vec!["a;b", "c"], vec!["1", "2"]]);
        // A quoted semicolon in a comma-separated header stays a comma file.
        let rows = parse_csv("\"a;b;c;d\",e\n1,2\n");
        assert_eq!(rows, vec![vec!["a;b;c;d", "e"], vec!["1", "2"]]);
        // Blank lines before the header do not hide the separator.
        let rows = parse_csv("\r\n\nsite;user;pass\r\nExample;alex;pw\r\n");
        assert_eq!(
            rows,
            vec![vec!["site", "user", "pass"], vec!["Example", "alex", "pw"]]
        );
        let rows = parse_csv("\n\ttitle\tuser\n\tExample\talex\n");
        assert_eq!(rows[1], vec!["", "Example", "alex"]);
    }

    #[test]
    fn csv_edge_cases() {
        // Tab-separated, with a quoted cell holding a tab and a line break.
        let t = load(
            "Title\tUsername\tPassword\tURL\nExample\talex\t\"p\tw\nx\"\thttps://tab.example.com\n",
        )
        .unwrap();
        assert_eq!(t.drafts.len(), 1);
        assert_eq!(t.drafts[0].password.as_str(), "p\tw\nx");
        assert_eq!(t.drafts[0].urls, vec!["https://tab.example.com"]);
        // Rows shorter and longer than the header.
        let short = load("name,url,username,password,note\nOnly name\nFull,https://f.example.com,u,p,n,extra,cells\n").unwrap();
        assert_eq!(short.drafts.len(), 2);
        assert_eq!(short.drafts[0].title, "Only name");
        assert!(short.drafts[0].password.is_empty() && short.drafts[0].urls.is_empty());
        assert_eq!(short.drafts[1].notes.as_str(), "n");
        // Old-style line ends (CR only), a doubled CR, and a header alone.
        let rows = parse_csv("a,b\r1,2\r\r\n3,4\r");
        assert_eq!(rows, vec![vec!["a", "b"], vec!["1", "2"], vec!["3", "4"]]);
        assert!(load("name,url,username,password\r\n").is_err());
        assert!(load("name,url,username,password\r\n\r\n\r\n").is_err());
    }

    #[test]
    fn mapping_never_uses_one_column_twice() {
        // "username" used to be picked as the title too (it contains
        // "name"), so every entry was titled with its user name.
        let m = guess_mapping(&header("url,username,password"));
        assert_eq!(
            (m.title, m.url, m.username, m.password),
            (None, Some(0), Some(1), Some(2))
        );
        let loaded = load("url,username,password\nhttps://shop.example.com,alex,pw\n").unwrap();
        assert_eq!(loaded.format, Format::Generic);
        assert_eq!(loaded.drafts[0].title, "shop.example.com");
        assert_eq!(loaded.drafts[0].username, "alex");
        // Partial matches still work for columns nobody else has.
        let m = guess_mapping(&header("Site name,User name,Pass,Login URL"));
        assert_eq!(
            (m.title, m.username, m.password, m.url),
            (Some(0), Some(1), Some(2), Some(3))
        );
    }

    /// The straightforward definition `find_duplicates` must agree with.
    fn duplicates_reference(vault: &Vault, drafts: &[Draft]) -> Vec<bool> {
        let same = |d: &Draft, kind: Kind, title: &str, user: &str, pw: &str| {
            d.kind == kind
                && d.title.trim().eq_ignore_ascii_case(title.trim())
                && d.username.trim() == user.trim()
                && d.password.as_str() == pw
        };
        drafts
            .iter()
            .enumerate()
            .map(|(n, d)| {
                vault.items.iter().filter(|i| !i.in_trash()).any(|i| {
                    let pw = i.password.open_str();
                    same(d, i.kind, &i.title, &i.username, &pw)
                }) || drafts[..n].iter().any(|e| {
                    same(d, e.kind, &e.title, &e.username, &e.password) && d.urls == e.urls
                })
            })
            .collect()
    }

    fn draft(kind: Kind, title: &str, user: &str, pw: &str, url: &str) -> Draft {
        let mut d = Draft::new(kind);
        d.title = title.to_string();
        d.username = user.to_string();
        d.password = secret_string(pw);
        d.urls = vec![url.to_string()];
        d
    }

    fn vault_of(s: &Arc<SessionKey>, count: usize) -> Vault {
        let mut v = Vault::new("t", 0);
        for n in 0..count {
            let mut item = Item::new(Kind::Login, 0);
            item.title = format!("Site {n}");
            item.username = format!("user{n}@example.com");
            item.password = Protected::seal_str(s, &format!("pw-{n}"));
            // Every seventh item is in the trash and must not count.
            if n % 7 == 3 {
                item.deleted = Some(1);
            }
            v.items.push(item);
        }
        v
    }

    #[test]
    fn duplicates_match_the_plain_definition() {
        let s = SessionKey::new();
        let v = vault_of(&s, 40);
        let u = |n: usize| format!("user{n}@example.com");
        let drafts = vec![
            draft(
                Kind::Login,
                "Site 0",
                &u(0),
                "pw-0",
                "https://a.example.com",
            ),
            // Title case and surrounding spaces do not matter.
            draft(Kind::Login, "  sITE 1 ", &format!(" {} ", u(1)), "pw-1", ""),
            // These do: user name case, password spaces, the type.
            draft(Kind::Login, "Site 2", "USER2@example.com", "pw-2", ""),
            draft(Kind::Login, "Site 2", &u(2), "pw-2 ", ""),
            draft(Kind::Note, "Site 2", &u(2), "pw-2", ""),
            // Non-ASCII case is not folded.
            draft(Kind::Login, "ÉCOLE", "a", "p", "https://e.example.com"),
            draft(Kind::Login, "école", "a", "p", "https://e.example.com"),
            // In the trash.
            draft(Kind::Login, "Site 3", &u(3), "pw-3", ""),
            // Within the file: same entry, then a different address.
            draft(Kind::Login, "New", "n", "p", "https://n.example.com"),
            draft(Kind::Login, "NEW", "n ", "p", "https://n.example.com"),
            draft(Kind::Login, "New", "n", "p", "https://other.example.com"),
            // The parts must not run into each other.
            draft(Kind::Login, "ab", "c", "d", ""),
            draft(Kind::Login, "a", "bc", "d", ""),
            draft(Kind::Login, "a", "b", "cd", ""),
            // A vault duplicate still counts as "earlier" for a later row.
            draft(
                Kind::Login,
                "Site 0",
                &u(0),
                "pw-0",
                "https://a.example.com",
            ),
        ];
        let got = find_duplicates(&v, &drafts);
        assert_eq!(got, duplicates_reference(&v, &drafts));
        assert_eq!(
            got,
            vec![
                true, true, false, false, false, false, false, false, false, true, false, false,
                false, false, true
            ]
        );
        assert!(find_duplicates(&v, &[]).is_empty());
    }

    #[test]
    fn duplicates_in_a_large_import() {
        // 2,000 drafts against 2,000 items: four million password
        // decryptions with a pairwise comparison, 2,000 with the lookup.
        const N: usize = 2_000;
        let s = SessionKey::new();
        let v = vault_of(&s, N);
        let drafts: Vec<Draft> = (0..N)
            .map(|n| {
                let url = format!("https://site{n}.example.com");
                match n % 4 {
                    // Already in the vault (unless that item is in the trash).
                    0 => draft(
                        Kind::Login,
                        &format!(" SITE {n}"),
                        &format!("user{n}@example.com"),
                        &format!("pw-{n}"),
                        &url,
                    ),
                    // Same title and user name, another password.
                    1 => draft(
                        Kind::Login,
                        &format!("Site {n}"),
                        &format!("user{n}@example.com"),
                        "changed",
                        &url,
                    ),
                    // New, and repeated by the next row.
                    2 => draft(Kind::Login, &format!("Fresh {n}"), "new", "pw", &url),
                    _ => draft(
                        Kind::Login,
                        &format!("Fresh {}", n - 1),
                        "new",
                        "pw",
                        &format!("https://site{}.example.com", n - 1),
                    ),
                }
            })
            .collect();
        let expected: Vec<bool> = (0..N)
            .map(|n| match n % 4 {
                0 => n % 7 != 3,
                1 | 2 => false,
                _ => true,
            })
            .collect();
        let got = find_duplicates(&v, &drafts);
        assert_eq!(got, expected);
        assert_eq!(got.iter().filter(|d| **d).count(), 929);
    }
}
