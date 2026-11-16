//! Importing from CSV and JSON exports of browsers and other password
//! managers. Everything is parsed in memory; plaintext cells are wiped when
//! the parsed table is dropped.

use crate::model::{CustomField, Item, Kind, Vault};
use crate::secret::{secret_string, Protected, SecretString, SessionKey};
use crate::util;
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
/// quotes, CRLF or LF, an optional byte-order mark. The separator is a
/// comma unless the first line has none but has semicolons or tabs.
pub fn parse_csv(text: &str) -> Vec<Vec<String>> {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    let first_line = text.lines().next().unwrap_or("");
    let sep = if first_line.contains(',') {
        ','
    } else if first_line.contains(';') {
        ';'
    } else if first_line.contains('\t') {
        '\t'
    } else {
        ','
    };
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
    let find = |names: &[&str]| -> Option<usize> {
        names
            .iter()
            .find_map(|n| h.iter().position(|x| x == n))
            .or_else(|| {
                names
                    .iter()
                    .find_map(|n| h.iter().position(|x| x.contains(n)))
            })
    };
    Mapping {
        title: find(&["title", "name", "account", "site", "service", "entry"]),
        username: find(&["username", "user", "login", "loginname", "email"]),
        password: find(&["password", "pass", "pwd"]),
        url: find(&["url", "website", "uri", "link", "address"]),
        notes: find(&["notes", "note", "comments", "comment", "extra"]),
        totp: find(&["totp", "otpauth", "otp", "2fa"]),
        folder: find(&["folder", "group", "category", "grouping"]),
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
pub fn find_duplicates(vault: &Vault, drafts: &[Draft]) -> Vec<bool> {
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
            }) || drafts[..n]
                .iter()
                .any(|e| same(d, e.kind, &e.title, &e.username, &e.password) && d.urls == e.urls)
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
}
