//! The vault's data model. Secrets are [`Protected`]: encrypted in memory
//! under the session key and decrypted only when used.

use crate::secret::{random_array, Protected, SecretString, SessionKey};
use crate::util;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Version of the serialized payload layout (inside the encrypted part).
pub const SCHEMA: u32 = 1;

/// How many old passwords are remembered per item.
pub const HISTORY_LIMIT: usize = 20;

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
)]
pub struct Id(pub u128);

impl Id {
    pub fn random() -> Id {
        Id(u128::from_le_bytes(random_array()))
    }

    pub fn hex(self) -> String {
        util::hex(&self.0.to_be_bytes())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum Kind {
    #[default]
    Login,
    Card,
    Identity,
    Note,
    Wifi,
    Licence,
}

impl Kind {
    pub const ALL: [Kind; 6] = [
        Kind::Login,
        Kind::Card,
        Kind::Identity,
        Kind::Note,
        Kind::Wifi,
        Kind::Licence,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Kind::Login => "Login",
            Kind::Card => "Card",
            Kind::Identity => "Identity",
            Kind::Note => "Secure note",
            Kind::Wifi => "Wi-Fi",
            Kind::Licence => "Licence or API key",
        }
    }

    pub fn plural(self) -> &'static str {
        match self {
            Kind::Login => "Logins",
            Kind::Card => "Cards",
            Kind::Identity => "Identities",
            Kind::Note => "Secure notes",
            Kind::Wifi => "Wi-Fi",
            Kind::Licence => "Licences and keys",
        }
    }

    /// Label of the plain "user name" slot, if this kind has one.
    pub fn username_label(self) -> Option<&'static str> {
        match self {
            Kind::Login => Some("Username"),
            Kind::Wifi => Some("Network name (SSID)"),
            Kind::Licence => Some("Licensed to / account"),
            _ => None,
        }
    }

    /// Label of the main secret slot, if this kind has one.
    pub fn password_label(self) -> Option<&'static str> {
        match self {
            Kind::Login => Some("Password"),
            Kind::Wifi => Some("Wi-Fi password"),
            Kind::Licence => Some("Key"),
            _ => None,
        }
    }

    pub fn has_urls(self) -> bool {
        matches!(self, Kind::Login | Kind::Licence)
    }

    pub fn has_totp(self) -> bool {
        self == Kind::Login
    }

    /// The fields a new item of this kind starts with: (label, hidden).
    pub fn template(self) -> &'static [(&'static str, bool)] {
        match self {
            Kind::Card => &[
                ("Cardholder name", false),
                ("Card number", true),
                ("Expiry (MM/YY)", false),
                ("Security code", true),
                ("PIN", true),
            ],
            Kind::Identity => &[
                ("Full name", false),
                ("Email", false),
                ("Phone", false),
                ("Address", false),
                ("Date of birth", false),
                ("ID number", true),
            ],
            Kind::Wifi => &[("Security", false)],
            Kind::Licence => &[("Product", false), ("Version", false)],
            Kind::Login | Kind::Note => &[],
        }
    }
}

pub const CARD_EXPIRY_LABEL: &str = "Expiry (MM/YY)";

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomField {
    pub label: String,
    pub hidden: bool,
    /// Used when the field is not hidden.
    pub value: String,
    /// Used when the field is hidden.
    pub secret: Protected,
}

impl CustomField {
    pub fn plain(label: &str, value: &str) -> CustomField {
        CustomField {
            label: label.to_string(),
            hidden: false,
            value: value.to_string(),
            secret: Protected::default(),
        }
    }

    pub fn hidden(session: &Arc<SessionKey>, label: &str, value: &str) -> CustomField {
        CustomField {
            label: label.to_string(),
            hidden: true,
            value: String::new(),
            secret: Protected::seal_str(session, value),
        }
    }

    pub fn is_blank(&self) -> bool {
        if self.hidden {
            self.secret.is_empty()
        } else {
            self.value.trim().is_empty()
        }
    }

    pub fn text(&self) -> SecretString {
        if self.hidden {
            self.secret.open_str()
        } else {
            crate::secret::secret_string(&self.value)
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct HistoryEntry {
    pub password: Protected,
    /// When this password stopped being the current one.
    pub replaced: i64,
}

/// A two-factor backup code.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct RecoveryCode {
    pub code: Protected,
    pub used: bool,
}

/// A file stored in the vault. The content lives in its own encrypted
/// section of the vault file and stays encrypted in memory.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Attachment {
    pub id: Id,
    pub name: String,
    /// Size of the original file in bytes.
    pub size: u64,
    pub nonce: [u8; 24],
    /// SHA-256 of the encrypted section, so sections cannot be swapped.
    pub digest: [u8; 32],
    /// The encrypted content (ciphertext and tag), under the attachment key.
    #[serde(skip)]
    pub blob: Arc<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Item {
    pub id: Id,
    pub kind: Kind,
    pub title: String,
    pub folder: Option<Id>,
    pub tags: Vec<String>,
    pub favourite: bool,
    pub created: i64,
    pub modified: i64,
    /// Set while the item is in the trash.
    pub deleted: Option<i64>,
    pub username: String,
    pub password: Protected,
    /// When the current password was set.
    pub password_changed: i64,
    pub urls: Vec<String>,
    /// An `otpauth://` URI or a bare base32 secret.
    pub totp: Protected,
    pub notes: Protected,
    pub fields: Vec<CustomField>,
    pub history: Vec<HistoryEntry>,
    pub recovery_codes: Vec<RecoveryCode>,
    pub attachments: Vec<Attachment>,
    /// Custom auto-type sequence; empty means the default.
    pub autotype: String,
    /// Optional "expires on" date (Unix time).
    pub expires: Option<i64>,
}

impl Item {
    pub fn new(kind: Kind, now: i64) -> Item {
        Item {
            id: Id::random(),
            kind,
            created: now,
            modified: now,
            password_changed: now,
            fields: kind
                .template()
                .iter()
                .map(|(label, hidden)| CustomField {
                    label: label.to_string(),
                    hidden: *hidden,
                    ..Default::default()
                })
                .collect(),
            ..Default::default()
        }
    }

    pub fn in_trash(&self) -> bool {
        self.deleted.is_some()
    }

    /// Sets a new password, remembering the old one in the history.
    pub fn set_password(&mut self, session: &Arc<SessionKey>, new: &str, now: i64) {
        let same = {
            let current = self.password.open_str();
            current.as_str() == new
        };
        if same {
            return;
        }
        if !self.password.is_empty() {
            self.history.insert(
                0,
                HistoryEntry {
                    password: self.password.clone(),
                    replaced: now,
                },
            );
            self.history.truncate(HISTORY_LIMIT);
        }
        self.password = Protected::seal_str(session, new);
        self.password_changed = now;
    }

    pub fn field(&self, label: &str) -> Option<&CustomField> {
        self.fields
            .iter()
            .find(|f| f.label.eq_ignore_ascii_case(label))
    }

    /// When the item expires: the explicit date, or a card's expiry.
    pub fn expiry(&self) -> Option<i64> {
        if self.expires.is_some() {
            return self.expires;
        }
        if self.kind == Kind::Card {
            let f = self
                .fields
                .iter()
                .find(|f| !f.hidden && f.label.to_lowercase().starts_with("expiry"))?;
            return util::parse_card_expiry(&f.value);
        }
        None
    }

    /// The line shown under the title in lists.
    pub fn subtitle(&self) -> String {
        match self.kind {
            Kind::Login | Kind::Wifi | Kind::Licence => {
                if !self.username.is_empty() {
                    self.username.clone()
                } else {
                    self.urls
                        .first()
                        .map(|u| util::host_of(u))
                        .unwrap_or_default()
                }
            }
            Kind::Card | Kind::Identity => self
                .fields
                .iter()
                .find(|f| !f.hidden && !f.value.trim().is_empty())
                .map(|f| f.value.clone())
                .unwrap_or_default(),
            Kind::Note => String::new(),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Folder {
    pub id: Id,
    pub name: String,
}

/// A key for an optional online service, kept inside the vault.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceKey {
    pub service: String,
    pub key: Protected,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Vault {
    pub schema: u32,
    pub id: Id,
    pub name: String,
    pub created: i64,
    pub modified: i64,
    pub folders: Vec<Folder>,
    pub items: Vec<Item>,
    pub service_keys: Vec<ServiceKey>,
    /// Cached Exposure check results (JSON, see `exposure::Cache`). Inside the
    /// encrypted payload like everything else; empty in older vaults.
    pub exposure: String,
}

impl Vault {
    pub fn new(name: &str, now: i64) -> Vault {
        Vault {
            schema: SCHEMA,
            id: Id::random(),
            name: name.to_string(),
            created: now,
            modified: now,
            ..Default::default()
        }
    }

    pub fn item(&self, id: Id) -> Option<&Item> {
        self.items.iter().find(|i| i.id == id)
    }

    pub fn item_mut(&mut self, id: Id) -> Option<&mut Item> {
        self.items.iter_mut().find(|i| i.id == id)
    }

    pub fn folder_name(&self, id: Option<Id>) -> Option<&str> {
        let id = id?;
        self.folders
            .iter()
            .find(|f| f.id == id)
            .map(|f| f.name.as_str())
    }

    /// Finds a folder by name (case-insensitive) or creates it.
    pub fn folder_id(&mut self, name: &str) -> Option<Id> {
        let name = name.trim();
        if name.is_empty() {
            return None;
        }
        if let Some(f) = self
            .folders
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(name))
        {
            return Some(f.id);
        }
        let id = Id::random();
        self.folders.push(Folder {
            id,
            name: name.to_string(),
        });
        self.folders.sort_by_key(|f| f.name.to_lowercase());
        Some(id)
    }

    /// All tags in use on items outside the trash, sorted.
    pub fn all_tags(&self) -> Vec<String> {
        let mut tags: Vec<String> = self
            .items
            .iter()
            .filter(|i| !i.in_trash())
            .flat_map(|i| i.tags.iter().cloned())
            .collect();
        tags.sort_by_key(|t| t.to_lowercase());
        tags.dedup_by(|a, b| a.eq_ignore_ascii_case(b));
        tags
    }

    pub fn move_to_trash(&mut self, id: Id, now: i64) {
        if let Some(i) = self.item_mut(id) {
            i.deleted = Some(now);
            i.modified = now;
        }
    }

    pub fn restore(&mut self, id: Id, now: i64) {
        if let Some(i) = self.item_mut(id) {
            i.deleted = None;
            i.modified = now;
        }
    }

    pub fn delete_forever(&mut self, id: Id) {
        self.items.retain(|i| i.id != id);
    }

    pub fn empty_trash(&mut self) -> usize {
        let before = self.items.len();
        self.items.retain(|i| !i.in_trash());
        before - self.items.len()
    }

    /// Removes items that have been in the trash for `days` days or more.
    /// With `days == 0` nothing is removed. Returns how many items went.
    pub fn purge_trash(&mut self, now: i64, days: u32) -> usize {
        if days == 0 {
            return 0;
        }
        let limit = now - i64::from(days) * util::DAY;
        let before = self.items.len();
        self.items
            .retain(|i| !matches!(i.deleted, Some(when) if when <= limit));
        before - self.items.len()
    }

    /// Copies an item (new id, "(copy)" title, no history). Returns the new id.
    pub fn duplicate(&mut self, id: Id, now: i64) -> Option<Id> {
        let mut copy = self.item(id)?.clone();
        copy.id = Id::random();
        copy.title = format!("{} (copy)", copy.title);
        copy.created = now;
        copy.modified = now;
        copy.deleted = None;
        copy.history.clear();
        let new_id = copy.id;
        self.items.push(copy);
        Some(new_id)
    }

    /// Distinct email addresses found in usernames and plain fields.
    pub fn emails(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let mut add = |text: &str| {
            let t = text.trim().to_lowercase();
            if looks_like_email(&t) && !out.contains(&t) {
                out.push(t);
            }
        };
        for i in self.items.iter().filter(|i| !i.in_trash()) {
            add(&i.username);
            for f in i.fields.iter().filter(|f| !f.hidden) {
                add(&f.value);
            }
        }
        out.sort();
        out
    }

    /// Distinct user names of logins that are not email addresses.
    pub fn usernames(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for i in self
            .items
            .iter()
            .filter(|i| i.kind == Kind::Login && !i.in_trash())
        {
            let u = i.username.trim();
            // Card and library numbers are not user names worth looking up.
            if u.chars().count() >= 3
                && u.chars().count() <= 64
                && !u.chars().all(|c| c.is_ascii_digit())
                && !u.contains('@')
                && !u
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control() || c == '/')
                && !out.iter().any(|o| o.eq_ignore_ascii_case(u))
            {
                out.push(u.to_string());
            }
        }
        out.sort_by_key(|u| u.to_lowercase());
        out
    }

    /// Distinct phone numbers (with a country code) from visible fields
    /// labelled as phone numbers.
    pub fn phones(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for i in self.items.iter().filter(|i| !i.in_trash()) {
            for f in i.fields.iter().filter(|f| {
                !f.hidden && {
                    let l = f.label.to_lowercase();
                    l.contains("phone") || l.contains("mobile")
                }
            }) {
                if let Some(p) = crate::exposure::normalize_phone(&f.value) {
                    if !out.contains(&p) {
                        out.push(p);
                    }
                }
            }
        }
        out.sort();
        out
    }

    pub fn service_key(&self, service: &str) -> Option<&Protected> {
        self.service_keys
            .iter()
            .find(|k| k.service == service && !k.key.is_empty())
            .map(|k| &k.key)
    }

    pub fn set_service_key(&mut self, service: &str, key: Protected) {
        self.service_keys.retain(|k| k.service != service);
        if !key.is_empty() {
            self.service_keys.push(ServiceKey {
                service: service.to_string(),
                key,
            });
        }
    }

    pub fn attachment_count(&self) -> usize {
        self.items.iter().map(|i| i.attachments.len()).sum()
    }
}

/// A conservative check: one `@`, something on both sides, a dot in the domain.
pub fn looks_like_email(text: &str) -> bool {
    let mut parts = text.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && domain.len() <= 255
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "@._%+-".contains(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_history_is_kept() {
        let s = SessionKey::new();
        let mut i = Item::new(Kind::Login, 100);
        i.set_password(&s, "first", 100);
        assert!(i.history.is_empty());
        i.set_password(&s, "second", 200);
        i.set_password(&s, "second", 300);
        assert_eq!(i.history.len(), 1);
        assert_eq!(i.history[0].password.open_str().as_str(), "first");
        assert_eq!(i.history[0].replaced, 200);
        assert_eq!(i.password_changed, 200);
        for n in 0..40 {
            i.set_password(&s, &format!("p{n}"), 400 + n);
        }
        assert_eq!(i.history.len(), HISTORY_LIMIT);
    }

    #[test]
    fn trash_duplicate_and_tags() {
        let mut v = Vault::new("Test", 1);
        let mut a = Item::new(Kind::Login, 1);
        a.title = "Example Mail".into();
        a.tags = vec!["Work".into(), "mail".into()];
        let id = a.id;
        v.items.push(a);
        let copy = v.duplicate(id, 5).unwrap();
        assert_ne!(copy, id);
        assert_eq!(v.item(copy).unwrap().title, "Example Mail (copy)");
        v.move_to_trash(copy, 6);
        assert!(v.item(copy).unwrap().in_trash());
        v.restore(copy, 7);
        assert!(!v.item(copy).unwrap().in_trash());
        v.move_to_trash(copy, 8);
        assert_eq!(v.empty_trash(), 1);
        assert_eq!(v.items.len(), 1);
        assert_eq!(v.all_tags(), vec!["mail".to_string(), "Work".to_string()]);
        let f = v.folder_id("Personal").unwrap();
        assert_eq!(v.folder_id("personal"), Some(f));
        assert_eq!(v.folder_name(Some(f)), Some("Personal"));
    }

    #[test]
    fn old_trash_is_purged_only_when_asked() {
        let day = util::DAY;
        let now = 1000 * day;
        let mut v = Vault::new("Test", 1);
        for (title, deleted) in [
            ("live", None),
            ("fresh", Some(now - 2 * day)),
            ("edge", Some(now - 30 * day)),
            ("old", Some(now - 90 * day)),
        ] {
            let mut i = Item::new(Kind::Login, 1);
            i.title = title.into();
            i.deleted = deleted;
            v.items.push(i);
        }
        assert_eq!(v.purge_trash(now, 0), 0, "0 days means never");
        assert_eq!(v.items.len(), 4);
        assert_eq!(v.purge_trash(now, 365), 0);
        assert_eq!(v.purge_trash(now, 30), 2);
        let left: Vec<&str> = v.items.iter().map(|i| i.title.as_str()).collect();
        assert_eq!(left, vec!["live", "fresh"]);
        // A clock that jumped back never deletes anything.
        assert_eq!(v.purge_trash(now - 500 * day, 30), 0);
    }

    #[test]
    fn emails_and_expiry() {
        let mut v = Vault::new("Test", 1);
        let mut a = Item::new(Kind::Login, 1);
        a.username = "Alex.Morgan@Example.com".into();
        v.items.push(a);
        let mut c = Item::new(Kind::Card, 1);
        c.fields[2].value = "03/27".into();
        assert_eq!(
            c.expiry(),
            Some(util::days_from_civil(2027, 4, 1) * util::DAY)
        );
        v.items.push(c);
        assert_eq!(v.emails(), vec!["alex.morgan@example.com".to_string()]);
        assert!(!looks_like_email("alex"));
        assert!(!looks_like_email("a@b"));
        assert!(!looks_like_email("a b@c.de"));
    }
}
