//! User settings, stored as JSON in `%APPDATA%\KeepForge\settings.json`, or
//! next to the EXE when a `portable.flag` file sits beside it.
//! Settings never contain secrets: no passwords, no keys, no vault content.

use crate::generator::{PasswordOptions, PhraseOptions};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThemeChoice {
    Dark,
    Light,
    System,
}

/// How the item list is ordered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SortOrder {
    /// By title, A to Z.
    #[default]
    Title,
    /// Most recently changed first.
    Changed,
    /// Most recently added first.
    Created,
}

impl SortOrder {
    pub const ALL: [SortOrder; 3] = [SortOrder::Title, SortOrder::Changed, SortOrder::Created];

    pub fn label(self) -> &'static str {
        match self {
            SortOrder::Title => "Title (A to Z)",
            SortOrder::Changed => "Recently changed",
            SortOrder::Created => "Recently added",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct RecentVault {
    pub path: String,
    pub name: String,
    pub last_opened: i64,
    /// Where this vault's key file was last found (a path, not the key).
    pub key_file: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub theme: ThemeChoice,
    /// Lock after this many minutes without keyboard or mouse input (0 = never).
    pub auto_lock_minutes: u32,
    pub lock_on_minimize: bool,
    /// Lock when Windows locks, sleeps or switches user.
    pub lock_on_session: bool,
    /// Clear copied secrets from the clipboard after this many seconds (0 = never).
    pub clipboard_seconds: u32,
    /// Ask Windows to leave the window out of screenshots and recordings.
    pub hide_from_capture: bool,
    pub tray_icon: bool,
    pub start_minimised: bool,
    /// Rolling backups kept next to the vault (0 = none).
    pub backups: u32,
    pub generator: PasswordOptions,
    pub phrase: PhraseOptions,
    /// The generator opens on passphrases instead of passwords.
    pub generator_phrase: bool,
    pub autotype_enabled: bool,
    pub autotype_hotkey: String,
    /// Search also looks inside hidden fields and passwords' custom fields.
    pub search_hidden: bool,
    pub attachment_limit_mb: u32,
    /// Passwords older than this many months are listed as old.
    pub old_password_months: u32,
    /// Revealed secrets hide again after this many seconds.
    pub reveal_seconds: u32,
    /// The user has turned on the online password breach check.
    pub breach_check: bool,
    /// "Don't ask again" for the email breach lookup explanation.
    pub email_lookup_ack: bool,
    /// "Don't ask again" for the torrent exposure explanation.
    pub ip_lookup_ack: bool,
    /// Block dynamically generated code in this process (takes effect at next start).
    pub block_dynamic_code: bool,
    /// Order of the item list.
    pub list_sort: SortOrder,
    /// Items stay in the trash this many days, then are removed for good
    /// when the vault is next unlocked (0 = until the trash is emptied).
    pub trash_days: u32,
    pub recent: Vec<RecentVault>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            theme: ThemeChoice::Dark,
            auto_lock_minutes: 5,
            lock_on_minimize: false,
            lock_on_session: true,
            clipboard_seconds: 20,
            hide_from_capture: true,
            tray_icon: false,
            start_minimised: false,
            backups: 5,
            generator: PasswordOptions::default(),
            phrase: PhraseOptions::default(),
            generator_phrase: false,
            autotype_enabled: true,
            autotype_hotkey: "Ctrl+Alt+A".into(),
            search_hidden: false,
            attachment_limit_mb: 10,
            old_password_months: 12,
            reveal_seconds: 20,
            breach_check: false,
            email_lookup_ack: false,
            ip_lookup_ack: false,
            block_dynamic_code: false,
            list_sort: SortOrder::Title,
            trash_days: 0,
            recent: Vec::new(),
        }
    }
}

pub const RECENT_LIMIT: usize = 8;

impl Settings {
    pub fn load(dir: &Path) -> Settings {
        let mut s: Settings = std::fs::read_to_string(dir.join("settings.json"))
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or_default();
        s.sanitize();
        s
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        std::fs::create_dir_all(dir).map_err(|e| format!("Could not save settings: {e}"))?;
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(dir.join("settings.json"), json)
            .map_err(|e| format!("Could not save settings: {e}"))
    }

    /// Keeps hand-edited values inside sensible ranges.
    pub fn sanitize(&mut self) {
        self.auto_lock_minutes = self.auto_lock_minutes.min(24 * 60);
        self.clipboard_seconds = self.clipboard_seconds.min(600);
        self.backups = self.backups.min(50);
        self.attachment_limit_mb = self.attachment_limit_mb.clamp(1, 200);
        self.old_password_months = self.old_password_months.clamp(1, 120);
        self.reveal_seconds = self.reveal_seconds.clamp(5, 300);
        self.trash_days = self.trash_days.min(3650);
        self.recent.truncate(RECENT_LIMIT);
    }

    /// Moves a vault to the top of the recent list.
    pub fn remember(&mut self, path: &Path, name: &str, key_file: Option<&Path>, now: i64) {
        let p = path.to_string_lossy().to_string();
        let old = self
            .recent
            .iter()
            .position(|r| r.path.eq_ignore_ascii_case(&p))
            .map(|i| self.recent.remove(i));
        self.recent.insert(
            0,
            RecentVault {
                path: p,
                name: name.to_string(),
                last_opened: now,
                key_file: key_file
                    .map(|k| k.to_string_lossy().to_string())
                    .or(old.and_then(|o| o.key_file)),
            },
        );
        self.recent.truncate(RECENT_LIMIT);
    }

    pub fn forget(&mut self, path: &str) {
        self.recent.retain(|r| !r.path.eq_ignore_ascii_case(path));
    }
}

/// Where settings and the log live: next to the EXE in portable mode,
/// otherwise `%APPDATA%\KeepForge`.
pub fn data_dir() -> PathBuf {
    if let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        if dir.join("portable.flag").exists() {
            return dir;
        }
    }
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("KeepForge")
}

pub fn is_portable() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("portable.flag").exists()))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_tolerant_loading() {
        let dir = crate::util::unique_temp_dir("settings");
        assert_eq!(Settings::load(&dir), Settings::default());
        let mut s = Settings {
            theme: ThemeChoice::Light,
            clipboard_seconds: 45,
            ..Default::default()
        };
        s.remember(Path::new("C:\\Vaults\\a.kfv"), "A", None, 10);
        s.remember(
            Path::new("C:\\Vaults\\b.kfv"),
            "B",
            Some(Path::new("E:\\b.key")),
            20,
        );
        s.remember(Path::new("c:\\vaults\\A.kfv"), "A", None, 30);
        assert_eq!(s.recent.len(), 2);
        assert_eq!(s.recent[0].name, "A");
        s.save(&dir).unwrap();
        assert_eq!(Settings::load(&dir), s);
        std::fs::write(
            dir.join("settings.json"),
            r#"{"theme":"System","future":1,"backups":9999,"clipboard_seconds":100000}"#,
        )
        .unwrap();
        let loaded = Settings::load(&dir);
        assert_eq!(loaded.theme, ThemeChoice::System);
        assert_eq!(loaded.backups, 50);
        assert_eq!(loaded.clipboard_seconds, 600);
        assert_eq!(loaded.auto_lock_minutes, 5);
        // A settings file written by an older version has no sort order or
        // trash limit: the list stays sorted by title and nothing is purged.
        assert_eq!(loaded.list_sort, SortOrder::Title);
        assert_eq!(loaded.trash_days, 0);
        std::fs::write(
            dir.join("settings.json"),
            r#"{"list_sort":"Changed","trash_days":999999}"#,
        )
        .unwrap();
        let loaded = Settings::load(&dir);
        assert_eq!(loaded.list_sort, SortOrder::Changed);
        assert_eq!(loaded.trash_days, 3650);
        std::fs::write(dir.join("settings.json"), "{{{").unwrap();
        assert_eq!(Settings::load(&dir), Settings::default());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The settings file has a fixed, reviewed set of fields. Adding a field
    /// means adding it here, which is the moment to check it is not a secret.
    #[test]
    fn settings_never_serialize_secrets() {
        let mut s = Settings::default();
        s.remember(Path::new("C:\\v.kfv"), "V", Some(Path::new("E:\\k.key")), 1);
        let json = serde_json::to_value(&s).unwrap();
        let mut keys: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "attachment_limit_mb",
                "auto_lock_minutes",
                "autotype_enabled",
                "autotype_hotkey",
                "backups",
                "block_dynamic_code",
                "breach_check",
                "clipboard_seconds",
                "email_lookup_ack",
                "generator",
                "generator_phrase",
                "hide_from_capture",
                "ip_lookup_ack",
                "list_sort",
                "lock_on_minimize",
                "lock_on_session",
                "old_password_months",
                "phrase",
                "recent",
                "reveal_seconds",
                "search_hidden",
                "start_minimised",
                "theme",
                "trash_days",
                "tray_icon",
            ]
        );
        let recent: Vec<&str> = json["recent"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(|k| k.as_str())
            .collect();
        assert_eq!(recent, vec!["key_file", "last_opened", "name", "path"]);
        let text = serde_json::to_string(&s).unwrap().to_lowercase();
        for word in ["password\"", "secret", "master", "token", "api_key", "hint"] {
            assert!(!text.contains(word), "settings mention {word}");
        }
    }
}
