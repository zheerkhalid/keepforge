# Changelog

All notable changes to KeepForge are listed here, newest first.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [1.2.0] - 2026-11-26

Vaults made with 1.0 and 1.1 open as they are. The vault gains one field, the saved Exposure check results; older versions ignore it.

### Added

- **Exposure check**, a new page that replaces *Breach lookup*. Check an **email address, user name, phone number, domain or password** against known breaches, pastes and **infostealer logs** (malware that copies the logins saved on a computer).
- **Several services instead of one.** Built in and free: XposedOrNot, LeakCheck's public API, Hudson Rock's infostealer lookup and Have I Been Pwned's list of breached sites. With a key of your own (pasted in Settings and kept inside the encrypted vault): Have I Been Pwned (breaches, pastes, and stealer-log sites where your plan includes them), Leak-Lookup (the only way to check a phone number) and Enzoic (passwords).
- **One list per breach.** When several services report the same breach, it is shown once: the site, when it happened, what leaked (passwords, phone numbers, addresses…), which services reported it, a link to details, a plain risk level (low, medium, high, act now) and **what to do**: change the password there, turn on two-step verification, watch for scam calls, scan the computer for malware.
- **You can see which services were asked**, what each found, and which failed and why (no key yet, too many lookups, not in your plan).
- **Linked to your vault.** Each breach shows "You have an account here in KeepForge" with the matching login and whether its password was changed since. The security dashboard lists these logins with the reason, warns when malware stole saved logins, and the item itself shows the warning.
- **Where is my user name registered?** Asks about 550 websites from the WhatsMyName list whether a profile with your user name exists, so you can find accounts you forgot. Six websites at a time, one request each, only after you tick "this is my own user name".
- **Were the sites in my vault breached?** Downloads the public list of breached sites once and compares it with your saved web addresses on your PC. Nothing about you is sent.
- **Check all** email addresses, user names and phone numbers in the vault in one go, with progress and Cancel. Each service is asked at its own pace and is left alone after it says "too many requests".
- **Results are saved** inside the encrypted vault with the date they were checked, so they are still there after the next unlock. Each result can be forgotten.
- **Optional re-check** when you unlock: weekly, monthly or every 3 months. Off unless you turn it on.
- **More password checks** for the single password check: XposedOrNot (sends 10 characters of a hash, which the settings explain) and Enzoic with your own key. Like Pwned Passwords, neither ever receives the password or its full hash.
- `--selftest-online` now asks every free source once with test data only (the test password "password", test@example.com, Have I Been Pwned's documented test accounts and test key, an invented user name).

### Changed

- **Every online source is off until you turn it on.** Settings › Online checks lists each one with exactly what it sends and what it returns; the first time you press Check, a box lets you pick which services to ask. If you had said yes to the email lookup before, XposedOrNot stays on.
- The sidebar entry *Breach lookup* is now *Exposure check*, and the dashboard's "Breached" list is called "Breached and exposed".
- `docs/SECURITY.md`, `docs/FORMAT.md` and the README's online checks table describe every source.

### Fixed

- Results of the email lookup were lost when the vault locked; they are now kept with the vault.

### Not included, on purpose

- Services that sell or show leaked passwords, password hashes or other people's records (DeHashed, Snusbase, BreachDirectory, ProxyNova COMB, Intelligence X, LeakCheck's paid API and others), services without an official API (Google Password Checkup, Mozilla Monitor, Cybernews, Avast and similar checkers would need scraping), and business-only services (SpyCloud, Constella, BreachSense). No free service allows checking phone numbers.

## [1.1.0] - 2026-11-24

Vaults made with 1.0.x open as they are; nothing about the vault file or its encryption has changed.

### Added

- **Kurdish, Arabic, Persian and Hebrew text is shown properly.** Titles, user names, folders, tags, field names, notes and the vault name on the lock screen are now drawn with joined letters and in the right reading order. Before, the letters stood apart and ran backwards.
- **Sort the item list** by title, by what changed most recently, or by what was added most recently (the new button next to *New*). The choice is remembered.
- **Move through the list with the keyboard.** Up, Down, Page Up, Page Down, Home and End walk the list, also while the search box is active, and Enter picks the first search result. So: `Ctrl+F`, type, Down, `Ctrl+C`.
- **Drag a file onto the window** to store it as an attachment of the item that is open.
- **The generator remembers what you copied.** The last 8 passwords copied from the Generator page are listed there, in case one went into a sign-up form before you saved it. They are kept in memory only and are gone when the vault locks.
- **Unencrypted web addresses in the security dashboard.** Logins whose saved address starts with `http://` are listed, because the password travels without encryption. Devices at home (router pages, `localhost`, private addresses) are left out.
- **Three more CSV export layouts are recognised on import**, including secure notes, payment cards and identities that used to arrive as plain logins or lose their folder, favourite mark or one-time code.
- **The trash can empty itself.** A new setting removes items that have been in the trash for 30 days, 90 days or a year. It is off unless you turn it on.
- **The lock screen says why it locked** ("Locked after 5 minutes without activity", "Locked because Windows was locked or went to sleep"). The short message shown before was gone by the time you came back.

### Changed

- Checking an import for duplicates is fast now, also with thousands of entries. Before, a large import into a large vault could freeze the window for a long time.
- A CSV file that only has web address, user name and password columns no longer uses the user name as the title; the site name is used.
- While you type a Kurdish or Arabic title, a "Shown as" line under the box shows how it will look (the text box itself still shows the letters unjoined).
- The demo vault (`KeepForge.exe --demo`) has an item written in Kurdish.
- For people who build KeepForge themselves: `scripts\package.ps1` follows `CARGO_TARGET_DIR`.

### Fixed

- The item list jumped slightly while scrolling and could be scrolled past its last item into an empty area.
- CSV import: a semicolon-separated file with a comma inside a quoted heading, or with an empty first line, was read as one single column.

## [1.0.1] - 2026-11-16

### Changed

- Changing the master password, the key file or the key stretching now asks for the current master password (and key file) first, so someone at an unlocked KeepForge cannot lock you out.

### Fixed

- Dialogs no longer open as a large empty panel: each kind of dialog keeps its own size.

## [1.0.0] - 2026-11-16

### Added

- First release: an offline password manager for Windows with one encrypted vault file (XChaCha20-Poly1305, Argon2id), optional key file, logins, cards, identities, notes, Wi-Fi and licence keys, folders, tags, favourites, trash, attachments and password history.
- Password and passphrase generator, built-in authenticator (one-time codes), auto-type with a global hotkey, auto-lock and a clipboard that clears itself.
- Security dashboard, optional leaked-password and email breach checks, and tools: strength tester, text and file encryption, checksums, QR codes, secure shred, torrent exposure check.
- Import from browser and password manager CSV or JSON exports, encrypted and plain export, rolling backups, merge when two PCs changed the file.
- Installer and portable ZIP.

[1.2.0]: https://github.com/zheerkhalid/keepforge/releases/tag/v1.2.0
[1.1.0]: https://github.com/zheerkhalid/keepforge/releases/tag/v1.1.0
[1.0.1]: https://github.com/zheerkhalid/keepforge/releases/tag/v1.0.1
[1.0.0]: https://github.com/zheerkhalid/keepforge/releases/tag/v1.0.0
