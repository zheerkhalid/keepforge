# KeepForge security notes

**KeepForge has not been independently audited.** It is built from
well-known, reviewed building blocks (the RustCrypto crates), but the way
they are put together here, and the rest of the program, have been checked
only by its developer and by its own tests. Decide for yourself how much to
trust it, and keep backups.

The file formats are described byte for byte in [FORMAT.md](FORMAT.md).

## What KeepForge is designed to protect against

| Situation | What protects you |
|---|---|
| The vault file is stolen, lost with a laptop or USB stick, or copied from a backup | The file is encrypted with XChaCha20-Poly1305 under a key stretched from your master password with Argon2id (256 MiB, 3 passes, 4 lanes by default). Every guess costs the attacker that much work. How long the vault holds depends on the strength of the master password |
| The vault sits in a cloud-synced folder and the provider, or someone who breaks into the account, gets it | Same as above. Names, titles, user names and attachments are all inside the encrypted part; the plaintext header holds only format numbers, KDF settings, a salt and a nonce |
| Someone changes the file (bit rot, a bad sync, a deliberate edit, swapping in parts of an older copy) | The header carries a MAC and is bound to the content as associated data; the content and every attachment are authenticated. Any change is detected at unlock and the vault is not opened. Rolling backups sit next to the vault |
| Two devices change the vault through a synced folder | KeepForge notices that the file on disk is no longer the one it opened and offers to merge (newest version of each item wins), reload or overwrite, instead of overwriting blindly |
| Someone looks over your shoulder | Secrets are masked until you reveal them and hide again after a short time. The lock screen shows only the vault's name |
| Screenshots, screen recording, screen sharing | The window asks Windows to leave it out of captures (setting, on by default; Windows 10 2004 or later for full exclusion). A camera pointed at the screen is not stopped |
| Clipboard history and cloud clipboard | Copied secrets carry the markers that keep them out of Windows clipboard history and cloud sync, and are cleared after 20 seconds (setting) if the clipboard still holds them, and on lock and exit |
| You walk away from an unlocked PC | Auto-lock after idle time (5 minutes by default), and when Windows locks, sleeps, switches user or a remote session disconnects; optionally on minimise |
| Casual snooping by other programs running as you | The process denies memory-read, memory-write, handle-duplication and thread-creation access to other non-elevated programs of the same user, blocks legacy DLL injection points, and loads libraries by name from System32 only. This stops simple tools, not determined malware (see below) |
| A crash | Crash dialogs and Windows Error Reporting are turned off for the process, so a crash does not upload a memory dump |

## What KeepForge cannot protect against

- **Malware or a keylogger running as you while the vault is unlocked (or
  while you type the master password).** Such a program can read the
  keyboard, the screen and the clipboard, drive the KeepForge window, and,
  with enough effort, read the process's memory: the access restrictions
  above can be undone by a program that runs as the same user, because that
  user owns the process. No password manager can protect a compromised
  session.
- **A weak master password.** Argon2id makes every guess expensive; it does
  not make "summer2024" a good password. KeepForge refuses the very weakest
  ones and shows an estimate, but an estimate is not a guarantee.
- **A compromised operating system, administrator or hardware** (a rootkit,
  a malicious driver, a hardware keylogger, someone with administrator
  rights on the PC).
- **Losing the master password or the key file.** There is no recovery and
  no back door. Use the emergency sheet.
- **What you do with plaintext.** An unencrypted export, an attachment saved
  to disk, or a password pasted into another program is outside KeepForge.
- **Traffic analysis of the file.** The file's size (padded to 4 KiB, plus
  attachment sizes) and the time it changes are visible to anyone who can
  see the file.

## Design in brief

- **Key hierarchy.** Argon2id(password, salt, optional key-file digest as
  Argon2's secret input) gives a 64-byte master key; HKDF-SHA-256 with
  distinct labels derives the vault encryption key, the header MAC key and
  the attachment key. The master key is wiped as soon as these are derived.
- **Nonces.** A fresh random 192-bit nonce for every save and every
  attachment. A fresh random salt (and therefore new keys) whenever the
  password, key file or KDF settings change.
- **KDF limits.** Files asking for less than 19 MiB / 2 passes (the OWASP
  minimum), or for more than 1 GiB / 16 passes, open only after you confirm;
  settings beyond 4 GiB / 64 passes / 64 lanes are refused outright, before
  any memory is allocated.
- **Saving.** Write to a temporary file in the same folder, flush to disk,
  rename over the vault. A backup of the previous file is taken on the
  first save after unlocking and then at most once an hour.
- **One window per vault.** A named mutex stops a second KeepForge from
  opening the same file on the same PC.

## Secrets in memory, and the honest limits

What is done:

- The master password is typed into a fixed-size buffer that never
  reallocates and is wiped the moment it is handed to key derivation; the
  copy given to the worker thread is wiped right after Argon2 has run.
- Working keys live in their own memory pages, locked with `VirtualLock`
  (best effort) so they are not written to the page file, and are wiped
  before the pages are released.
- While a vault is unlocked, every secret in it (passwords, one-time-code
  seeds, notes, hidden fields, card numbers, recovery codes, attachments)
  stays encrypted in memory under a random key that exists only for that
  session, and is decrypted only at the moment it is shown, copied, typed
  or saved.
- Locking wipes the session key first. From then on, every encrypted secret
  of that session is unreadable, even a copy that some part of the program
  might still hold. Then the whole unlocked state, including any open edit
  form, is dropped, and the toolkit's text-field state is cleared. A test
  checks that nothing of the vault object survives a lock.

What cannot be done, and you should know:

- The user-interface toolkit (egui) works with ordinary strings. A secret
  that is **revealed on screen** is copied into the toolkit's text layout
  and glyph caches for as long as it is shown; those copies are freed, not
  wiped. Text pasted into KeepForge arrives through an ordinary string.
  KeepForge clears the toolkit's undo history for secret fields after every
  frame and keeps its own copies in wiping buffers, but it cannot wipe the
  toolkit's internals.
- Kurdish, Arabic and other right-to-left text is drawn by Windows (GDI)
  into small bitmaps, because the toolkit cannot join those letters. The
  bitmaps are a second copy of what is on screen: those of a revealed secret
  (a note, a hidden field) are dropped as soon as it is hidden again, and
  all of them when the vault locks. Like the toolkit's own caches they are
  freed, not wiped.
- The Generator page keeps the last 8 passwords you copied from it. They are
  encrypted in memory under the session key like every other secret, never
  written to disk, and unreadable once the vault locks.
- The password strength estimator (zxcvbn), the CBOR and JSON encoders and
  the Windows clipboard make short-lived ordinary copies of what they
  process. They are freed, not wiped.
- Freed memory is not erased by Windows; hibernation and crash dumps taken
  by an administrator can capture the memory of a running, unlocked
  KeepForge. Full-disk encryption (BitLocker) is the protection for
  hibernation files and the page file.
- `VirtualLock`, the mitigation policies and the access restrictions are
  best effort. Their outcome is listed in Settings › Process protection and
  in `keepforge.log` in the settings folder (the log holds no secrets).
- The wait after wrong password attempts on the lock screen is a courtesy
  against someone typing guesses at your keyboard. It does nothing against
  an attacker who has the file; Argon2id is what slows them down.
- Changing the master password, key file or key stretching asks for the
  current master password (and key file) first. This stops someone at an
  unlocked KeepForge from locking you out; they can still read and export
  what is open, so lock the vault when you leave. Backups made earlier
  still open with the old password.
- "Block dynamically generated code" is off by default because some graphics
  drivers need to generate code. If a start does not get as far as drawing
  the window, the next start runs in compatibility mode (no library-path
  restriction, no dynamic-code block) and says so.
- With the access restrictions in place, `taskkill /F` and PowerShell's
  `Stop-Process` from a non-elevated prompt report "Access is denied",
  because they ask for more access than they need. Task Manager, closing
  the window, and an elevated prompt still work.
- Windows Hello quick unlock is not included. A sound version needs a key
  that is itself protected by Hello, not a consent prompt in front of a
  stored key; that has not been built.

## Network use

KeepForge makes **no network connection on its own**: no update check, no
telemetry, no icon downloads (the only exception is a periodic re-check you
can turn on yourself, below). The installer and the program work on a PC
without internet. All connections go through one small client
(`src/net.rs`) on top of WinHTTP, the TLS stack that ships with Windows:
HTTPS only, certificate checks at the system defaults, TLS 1.2 or later, no
redirects, no cookies, fixed timeouts, capped response size, User-Agent
`KeepForge`. Everything received is treated as untrusted text: parsed
strictly, stripped of control characters, cut to length and only ever shown
as plain text.

The optional features below use it. Every one of them is **off until you
turn it on** (Settings › Online checks, or the "Choose which services to
ask" box the first time you press Check), and each runs only when you press
a button. The single exception is the optional periodic re-check of the
Exposure check, which is off by default and, when you turn it on, runs at
most once per unlock when the last full check is older than the period you
chose.

| Feature | Sent | To | Not sent |
|---|---|---|---|
| Password check with Pwned Passwords (dashboard, strength tester, Exposure check) | The first 5 hex characters of the SHA-1 hash of each checked password, with padding requested so response sizes say nothing | `api.pwnedpasswords.com` (Have I Been Pwned) | The password, the rest of the hash, user names, site names. The match is made locally; padded (count 0) lines are discarded |
| Password check with XposedOrNot (Exposure check, off by default) | The first 10 hex characters of the password's Keccak-512 hash | `passwords.xposedornot.com` | The password and the rest of the hash. 10 characters are far more specific than Pwned Passwords' 5: few passwords share them, so the service could tell whether you checked a common password. The settings text says so |
| Password check with Enzoic (your own key) | The first 10 hex characters of the password's SHA-256 hash, and your key | `api.enzoic.com` | The password and the rest of the hash. The service answers with the full hashes in that bucket and the match is made locally |
| Exposure check: XposedOrNot | The email address you check | `api.xposedornot.com` | Everything else |
| Exposure check: LeakCheck public API | The email address or user name you check | `leakcheck.io` | Everything else. The public API answers with breach names and months only |
| Exposure check: Hudson Rock | The email address, user name or domain you check | `cavalier.hudsonrock.com` | Everything else. Its answer contains masked passwords, logins, IP addresses and file paths of the infected computer: KeepForge's parser does not read those fields, so they are never shown or stored |
| Exposure check: Have I Been Pwned (sites) | The domain you check, or nothing at all for "Compare my saved sites", which downloads the public list of every breach once and compares it with your saved web addresses on this PC | `haveibeenpwned.com` | Your saved web addresses and everything else |
| Exposure check: Have I Been Pwned (your own key) | The email address you check and your key (breaches, pastes, and stealer-log sites where your plan includes them) | `haveibeenpwned.com` | Everything else |
| Exposure check: Leak-Lookup (your own key) | The email address, user name, phone number or domain you check, and your key | `leak-lookup.com` | Everything else. Only breach names are read; anything else in an answer is ignored |
| Where a user name is registered | The user name you check, once to each of about 550 websites (the public profile address from the bundled WhatsMyName list), six at a time | Those websites | Everything else. Sites that need a login, a POST request or a CAPTCHA, or that the list marks as bot-protected, are skipped; no browser identity is faked |
| Torrent exposure check | The public IP address you type and your own API key, at most one request per 2 s | The iknowwhatyoudownload.com Peer API (host `api.antitor.com` unless you enter another) | Anything from the vault. The key is stored only inside the encrypted vault. Private, loopback, link-local and reserved addresses are refused locally. No bulk lookup, history or monitoring exists |

How the Exposure check keeps to the rules:

- Each source runs on its own thread with its own pause between requests
  (from 1.5 s up to 13 s for Leak-Lookup's free key); a source that answers
  "too many requests" twice is not asked again in that run.
- Keys are stored only in the encrypted vault (`service_keys`), never in the
  settings file, and are checked for odd characters before use so they
  cannot inject request headers.
- Results are saved inside the encrypted vault (the `exposure` field, see
  `docs/FORMAT.md`) so you can see them later; you can forget any result.
- Everything that comes back is parsed strictly, cut to length and shown as
  plain text; links are only opened when you click them, and only `https://`
  links from a source are kept.
- Services whose terms forbid this use, that require scraping, or that
  return leaked passwords, hashes or other people's records (for example
  DeHashed, Snusbase, BreachDirectory, ProxyNova COMB, Intelligence X) are
  not used. The research behind these choices is summarised in the 1.2.0
  changelog entry.

Each service necessarily sees your IP address. The torrent data comes from
the public DHT and peer exchange, is unconfirmed, and may belong to other
people who shared the address; names of items in the worst content category
are dropped by the parser and never displayed.

## Reporting a problem

Please report security problems privately to the developer through
https://zheer.dev rather than in a public issue.
