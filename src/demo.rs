//! Invented data for `--demo` and screenshots. Nothing here comes from the
//! PC it runs on, nothing is written to disk and nothing is sent anywhere.

use crate::breach::Breach;
use crate::exposure::sites::{SiteHit, SiteScan};
use crate::exposure::{Answer, Cache, Finding, FindingKind, QueryKind, SourceError, SourceId};
use crate::model::{CustomField, Item, Kind, RecoveryCode, Vault};
use crate::secret::{Protected, SessionKey};
use crate::torrent::{ContentClass, PeerItem, PeerReport};
use crate::util::{self, DAY};
use std::sync::Arc;

pub const DEMO_EMAIL: &str = "alex.morgan@example.com";
/// Title of the demo item written in Kurdish ("work email").
pub const DEMO_KURDISH_TITLE: &str =
    "\u{626}\u{6CC}\u{645}\u{6D5}\u{6CC}\u{6B5}\u{6CC} \u{6A9}\u{627}\u{631}";

pub const DEMO_PATH: &str = "C:\\Users\\Alex\\Documents\\Personal.kfv";

#[allow(clippy::too_many_arguments)]
fn login(
    s: &Arc<SessionKey>,
    now: i64,
    title: &str,
    user: &str,
    password: &str,
    url: &str,
    age_days: i64,
    totp: &str,
) -> Item {
    let mut i = Item::new(Kind::Login, now - age_days * DAY - 40 * DAY);
    i.title = title.into();
    i.username = user.into();
    i.password = Protected::seal_str(s, password);
    i.password_changed = now - age_days * DAY;
    i.modified = now - age_days * DAY;
    i.urls = vec![url.into()];
    i.totp = Protected::seal_str(s, totp);
    i
}

/// The demo vault: about twenty invented items of every type.
pub fn vault(s: &Arc<SessionKey>, now: i64) -> Vault {
    let mut v = Vault::new("Personal", now - 900 * DAY);
    let personal = v.folder_id("Personal");
    let work = v.folder_id("Work");
    let finance = v.folder_id("Finance");

    let mut mail = login(
        s,
        now,
        "Example Mail",
        DEMO_EMAIL,
        "tU9#vqLr2!xWmZ6p",
        "https://mail.example.com",
        64,
        "JBSWY3DPEHPK3PXP",
    );
    mail.favourite = true;
    mail.folder = personal;
    mail.tags = vec!["mail".into(), "2fa".into()];
    mail.notes = Protected::seal_str(s, "Recovery address is the family mailbox.\nSecurity question answers are in the custom fields.");
    mail.fields
        .push(CustomField::plain("Plan", "Family (5 mailboxes)"));
    mail.fields
        .push(CustomField::hidden(s, "Security answer", "blue heron 1987"));
    mail.history.push(crate::model::HistoryEntry {
        password: Protected::seal_str(s, "Summer-Mail-2022"),
        replaced: now - 64 * DAY,
    });
    mail.history.push(crate::model::HistoryEntry {
        password: Protected::seal_str(s, "mailbox2019"),
        replaced: now - 700 * DAY,
    });
    for (code, used) in [
        ("4821-7730", true),
        ("9056-1142", false),
        ("3370-8891", false),
        ("6104-2259", false),
    ] {
        mail.recovery_codes.push(RecoveryCode {
            code: Protected::seal_str(s, code),
            used,
        });
    }
    v.items.push(mail);

    let mut photo = login(
        s,
        now,
        "Photo Cloud",
        DEMO_EMAIL,
        "PhotoCloud2018",
        "https://photocloud.example/login",
        2900,
        "",
    );
    photo.folder = personal;
    photo.tags = vec!["family".into()];
    v.items.push(photo);

    let mut bank = login(
        s,
        now,
        "Sample Bank",
        "amorgan84",
        "Hx4$wP!z9Qm@7LrT2vNe",
        "https://online.samplebank.example",
        120,
        "KRSXG5CTMVRXEZLU",
    );
    bank.favourite = true;
    bank.folder = finance;
    bank.tags = vec!["2fa".into()];
    v.items.push(bank);

    let mut shop = login(
        s,
        now,
        "Example Shop",
        DEMO_EMAIL,
        "orchid-tunnel-magnet-41",
        "https://www.shop.example",
        300,
        "",
    );
    shop.folder = personal;
    shop.tags = vec!["shopping".into()];
    v.items.push(shop);

    let mut travel = login(
        s,
        now,
        "Travel Booker",
        DEMO_EMAIL,
        "Kd8!rVz3#nQ1mTy6",
        "https://travelbooker.example",
        210,
        "",
    );
    travel.folder = personal;
    v.items.push(travel);

    let mut stream = login(
        s,
        now,
        "Stream Box",
        "alexm",
        "movie-night-77",
        "https://streambox.example",
        500,
        "",
    );
    stream.folder = personal;
    stream.tags = vec!["family".into()];
    v.items.push(stream);

    let mut music = login(
        s,
        now,
        "Music Corner",
        "alexm",
        "movie-night-77",
        "https://musiccorner.example",
        480,
        "",
    );
    music.folder = personal;
    v.items.push(music);

    let mut git = login(
        s,
        now,
        "Dev Forge",
        "alex-morgan",
        "f7Q!mZx2@Lp9#wRt5Ks",
        "https://devforge.example",
        30,
        "GEZDGNBVGY3TQOJQ",
    );
    git.folder = work;
    git.favourite = true;
    git.tags = vec!["2fa".into()];
    v.items.push(git);

    let mut chat = login(
        s,
        now,
        "Workspace Chat",
        "alex.morgan@northwind.example",
        "Bq6@tHn1!vXs8Dz4",
        "https://chat.northwind.example",
        95,
        "",
    );
    chat.folder = work;
    v.items.push(chat);

    let mut vpn = login(
        s,
        now,
        "Company VPN",
        "amorgan",
        "Zp3#kWv8!rTq5Ny1",
        "https://vpn.northwind.example",
        20,
        "MFRGGZDFMZTWQ2LK",
    );
    vpn.folder = work;
    vpn.tags = vec!["2fa".into()];
    vpn.autotype = "{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}".into();
    v.items.push(vpn);

    let mut forum = login(
        s,
        now,
        "Pixel Forum",
        "alex_m",
        "sunshine1",
        "https://pixelforum.example",
        3000,
        "",
    );
    forum.folder = personal;
    v.items.push(forum);

    let mut library = login(s, now, "City Library", "20481573", "", "", 400, "");
    library.folder = personal;
    v.items.push(library);

    // A card that expires next month, so the dashboard has something to show.
    let (y, m, _) = util::civil_from_days((now + 2 * DAY).div_euclid(DAY));
    let mut card = Item::new(Kind::Card, now - 700 * DAY);
    card.title = "Sample Bank debit card".into();
    card.folder = finance;
    card.fields[0].value = "Alex Morgan".into();
    card.fields[1].secret = Protected::seal_str(s, "4000 0012 3456 7899");
    card.fields[2].value = format!("{m:02}/{:02}", y % 100);
    card.fields[3].secret = Protected::seal_str(s, "318");
    card.fields[4].secret = Protected::seal_str(s, "5067");
    card.modified = now - 300 * DAY;
    v.items.push(card);

    let mut credit = Item::new(Kind::Card, now - 200 * DAY);
    credit.title = "Travel credit card".into();
    credit.folder = finance;
    credit.fields[0].value = "Alex Morgan".into();
    credit.fields[1].secret = Protected::seal_str(s, "5100 0045 6789 0123");
    credit.fields[2].value = format!("09/{:02}", (y + 3) % 100);
    credit.fields[3].secret = Protected::seal_str(s, "742");
    credit.modified = now - 200 * DAY;
    v.items.push(credit);

    let mut me = Item::new(Kind::Identity, now - 800 * DAY);
    me.title = "Alex Morgan".into();
    me.folder = personal;
    me.fields[0].value = "Alex Morgan".into();
    me.fields[1].value = DEMO_EMAIL.into();
    me.fields[2].value = "+1 555 0142".into();
    me.fields[3].value = "12 Sample Street, Springfield".into();
    me.fields[4].value = "14 March 1984".into();
    me.fields[5].secret = Protected::seal_str(s, "X1234567");
    me.modified = now - 400 * DAY;
    v.items.push(me);

    let mut shed = Item::new(Kind::Note, now - 100 * DAY);
    shed.title = "Garden shed and bike lock".into();
    shed.folder = personal;
    shed.notes = Protected::seal_str(s, "Shed padlock: 2468\nBike lock: 7 - 1 - 9 - 3");
    shed.modified = now - 100 * DAY;
    v.items.push(shed);

    let mut wifi = Item::new(Kind::Wifi, now - 350 * DAY);
    wifi.title = "Home Wi-Fi".into();
    wifi.folder = personal;
    wifi.username = "Morgan-Home".into();
    wifi.password = Protected::seal_str(s, "maple-kettle-harbor-29");
    wifi.password_changed = now - 350 * DAY;
    wifi.fields[0].value = "WPA2".into();
    wifi.modified = now - 350 * DAY;
    wifi.tags = vec!["family".into()];
    v.items.push(wifi);

    let mut licence = Item::new(Kind::Licence, now - 150 * DAY);
    licence.title = "Photo Editor Pro".into();
    licence.folder = personal;
    licence.username = "Alex Morgan".into();
    licence.password = Protected::seal_str(s, "PEP5-K7QW-93LX-ZT2M-HB64");
    licence.fields[0].value = "Photo Editor Pro".into();
    licence.fields[1].value = "5".into();
    licence.expires = Some(now + 12 * DAY);
    licence.modified = now - 150 * DAY;
    v.items.push(licence);

    let mut api = Item::new(Kind::Licence, now - 60 * DAY);
    api.title = "Weather API key".into();
    api.folder = work;
    api.username = "northwind-dashboard".into();
    api.password = Protected::seal_str(s, "wx_live_5f2c9a71e04b4d6c8a13b7e2f90d");
    api.urls = vec!["https://api.weather.example".into()];
    api.fields[0].value = "Weather API".into();
    api.modified = now - 60 * DAY;
    v.items.push(api);

    // A Kurdish title, user name, tag and note: right-to-left text.
    let mut kurdish = login(
        s,
        now,
        DEMO_KURDISH_TITLE,
        "\u{626}\u{627}\u{6B5}\u{6CE}\u{6A9}\u{633}",
        "qN4!zVb7#Lw2@Hs9",
        "https://posta.example",
        21,
        "",
    );
    kurdish.folder = work;
    kurdish.tags = vec!["\u{6A9}\u{627}\u{631}".into()];
    kurdish.notes = Protected::seal_str(
        s,
        "\u{626}\u{6D5}\u{645} \u{6BE}\u{6D5}\u{698}\u{645}\u{627}\u{631}\u{6D5} \u{628}\u{6C6} \u{6A9}\u{627}\u{631}\u{6CC} \u{695}\u{6C6}\u{698}\u{627}\u{646}\u{6D5}\u{6CC}\u{6D5}.",
    );
    kurdish.fields.push(CustomField::plain(
        "\u{628}\u{6D5}\u{634}",
        "\u{6A9}\u{627}\u{631}\u{6AF}\u{6CE}\u{695}\u{6CC}",
    ));
    v.items.push(kurdish);

    let mut old = login(
        s,
        now,
        "Old Blog",
        "alexm",
        "blogger123",
        "https://oldblog.example",
        2000,
        "",
    );
    old.deleted = Some(now - 3 * DAY);
    v.items.push(old);

    v
}

/// Invented breach results for the demo email address.
pub fn breaches() -> Vec<Breach> {
    vec![
        Breach {
            name: "PhotoCloud".into(),
            domain: "photocloud.example".into(),
            year: Some(2021),
            records: 4_812_300,
            exposed: vec!["Email addresses".into(), "Passwords".into(), "Usernames".into()],
            industry: "Photo hosting".into(),
            password_risk: "easytocrack".into(),
            description: "Photo Cloud, an invented photo hosting service, had its user database copied in 2021. The data included email addresses, user names and weakly protected passwords.".into(),
            reference: String::new(),
        },
        Breach {
            name: "PixelForum".into(),
            domain: "pixelforum.example".into(),
            year: Some(2019),
            records: 356_000,
            exposed: vec!["Email addresses".into(), "Passwords".into(), "IP addresses".into()],
            industry: "Community".into(),
            password_risk: "plaintext".into(),
            description: "Pixel Forum, an invented hobby forum, exposed its member list in 2019, including passwords stored without protection.".into(),
            reference: String::new(),
        },
        Breach {
            name: "ExampleShop".into(),
            domain: "shop.example".into(),
            year: Some(2017),
            records: 1_250_000,
            exposed: vec!["Email addresses".into(), "Names".into(), "Phone numbers".into(), "Physical addresses".into()],
            industry: "Retail".into(),
            password_risk: "unknown".into(),
            description: "An invented online shop leaked order records in 2017: names, postal addresses and phone numbers. Passwords were not part of it.".into(),
            reference: String::new(),
        },
    ]
}

/// The online sources switched on in the demo.
pub const DEMO_SOURCES: [&str; 7] = [
    "xposedornot",
    "leakcheck",
    "hudsonrock",
    "hibp-domain",
    "hibp",
    "whatsmyname",
    "pw-xposedornot",
];

fn found(
    source: SourceId,
    name: &str,
    domain: &str,
    date: &str,
    data: &[&str],
    text: &str,
) -> Finding {
    Finding {
        source,
        kind: FindingKind::Breach,
        name: name.into(),
        domain: domain.into(),
        date: date.into(),
        data: data.iter().map(|d| d.to_string()).collect(),
        description: text.into(),
        ..Default::default()
    }
}

/// Invented answers of the Exposure check sources. The demo never goes online.
pub fn exposure_answer(
    source: SourceId,
    kind: QueryKind,
    value: &str,
) -> Result<Answer, SourceError> {
    use QueryKind::*;
    use SourceId::*;
    let of = |findings: Vec<Finding>| {
        Ok(Answer {
            findings,
            note: String::new(),
        })
    };
    match (source, kind, value) {
        (Hibp, _, _) | (LeakLookup, _, _) => Err(SourceError::NeedsKey),
        (XposedOrNot, Email, DEMO_EMAIL) => of(breaches()
            .into_iter()
            .map(|b| Finding {
                source: XposedOrNot,
                kind: FindingKind::Breach,
                date: b.year.map(|y| y.to_string()).unwrap_or_default(),
                records: b.records,
                facts: vec![b.industry.clone()],
                password_risk: b.password_risk.clone(),
                name: b.name,
                domain: b.domain,
                data: b.exposed,
                description: b.description,
                ..Default::default()
            })
            .collect()),
        (LeakCheck, Email, DEMO_EMAIL) => Ok(Answer {
            findings: vec![
                found(LeakCheck, "PhotoCloud.example", "", "2021-03", &[], ""),
                found(LeakCheck, "Shop.example", "", "2017-08", &[], ""),
                found(LeakCheck, "TravelBooker.example", "", "2023-05", &[], ""),
            ],
            note: "Across these breaches LeakCheck saw: passwords, names, phone numbers. It does not say which breach held what.".into(),
        }),
        (HudsonRock, Email, DEMO_EMAIL) => of(vec![Finding {
            source: HudsonRock,
            kind: FindingKind::Stealer,
            name: "Infostealer infection".into(),
            date: "2025-02-14".into(),
            data: vec!["Passwords".into(), "Browser cookies".into(), "Usernames".into()],
            description: "Malware on a computer linked to this value copied the logins and cookies saved there.".into(),
            facts: vec![
                "System: Windows 10 Home".into(),
                "Computer: LAPTOP-EXAMPLE".into(),
                "Malware: an invented stealer".into(),
                "38 saved logins taken (0 work)".into(),
            ],
            ..Default::default()
        }]),
        (LeakCheck, Username, "alex_m") => of(vec![found(LeakCheck, "PixelForum.example", "", "2019-11", &[], "")]),
        (HibpDomain, Domain, "photocloud.example") => of(vec![Finding {
            source: HibpDomain,
            kind: FindingKind::SiteBreach,
            ..found(HibpDomain, "Photo Cloud", "photocloud.example", "2021-03-12", &["Email addresses", "Passwords", "Usernames"], "In March 2021, the invented Photo Cloud service had its user database copied.")
        }]),
        _ => of(Vec::new()),
    }
}

/// Invented "where is this user name registered" hits.
pub fn site_hits(username: &str) -> Vec<SiteHit> {
    if username != "alex_m" {
        return Vec::new();
    }
    [
        ("GitHub", "coding", "https://github.com/"),
        ("Reddit", "social", "https://www.reddit.com/user/"),
        ("Chess.com", "gaming", "https://www.chess.com/member/"),
        ("Duolingo", "hobby", "https://www.duolingo.com/profile/"),
        ("SoundCloud", "music", "https://soundcloud.com/"),
    ]
    .iter()
    .map(|(name, cat, url)| SiteHit {
        name: name.to_string(),
        category: cat.to_string(),
        url: format!("{url}{username}"),
    })
    .collect()
}

/// Invented breaches of sites saved in the demo vault (as if from the
/// public list of breached sites).
pub fn site_breaches() -> Vec<Finding> {
    vec![
        Finding {
            kind: FindingKind::SiteBreach,
            ..found(
                SourceId::HibpDomain,
                "Photo Cloud",
                "photocloud.example",
                "2021-03-12",
                &["Email addresses", "Passwords", "Usernames"],
                "In March 2021, the invented Photo Cloud service had its user database copied.",
            )
        },
        Finding {
            kind: FindingKind::SiteBreach,
            ..found(
                SourceId::HibpDomain,
                "Pixel Forum",
                "pixelforum.example",
                "2019-11-02",
                &["Email addresses", "IP addresses", "Passwords"],
                "The invented Pixel Forum exposed its member list in November 2019.",
            )
        },
    ]
}

/// A demo cache as if the address and a user name had been checked.
pub fn exposure_cache(now: i64) -> Cache {
    let mut c = Cache::default();
    for (kind, value) in [
        (QueryKind::Username, "alex_m"),
        (QueryKind::Email, DEMO_EMAIL),
    ] {
        let r = c.record_mut(kind, value, now - 3600);
        r.checked = now - 3600;
        for source in SourceId::ALL {
            if source.supports(kind) && (source.key_name().is_none() || source == SourceId::Hibp) {
                r.apply(source, exposure_answer(source, kind, value));
            }
        }
    }
    let r = c.record_mut(QueryKind::Username, "alex_m", now);
    r.sites = Some(SiteScan {
        when: now - 3500,
        asked: 557,
        unclear: 61,
        found: site_hits("alex_m"),
        complete: true,
    });
    c.site_breaches = site_breaches();
    c.sites_checked = now - 3600;
    c.last_all = now - 3600;
    c
}

/// An invented, harmless torrent exposure result.
pub fn peer_report() -> PeerReport {
    let item = |name: &str, category: &str, first: &str, last: &str, size: u64| PeerItem {
        name: name.into(),
        category: category.into(),
        first_seen: first.into(),
        last_seen: last.into(),
        size: Some(size),
        class: ContentClass::Normal,
    };
    PeerReport {
        ip: "93.184.216.34".into(),
        isp: "Example Broadband".into(),
        country: "Exampleland".into(),
        city: "Springfield".into(),
        items: vec![
            item(
                "Open-source Linux ISO (desktop, 64-bit)",
                "PC",
                "2026-11-02",
                "2026-11-09",
                4_700_000_000,
            ),
            item(
                "Public-domain film (1925, restored)",
                "Movies",
                "2026-11-05",
                "2026-11-05",
                1_450_000_000,
            ),
            item(
                "Creative Commons music collection",
                "Music",
                "2026-10-28",
                "2026-11-01",
                310_000_000,
            ),
            item(
                "Free e-book bundle: classic novels",
                "Books",
                "2026-10-21",
                "2026-10-22",
                48_000_000,
            ),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_vault_is_complete_and_invented() {
        let s = SessionKey::new();
        let v = vault(&s, 1_800_000_000);
        for kind in Kind::ALL {
            assert!(v.items.iter().any(|i| i.kind == kind), "{kind:?}");
        }
        assert!(v.items.iter().any(|i| i.in_trash()));
        assert!(v.items.iter().any(|i| !i.recovery_codes.is_empty()));
        assert!(v.items.iter().any(|i| i.title == DEMO_KURDISH_TITLE));
        assert_eq!(
            v.emails(),
            vec![
                DEMO_EMAIL.to_string(),
                "alex.morgan@northwind.example".to_string()
            ]
        );
        // Every address is on a reserved example domain.
        for i in &v.items {
            for u in &i.urls {
                assert!(
                    u.is_empty()
                        || util::host_of(u).ends_with(".example")
                        || util::host_of(u).ends_with("example.com"),
                    "{u}"
                );
            }
        }
        // The demo breaches line up with demo items.
        let flagged = crate::breach::items_to_change(&v, breaches().iter());
        assert_eq!(flagged.len(), 2);
        assert!(!peer_report().items.is_empty());
        // The demo exposure results line up with demo items too.
        let cache = exposure_cache(1_800_000_000);
        let exposures = cache.all_exposures();
        assert!(exposures
            .iter()
            .any(|(_, _, e)| e.kind == FindingKind::Stealer));
        let merged: Vec<crate::exposure::Exposure> =
            exposures.into_iter().map(|(_, _, e)| e).collect();
        let change = crate::exposure::items_to_change(&v, merged.iter());
        assert!(change.len() >= 2, "{change:?}");
        assert!(crate::exposure::breaches_for_vault(&v, &site_breaches()).len() == 2);
    }
}
