//! One client per breach source. Each turns a value into a request and the
//! answer into [`Finding`]s; the network is behind [`Transport`].
//!
//! Only official, documented APIs are used, and only the parts that say
//! *where* something leaked. Nothing that returns leaked passwords, hashes or
//! other people's records is asked for or kept.

use super::{Finding, FindingKind, QueryKind, SourceError, SourceId, Transport};
use crate::net::{NetError, Response};
use crate::totp::percent_encode;
use crate::util;
use serde::Deserialize;

pub const XON_HOST: &str = crate::breach::HOST;
pub const LEAKCHECK_HOST: &str = "leakcheck.io";
pub const HUDSON_HOST: &str = "cavalier.hudsonrock.com";
pub const HIBP_HOST: &str = "haveibeenpwned.com";
pub const LEAKLOOKUP_HOST: &str = "leak-lookup.com";

/// No source gets to list more than this many results for one value.
pub const MAX_FINDINGS: usize = 600;
const MAX_BODY: usize = 8 * 1024 * 1024;

/// What one source said about one value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Answer {
    pub findings: Vec<Finding>,
    /// A remark shown with the source's result (for example which kinds of
    /// data it saw overall).
    pub note: String,
}

impl Answer {
    fn of(findings: Vec<Finding>) -> Answer {
        Answer {
            findings,
            note: String::new(),
        }
    }
}

fn net_error(e: NetError) -> SourceError {
    SourceError::Net(e.to_string())
}

/// Status codes every source treats the same way.
fn common_status(status: u32) -> Result<(), SourceError> {
    match status {
        200 => Ok(()),
        401 => Err(SourceError::BadKey),
        429 => Err(SourceError::RateLimited),
        other => Err(SourceError::Service(other)),
    }
}

/// Looks `value` up at `source`. `between` is called before every request
/// after the first one (the caller uses it to keep to rate limits).
pub fn check(
    source: SourceId,
    t: &dyn Transport,
    kind: QueryKind,
    value: &str,
    key: Option<&str>,
    between: &dyn Fn(),
) -> Result<Answer, SourceError> {
    if !source.supports(kind) {
        return Err(SourceError::Unsupported);
    }
    let value = kind
        .normalize(value)
        .map_err(|_| SourceError::Unsupported)?;
    if source.key_name().is_some() && key.map(str::trim).unwrap_or("").is_empty() {
        return Err(SourceError::NeedsKey);
    }
    let key = key.map(str::trim).unwrap_or("");
    match source {
        SourceId::XposedOrNot => xposedornot(t, &value),
        SourceId::LeakCheck => leakcheck(t, &value),
        SourceId::HudsonRock => hudson_rock(t, kind, &value),
        SourceId::HibpDomain => hibp_domain(t, &value),
        SourceId::Hibp => hibp_account(t, kind, &value, key, between),
        SourceId::LeakLookup => leak_lookup(t, kind, &value, key),
        SourceId::Unknown => Err(SourceError::Unsupported),
    }
}

// --------------------------------------------------------------------------------------
// Small helpers for untrusted text
// --------------------------------------------------------------------------------------

/// Plain text from a short HTML fragment: tags dropped, common entities decoded.
pub fn strip_html(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut in_tag = false;
    for c in html.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
}

/// Keeps only https links without spaces or quotes.
fn safe_link(url: &str) -> String {
    let u = url.trim();
    if u.len() <= 300
        && u.to_lowercase().starts_with("https://")
        && !u
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || c == '"')
    {
        u.to_string()
    } else {
        String::new()
    }
}

/// `YYYY`, `YYYY-MM` or `YYYY-MM-DD` from the start of a date text, or empty.
pub fn tidy_date(text: &str) -> String {
    let t = text.trim();
    let ok = |s: &str, len: usize| {
        s.len() >= len
            && s[..len].chars().enumerate().all(|(i, c)| {
                if i == 4 || i == 7 {
                    c == '-'
                } else {
                    c.is_ascii_digit()
                }
            })
    };
    let take = if ok(t, 10) {
        10
    } else if ok(t, 7) {
        7
    } else if ok(t, 4) {
        4
    } else {
        return String::new();
    };
    let year: i64 = t[..4].parse().unwrap_or(0);
    if (1980..=2100).contains(&year) {
        t[..take].to_string()
    } else {
        String::new()
    }
}

// --------------------------------------------------------------------------------------
// XposedOrNot (free, no key)
// --------------------------------------------------------------------------------------

fn xposedornot(t: &dyn Transport, email: &str) -> Result<Answer, SourceError> {
    let path = format!("/v1/breach-analytics?email={}", percent_encode(email));
    let r = t
        .get(XON_HOST, &path, &["Accept: application/json"], MAX_BODY)
        .map_err(net_error)?;
    parse_xposedornot(r.status, &r.body)
}

pub fn parse_xposedornot(status: u32, body: &[u8]) -> Result<Answer, SourceError> {
    use crate::breach::{BreachError, EmailResult};
    match crate::breach::parse_analytics(status, body) {
        Ok(EmailResult::NotFound) => Ok(Answer::default()),
        Ok(EmailResult::Found(list)) => Ok(Answer::of(
            list.into_iter()
                .map(|b| Finding {
                    source: SourceId::XposedOrNot,
                    kind: FindingKind::Breach,
                    link: safe_link(&b.reference),
                    name: b.name,
                    domain: b.domain,
                    date: b.year.map(|y| y.to_string()).unwrap_or_default(),
                    records: b.records,
                    data: b.exposed,
                    description: b.description,
                    facts: if b.industry.is_empty() {
                        Vec::new()
                    } else {
                        vec![b.industry]
                    },
                    password_risk: b.password_risk,
                })
                .collect(),
        )),
        Err(BreachError::RateLimited) => Err(SourceError::RateLimited),
        Err(BreachError::Malformed) => Err(SourceError::Malformed),
        Err(BreachError::Service(c)) => Err(SourceError::Service(c)),
        Err(BreachError::Net(e)) => Err(SourceError::Net(e)),
        Err(BreachError::BadEmail) => Err(SourceError::Unsupported),
    }
}

// --------------------------------------------------------------------------------------
// LeakCheck public API (free, no key): breach names and dates only
// --------------------------------------------------------------------------------------

fn leakcheck(t: &dyn Transport, value: &str) -> Result<Answer, SourceError> {
    let path = format!("/api/public?check={}", percent_encode(value));
    let r = t
        .get(
            LEAKCHECK_HOST,
            &path,
            &["Accept: application/json"],
            MAX_BODY,
        )
        .map_err(net_error)?;
    parse_leakcheck(r.status, &r.body)
}

#[derive(Deserialize)]
struct LeakCheckAnswer {
    success: bool,
    #[serde(default)]
    error: String,
    #[serde(default)]
    fields: Vec<String>,
    #[serde(default)]
    sources: Vec<LeakCheckSource>,
}

#[derive(Deserialize)]
struct LeakCheckSource {
    name: String,
    #[serde(default)]
    date: String,
}

pub fn parse_leakcheck(status: u32, body: &[u8]) -> Result<Answer, SourceError> {
    if status == 404 {
        return Ok(Answer::default());
    }
    common_status(status)?;
    let a: LeakCheckAnswer = serde_json::from_slice(body).map_err(|_| SourceError::Malformed)?;
    if !a.success {
        let e = a.error.to_lowercase();
        return if e.contains("not found") {
            Ok(Answer::default())
        } else if e.contains("limit") || e.contains("too many") {
            Err(SourceError::RateLimited)
        } else if e.contains("invalid") || e.contains("characters") || e.contains("short") {
            Err(SourceError::Unsupported)
        } else {
            Err(SourceError::Malformed)
        };
    }
    let findings: Vec<Finding> = a
        .sources
        .into_iter()
        .take(MAX_FINDINGS)
        .map(|s| Finding {
            source: SourceId::LeakCheck,
            kind: FindingKind::Breach,
            name: util::clean_remote(&s.name, 80),
            date: tidy_date(&s.date),
            ..Default::default()
        })
        .filter(|f| !f.name.is_empty())
        .collect();
    // The kinds of data are given for all results together, not per breach.
    let mut kinds: Vec<String> = Vec::new();
    for f in a.fields.iter().take(40) {
        let label = match f.to_lowercase().as_str() {
            "password" => "passwords",
            "phone" => "phone numbers",
            "address" | "city" | "zip" | "state" => "postal addresses",
            "dob" => "dates of birth",
            "ip" | "ip1" | "ip2" => "IP addresses",
            "ssn" => "national ID numbers",
            "username" | "profile_name" => "user names",
            "first_name" | "last_name" | "middle_name" | "name" => "names",
            _ => continue,
        };
        if !kinds.iter().any(|k| k == label) {
            kinds.push(label.to_string());
        }
    }
    let note = if findings.is_empty() || kinds.is_empty() {
        String::new()
    } else {
        format!(
            "Across these breaches LeakCheck saw: {}. It does not say which breach held what.",
            kinds.join(", ")
        )
    };
    Ok(Answer { findings, note })
}

// --------------------------------------------------------------------------------------
// Hudson Rock Cavalier free OSINT API: infostealer infections
// --------------------------------------------------------------------------------------

fn hudson_rock(t: &dyn Transport, kind: QueryKind, value: &str) -> Result<Answer, SourceError> {
    let path = match kind {
        QueryKind::Email => format!(
            "/api/json/v2/osint-tools/search-by-email?email={}",
            percent_encode(value)
        ),
        QueryKind::Username => format!(
            "/api/json/v2/osint-tools/search-by-username?username={}",
            percent_encode(value)
        ),
        QueryKind::Domain => format!(
            "/api/json/v2/osint-tools/search-by-domain?domain={}",
            percent_encode(value)
        ),
        QueryKind::Phone => return Err(SourceError::Unsupported),
    };
    let r = t
        .get(HUDSON_HOST, &path, &["Accept: application/json"], MAX_BODY)
        .map_err(net_error)?;
    if kind == QueryKind::Domain {
        parse_hudson_domain(r.status, &r.body, value)
    } else {
        parse_hudson(r.status, &r.body)
    }
}

#[derive(Deserialize)]
struct HudsonAnswer {
    #[serde(default)]
    stealers: Vec<HudsonStealer>,
}

#[derive(Deserialize)]
struct HudsonStealer {
    #[serde(default)]
    date_compromised: String,
    #[serde(default)]
    stealer_family: String,
    #[serde(default)]
    operating_system: String,
    #[serde(default)]
    computer_name: String,
    #[serde(default)]
    antiviruses: serde_json::Value,
    #[serde(default)]
    total_user_services: serde_json::Value,
    #[serde(default)]
    total_corporate_services: serde_json::Value,
    // Deliberately not read: top_passwords, top_logins, ip, malware_path.
}

fn number(v: &serde_json::Value) -> u64 {
    match v {
        serde_json::Value::Number(n) => n.as_u64().unwrap_or(0),
        serde_json::Value::String(s) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

fn known(text: &str) -> Option<String> {
    let t = util::clean_remote(text, 80);
    (!t.is_empty() && !t.eq_ignore_ascii_case("not found") && !t.eq_ignore_ascii_case("n/a"))
        .then_some(t)
}

pub fn parse_hudson(status: u32, body: &[u8]) -> Result<Answer, SourceError> {
    if status == 404 {
        return Ok(Answer::default());
    }
    common_status(status)?;
    let a: HudsonAnswer = serde_json::from_slice(body).map_err(|_| SourceError::Malformed)?;
    let findings = a
        .stealers
        .into_iter()
        .take(20)
        .map(|s| {
            let mut facts = Vec::new();
            if let Some(os) = known(&s.operating_system) {
                facts.push(format!("System: {os}"));
            }
            if let Some(pc) = known(&s.computer_name) {
                facts.push(format!("Computer: {pc}"));
            }
            if let Some(f) = known(&s.stealer_family) {
                facts.push(format!("Malware: {f}"));
            }
            let av: Vec<String> = match &s.antiviruses {
                serde_json::Value::Array(list) => list
                    .iter()
                    .filter_map(|v| v.as_str().and_then(known))
                    .take(4)
                    .collect(),
                serde_json::Value::String(text) => known(text).into_iter().collect(),
                _ => Vec::new(),
            };
            if !av.is_empty() {
                facts.push(format!("Antivirus: {}", av.join(", ")));
            }
            let user = number(&s.total_user_services);
            let work = number(&s.total_corporate_services);
            if user + work > 0 {
                facts.push(format!(
                    "{} saved logins taken ({} work)",
                    util::thousands(user + work),
                    util::thousands(work)
                ));
            }
            Finding {
                source: SourceId::HudsonRock,
                kind: FindingKind::Stealer,
                name: "Infostealer infection".into(),
                date: tidy_date(&s.date_compromised),
                data: vec!["Passwords".into(), "Browser cookies".into(), "Usernames".into()],
                description: "Malware on a computer linked to this value copied the logins and cookies saved there.".into(),
                link: "https://www.hudsonrock.com/free-tools".into(),
                facts,
                ..Default::default()
            }
        })
        .collect();
    Ok(Answer::of(findings))
}

#[derive(Deserialize)]
struct HudsonDomain {
    #[serde(default)]
    total: serde_json::Value,
    #[serde(default)]
    employees: serde_json::Value,
    #[serde(default)]
    users: serde_json::Value,
    #[serde(default)]
    third_parties: serde_json::Value,
    #[serde(default)]
    last_employee_compromised: String,
    #[serde(default)]
    last_user_compromised: String,
}

/// The domain lookup gives counts only: how many infected computers had
/// logins of the organisation's staff, and of its site's users.
pub fn parse_hudson_domain(status: u32, body: &[u8], domain: &str) -> Result<Answer, SourceError> {
    if status == 404 {
        return Ok(Answer::default());
    }
    common_status(status)?;
    let a: HudsonDomain = serde_json::from_slice(body).map_err(|_| SourceError::Malformed)?;
    let (employees, users, third) = (
        number(&a.employees),
        number(&a.users),
        number(&a.third_parties),
    );
    let total = number(&a.total).max(employees + users + third);
    if total == 0 {
        return Ok(Answer::default());
    }
    let mut facts = Vec::new();
    if employees > 0 {
        facts.push(format!(
            "{} staff computers infected",
            util::thousands(employees)
        ));
    }
    if users > 0 {
        facts.push(format!(
            "{} users' computers infected",
            util::thousands(users)
        ));
    }
    if third > 0 {
        facts.push(format!("{} third-party logins", util::thousands(third)));
    }
    let last = [
        tidy_date(&a.last_employee_compromised),
        tidy_date(&a.last_user_compromised),
    ]
    .into_iter()
    .max()
    .unwrap_or_default();
    Ok(Answer::of(vec![Finding {
        source: SourceId::HudsonRock,
        kind: FindingKind::Stealer,
        name: format!("Infostealer logins for {domain}"),
        domain: domain.to_string(),
        date: last,
        records: total,
        data: vec!["Passwords".into(), "Usernames".into()],
        description: "Computers infected by infostealer malware held logins for this domain. Hudson Rock gives counts only.".into(),
        link: "https://www.hudsonrock.com/free-tools".into(),
        facts,
        ..Default::default()
    }]))
}

// --------------------------------------------------------------------------------------
// Have I Been Pwned
// --------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HibpBreach {
    name: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    domain: String,
    #[serde(default)]
    breach_date: String,
    #[serde(default)]
    pwn_count: serde_json::Value,
    #[serde(default)]
    description: String,
    #[serde(default)]
    data_classes: Vec<String>,
    #[serde(default)]
    is_verified: Option<bool>,
    #[serde(default)]
    is_fabricated: Option<bool>,
    #[serde(default)]
    is_spam_list: Option<bool>,
    #[serde(default)]
    is_stealer_log: Option<bool>,
}

fn hibp_finding(b: HibpBreach, kind: FindingKind) -> Finding {
    let name = util::clean_remote(&b.name, 80);
    let mut facts = Vec::new();
    if b.is_verified == Some(false) {
        facts.push("Unverified breach".to_string());
    }
    if b.is_fabricated == Some(true) {
        facts.push("Probably fabricated data".to_string());
    }
    if b.is_spam_list == Some(true) {
        facts.push("Spam list".to_string());
    }
    if b.is_stealer_log == Some(true) {
        facts.push("From infostealer logs".to_string());
    }
    Finding {
        source: if kind == FindingKind::SiteBreach {
            SourceId::HibpDomain
        } else {
            SourceId::Hibp
        },
        kind,
        link: if name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            format!("https://haveibeenpwned.com/Breach/{name}")
        } else {
            String::new()
        },
        name: if b.title.trim().is_empty() {
            name
        } else {
            util::clean_remote(&b.title, 80)
        },
        domain: util::host_of(&util::clean_remote(&b.domain, 120)),
        date: tidy_date(&b.breach_date),
        records: number(&b.pwn_count),
        data: b
            .data_classes
            .iter()
            .take(30)
            .map(|d| util::clean_remote(d, 40))
            .filter(|d| !d.is_empty())
            .collect(),
        description: util::clean_remote(&strip_html(&b.description), 700),
        facts,
        ..Default::default()
    }
}

/// A list of breach models (`/breaches`, `/breaches?domain=`, `/breachedaccount`).
pub fn parse_hibp_breaches(
    status: u32,
    body: &[u8],
    kind: FindingKind,
) -> Result<Vec<Finding>, SourceError> {
    match status {
        404 => return Ok(Vec::new()),
        403 => return Err(SourceError::NotInPlan),
        400 => return Err(SourceError::Unsupported),
        _ => common_status(status)?,
    }
    let list: Vec<HibpBreach> = serde_json::from_slice(body).map_err(|_| SourceError::Malformed)?;
    Ok(list
        .into_iter()
        .take(MAX_FINDINGS * 2)
        .map(|b| hibp_finding(b, kind))
        .filter(|f| !f.name.is_empty())
        .collect())
}

fn hibp_domain(t: &dyn Transport, domain: &str) -> Result<Answer, SourceError> {
    let path = format!("/api/v3/breaches?domain={}", percent_encode(domain));
    let r = t.get(HIBP_HOST, &path, &[], MAX_BODY).map_err(net_error)?;
    Ok(Answer::of(parse_hibp_breaches(
        r.status,
        &r.body,
        FindingKind::SiteBreach,
    )?))
}

/// The full public list of breached sites (no key, nothing about the user
/// is sent), for comparing with the sites saved in the vault.
pub fn hibp_all_breaches(t: &dyn Transport) -> Result<Vec<Finding>, SourceError> {
    let r = t
        .get(HIBP_HOST, "/api/v3/breaches", &[], 16 * 1024 * 1024)
        .map_err(net_error)?;
    parse_hibp_breaches(r.status, &r.body, FindingKind::SiteBreach)
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct HibpPaste {
    #[serde(default)]
    source: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    date: Option<String>,
    #[serde(default)]
    email_count: serde_json::Value,
}

pub fn parse_hibp_pastes(status: u32, body: &[u8]) -> Result<Vec<Finding>, SourceError> {
    match status {
        404 => return Ok(Vec::new()),
        403 => return Err(SourceError::NotInPlan),
        _ => common_status(status)?,
    }
    let list: Vec<HibpPaste> = serde_json::from_slice(body).map_err(|_| SourceError::Malformed)?;
    Ok(list
        .into_iter()
        .take(100)
        .map(|p| {
            let source = util::clean_remote(&p.source, 40);
            let id = util::clean_remote(&p.id, 60);
            let link = if source.eq_ignore_ascii_case("pastebin")
                && !id.is_empty()
                && id.chars().all(|c| c.is_ascii_alphanumeric())
            {
                format!("https://pastebin.com/{id}")
            } else {
                String::new()
            };
            let title = p
                .title
                .map(|t| util::clean_remote(&t, 80))
                .unwrap_or_default();
            Finding {
                source: SourceId::Hibp,
                kind: FindingKind::Paste,
                name: if title.is_empty() {
                    format!("Paste on {source}")
                } else {
                    format!("Paste on {source}: {title}")
                },
                date: p.date.map(|d| tidy_date(&d)).unwrap_or_default(),
                records: number(&p.email_count),
                data: vec!["Email addresses".into()],
                description: "The address appeared in text posted publicly on a paste site.".into(),
                link,
                ..Default::default()
            }
        })
        .collect())
}

/// `stealerlogsbyemail`: the sites whose logins for this address were
/// captured by infostealer malware.
pub fn parse_hibp_stealer_sites(status: u32, body: &[u8]) -> Result<Vec<Finding>, SourceError> {
    match status {
        404 => return Ok(Vec::new()),
        403 => return Err(SourceError::NotInPlan),
        _ => common_status(status)?,
    }
    let list: Vec<String> = serde_json::from_slice(body).map_err(|_| SourceError::Malformed)?;
    let mut out: Vec<Finding> = Vec::new();
    for d in list.into_iter().take(MAX_FINDINGS) {
        let host = util::host_of(&util::clean_remote(&d, 120));
        if host.is_empty() || out.iter().any(|f| f.domain == host) {
            continue;
        }
        out.push(Finding {
            source: SourceId::Hibp,
            kind: FindingKind::StealerSite,
            name: host.clone(),
            domain: host,
            data: vec!["Passwords".into(), "Usernames".into()],
            description: "Your login for this site was in logs of infostealer malware.".into(),
            link: "https://haveibeenpwned.com/FAQs".into(),
            ..Default::default()
        });
    }
    Ok(out)
}

fn hibp_account(
    t: &dyn Transport,
    kind: QueryKind,
    value: &str,
    key: &str,
    between: &dyn Fn(),
) -> Result<Answer, SourceError> {
    if key.len() > 100 || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(SourceError::BadKey);
    }
    let header = format!("hibp-api-key: {key}");
    let headers = [header.as_str(), "Accept: application/json"];
    if kind != QueryKind::Email {
        return Err(SourceError::Unsupported);
    }
    let path = format!(
        "/api/v3/breachedaccount/{}?truncateResponse=false&includeUnverified=true",
        percent_encode(value)
    );
    let r: Response = t
        .get(HIBP_HOST, &path, &headers, MAX_BODY)
        .map_err(net_error)?;
    let mut findings = parse_hibp_breaches(r.status, &r.body, FindingKind::Breach)?;
    let mut notes: Vec<&str> = Vec::new();
    {
        // Pastes and stealer logs are extras: a plan without them is not a failure.
        between();
        let r = t
            .get(
                HIBP_HOST,
                &format!("/api/v3/pasteaccount/{}", percent_encode(value)),
                &headers,
                MAX_BODY,
            )
            .map_err(net_error)?;
        match parse_hibp_pastes(r.status, &r.body) {
            Ok(list) => findings.extend(list),
            Err(SourceError::RateLimited) => {
                notes.push("Pastes were not checked: too many lookups.")
            }
            Err(_) => notes.push("Pastes are not included in your plan."),
        }
        between();
        let r = t
            .get(
                HIBP_HOST,
                &format!("/api/v3/stealerlogsbyemail/{}", percent_encode(value)),
                &headers,
                MAX_BODY,
            )
            .map_err(net_error)?;
        match parse_hibp_stealer_sites(r.status, &r.body) {
            Ok(list) => findings.extend(list),
            Err(SourceError::RateLimited) => {
                notes.push("Stealer logs were not checked: too many lookups.")
            }
            Err(_) => notes.push(
                "Stealer logs need an HIBP Pro plan and an address on a domain you verified.",
            ),
        }
    }
    Ok(Answer {
        findings,
        note: notes.join(" "),
    })
}

// --------------------------------------------------------------------------------------
// Leak-Lookup (the user's own key): breach names only
// --------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct LeakLookupAnswer {
    #[serde(default)]
    error: serde_json::Value,
    #[serde(default)]
    message: serde_json::Value,
}

fn leak_lookup(
    t: &dyn Transport,
    kind: QueryKind,
    value: &str,
    key: &str,
) -> Result<Answer, SourceError> {
    if key.len() > 100 || !key.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(SourceError::BadKey);
    }
    let kind_name = match kind {
        QueryKind::Email => "email_address",
        QueryKind::Username => "username",
        QueryKind::Phone => "phone",
        QueryKind::Domain => "domain",
    };
    let body = format!(
        "key={}&type={kind_name}&query={}",
        percent_encode(key),
        percent_encode(value)
    );
    let r = t
        .post(
            LEAKLOOKUP_HOST,
            "/api/search",
            &[
                "Content-Type: application/x-www-form-urlencoded",
                "Accept: application/json",
            ],
            body.as_bytes(),
            MAX_BODY,
        )
        .map_err(net_error)?;
    parse_leak_lookup(r.status, &r.body)
}

pub fn parse_leak_lookup(status: u32, body: &[u8]) -> Result<Answer, SourceError> {
    common_status(status)?;
    let a: LeakLookupAnswer = serde_json::from_slice(body).map_err(|_| SourceError::Malformed)?;
    let failed = match &a.error {
        serde_json::Value::String(s) => s.eq_ignore_ascii_case("true"),
        serde_json::Value::Bool(b) => *b,
        _ => false,
    };
    if failed {
        let m = a.message.as_str().unwrap_or("").to_lowercase();
        return Err(if m.contains("limit") {
            SourceError::RateLimited
        } else if m.contains("key") {
            SourceError::BadKey
        } else if m.contains("type") || m.contains("query") {
            SourceError::Unsupported
        } else {
            SourceError::Malformed
        });
    }
    // Names of breached sites are the keys. Whatever a paid key may add as
    // values (leaked records) is ignored, never read or kept.
    let names: Vec<String> = match &a.message {
        serde_json::Value::Object(map) => map.keys().cloned().collect(),
        serde_json::Value::Array(list) => list
            .iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect(),
        serde_json::Value::String(s)
            if s.trim().is_empty() || s.to_lowercase().contains("no results") =>
        {
            Vec::new()
        }
        _ => return Err(SourceError::Malformed),
    };
    Ok(Answer::of(
        names
            .iter()
            .take(MAX_FINDINGS)
            .map(|n| Finding {
                source: SourceId::LeakLookup,
                kind: FindingKind::Breach,
                name: util::clean_remote(n, 80),
                ..Default::default()
            })
            .filter(|f| !f.name.is_empty())
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::super::testing::Recorded;
    use super::*;

    fn no_wait() {}

    #[test]
    fn helpers() {
        assert_eq!(
            strip_html(
                r#"In 2013, <em>153 million</em> &quot;Adobe&quot; <a href="http://x">accounts</a> &amp; more"#
            ),
            "In 2013, 153 million \"Adobe\" accounts & more"
        );
        assert_eq!(tidy_date("2019-06-01T00:00:00Z"), "2019-06-01");
        assert_eq!(tidy_date("2020-05"), "2020-05");
        assert_eq!(tidy_date("2019"), "2019");
        assert_eq!(tidy_date(""), "");
        assert_eq!(tidy_date("12/2019"), "");
        assert_eq!(tidy_date("0001-01-01"), "");
        assert_eq!(safe_link("https://example.com/a"), "https://example.com/a");
        assert_eq!(safe_link("http://example.com"), "");
        assert_eq!(safe_link("javascript:alert(1)"), "");
        assert_eq!(safe_link("https://a.com/\"x"), "");
    }

    // Shapes recorded from the live XposedOrNot API (values invented).
    const XON_FOUND: &str = r#"{"BreachMetrics":{"risk":[{"risk_label":"High","risk_score":70}]},
      "BreachesSummary":{"site":"PhotoCloud;ExampleShop-2021"},
      "ExposedBreaches":{"breaches_details":[
        {"breach":"PhotoCloud","details":"Photo Cloud was breached.","domain":"photocloud.example","industry":"Information Technology","references":"https://news.example/photocloud",
         "password_risk":"plaintext","xposed_data":"Email addresses;Passwords","xposed_date":"2019","xposed_records":1234567},
        {"breach":"ExampleShop-2021","details":"A shop.","domain":"www.shop.example","industry":"Retail","references":"http://insecure.example",
         "password_risk":"unknown","xposed_data":"Email addresses;Phone numbers","xposed_date":2021,"xposed_records":"5000"}]}}"#;

    #[test]
    fn xposedornot() {
        let t = Recorded::new().with(
            XON_HOST,
            "/v1/breach-analytics?email=alex%40example.com",
            200,
            XON_FOUND,
        );
        let a = check(
            SourceId::XposedOrNot,
            &t,
            QueryKind::Email,
            " Alex@Example.com",
            None,
            &no_wait,
        )
        .unwrap();
        assert_eq!(a.findings.len(), 2);
        let p = a.findings.iter().find(|f| f.name == "PhotoCloud").unwrap();
        assert_eq!(p.date, "2019");
        assert_eq!(p.password_risk, "plaintext");
        assert_eq!(p.link, "https://news.example/photocloud");
        assert_eq!(
            a.findings
                .iter()
                .find(|f| f.name != "PhotoCloud")
                .unwrap()
                .link,
            "",
            "http links are dropped"
        );
        assert_eq!(p.data, vec!["Email addresses", "Passwords"]);
        assert_eq!(t.seen().len(), 1);
        assert_eq!(
            parse_xposedornot(200, br#"{"Error":"Not found","email":null}"#),
            Ok(Answer::default())
        );
        assert_eq!(parse_xposedornot(429, b""), Err(SourceError::RateLimited));
        assert_eq!(
            parse_xposedornot(200, b"<html>"),
            Err(SourceError::Malformed)
        );
        // Usernames are not something XposedOrNot can look up; nothing is sent.
        assert_eq!(
            check(
                SourceId::XposedOrNot,
                &t,
                QueryKind::Username,
                "alex",
                None,
                &no_wait
            ),
            Err(SourceError::Unsupported)
        );
        assert_eq!(t.seen().len(), 1);
    }

    // Shape recorded from the live LeakCheck public API (names invented).
    const LEAKCHECK_FOUND: &str = r#"{"success":true,"found":3,"fields":["username","password","phone","address","dob","origin"],
      "sources":[{"name":"PhotoCloud.example","date":"2019-06"},{"name":"Old Forum","date":""},{"name":"Shop.example","date":"2021-02"}]}"#;

    #[test]
    fn leakcheck() {
        let t = Recorded::new().with(
            LEAKCHECK_HOST,
            "/api/public?check=alex_m",
            200,
            LEAKCHECK_FOUND,
        );
        let a = check(
            SourceId::LeakCheck,
            &t,
            QueryKind::Username,
            "alex_m",
            None,
            &no_wait,
        )
        .unwrap();
        assert_eq!(a.findings.len(), 3);
        assert_eq!(a.findings[0].name, "PhotoCloud.example");
        assert_eq!(a.findings[0].date, "2019-06");
        assert_eq!(a.findings[1].date, "");
        assert!(
            a.note.contains("passwords")
                && a.note.contains("phone numbers")
                && a.note.contains("dates of birth")
        );
        assert_eq!(
            parse_leakcheck(200, br#"{"success": false, "error": "Not found"}"#),
            Ok(Answer::default())
        );
        assert_eq!(
            parse_leakcheck(
                200,
                br#"{"success":false,"error":"Too many requests, limit reached"}"#
            ),
            Err(SourceError::RateLimited)
        );
        assert_eq!(
            parse_leakcheck(
                200,
                br#"{"success":false,"error":"Invalid characters in query"}"#
            ),
            Err(SourceError::Unsupported)
        );
        assert_eq!(parse_leakcheck(429, b""), Err(SourceError::RateLimited));
        assert_eq!(parse_leakcheck(200, b"[]"), Err(SourceError::Malformed));
        assert_eq!(parse_leakcheck(503, b""), Err(SourceError::Service(503)));
    }

    // Shape recorded from the live Hudson Rock API (values invented).
    const HUDSON_FOUND: &str = r#"{"message":"This email address is associated with a computer that was infected by an info-stealer...",
      "stealers":[{"total_corporate_services":3,"total_user_services":41,"date_compromised":"2024-03-02T11:22:33.000Z",
        "computer_name":"DESKTOP-EXAMPLE (Alex)","operating_system":"Windows 11 Pro","malware_path":"C:\\Users\\x\\a.exe",
        "antiviruses":["Windows Defender"],"ip":"203.0.***.***","top_passwords":["p******1"],"top_logins":["a****@example.com"]},
        {"total_corporate_services":0,"total_user_services":0,"date_compromised":"2022-01-01T00:00:00.000Z","computer_name":"Not Found",
        "operating_system":"Not Found","antiviruses":[],"ip":"Not Found"}],
      "total_corporate_services":3,"total_user_services":41}"#;

    #[test]
    fn hudson_rock() {
        let t = Recorded::new().with(
            HUDSON_HOST,
            "/api/json/v2/osint-tools/search-by-email?email=alex%40example.com",
            200,
            HUDSON_FOUND,
        );
        let a = check(
            SourceId::HudsonRock,
            &t,
            QueryKind::Email,
            "alex@example.com",
            None,
            &no_wait,
        )
        .unwrap();
        assert_eq!(a.findings.len(), 2);
        let f = &a.findings[0];
        assert_eq!(f.kind, FindingKind::Stealer);
        assert_eq!(f.date, "2024-03-02");
        assert!(f.facts.contains(&"System: Windows 11 Pro".to_string()));
        assert!(f.facts.contains(&"Antivirus: Windows Defender".to_string()));
        assert!(f.facts.iter().any(|x| x.starts_with("44 saved logins")));
        // Masked passwords, logins, IP and paths are never kept.
        let all = format!("{:?}", a.findings);
        for secret in ["p******1", "a****@example.com", "203.0", "a.exe"] {
            assert!(!all.contains(secret), "{secret}");
        }
        assert!(
            a.findings[1].facts.is_empty(),
            "\"Not Found\" values are dropped"
        );
        let clean = br#"{"message":"This username is not associated with a computer infected by an info-stealer.","stealers":[],"total_corporate_services":0,"total_user_services":0}"#;
        assert_eq!(parse_hudson(200, clean), Ok(Answer::default()));
        assert_eq!(parse_hudson(429, b""), Err(SourceError::RateLimited));
        assert_eq!(parse_hudson(200, b"nope"), Err(SourceError::Malformed));
        let t = Recorded::new().with(
            HUDSON_HOST,
            "/api/json/v2/osint-tools/search-by-username?username=alex_m",
            200,
            std::str::from_utf8(clean).unwrap(),
        );
        assert_eq!(
            check(
                SourceId::HudsonRock,
                &t,
                QueryKind::Username,
                "alex_m",
                None,
                &no_wait
            ),
            Ok(Answer::default())
        );
    }

    #[test]
    fn hudson_rock_domain() {
        let body = br#"{"total":120,"totalStealers":118,"employees":7,"users":110,"third_parties":3,
            "last_employee_compromised":"2025-09-01T00:00:00.000Z","last_user_compromised":"2026-01-02T00:00:00.000Z"}"#;
        let a = parse_hudson_domain(200, body, "example.com").unwrap();
        assert_eq!(a.findings.len(), 1);
        let f = &a.findings[0];
        assert_eq!(f.records, 120);
        assert_eq!(f.date, "2026-01-02");
        assert_eq!(f.domain, "example.com");
        assert!(f.facts[0].starts_with("7 staff"));
        assert_eq!(
            parse_hudson_domain(
                200,
                br#"{"total":0,"employees":0,"users":0}"#,
                "example.com"
            ),
            Ok(Answer::default())
        );
    }

    // Shape from the HIBP API documentation (values invented).
    const HIBP_BREACHES: &str = r#"[{"Name":"PhotoCloud","Title":"Photo Cloud","Domain":"photocloud.example","BreachDate":"2019-06-01",
        "AddedDate":"2019-07-01T00:00:00Z","PwnCount":1234567,"Description":"Photo Cloud <a href=\"https://x\">lost</a> data.",
        "DataClasses":["Email addresses","Passwords"],"IsVerified":true,"IsFabricated":false,"IsSensitive":false,"IsRetired":false,
        "IsSpamList":false,"IsMalware":false,"IsStealerLog":false,"LogoPath":"https://logos.haveibeenpwned.com/x.png"},
       {"Name":"Shop Leak","Title":"","Domain":"","BreachDate":"2021","PwnCount":"12","Description":"","DataClasses":[],"IsVerified":false}]"#;

    #[test]
    fn hibp_account_with_pastes_and_stealer_logs() {
        let t = Recorded::new()
            .with(HIBP_HOST, "/api/v3/breachedaccount/alex%40example.com", 200, HIBP_BREACHES)
            .with(HIBP_HOST, "/api/v3/pasteaccount/", 200, r#"[{"Source":"Pastebin","Id":"8Q0BvKD8","Title":"syslog","Date":"2014-03-04T19:14:54Z","EmailCount":139},{"Source":"AdHocUrl","Id":"http://x","Title":null,"Date":null,"EmailCount":3}]"#)
            .with(HIBP_HOST, "/api/v3/stealerlogsbyemail/", 200, r#"["netflix.com","www.netflix.com","spotify.com"]"#);
        // No key: nothing is sent.
        assert_eq!(
            check(
                SourceId::Hibp,
                &t,
                QueryKind::Email,
                "alex@example.com",
                None,
                &no_wait
            ),
            Err(SourceError::NeedsKey)
        );
        assert_eq!(
            check(
                SourceId::Hibp,
                &t,
                QueryKind::Email,
                "alex@example.com",
                Some("  "),
                &no_wait
            ),
            Err(SourceError::NeedsKey)
        );
        assert!(t.seen().is_empty());
        let waits = std::cell::Cell::new(0);
        let a = check(
            SourceId::Hibp,
            &t,
            QueryKind::Email,
            "alex@example.com",
            Some("0123abcd"),
            &|| waits.set(waits.get() + 1),
        )
        .unwrap();
        assert_eq!(waits.get(), 2, "paced between the three requests");
        let seen = t.seen();
        assert_eq!(seen.len(), 3);
        assert!(seen.iter().all(|s| s.contains("hibp-api-key: 0123abcd")));
        let breaches: Vec<&Finding> = a
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::Breach)
            .collect();
        assert_eq!(breaches.len(), 2);
        assert_eq!(breaches[0].name, "Photo Cloud");
        assert_eq!(breaches[0].date, "2019-06-01");
        assert_eq!(breaches[0].description, "Photo Cloud lost data.");
        assert_eq!(
            breaches[0].link,
            "https://haveibeenpwned.com/Breach/PhotoCloud"
        );
        assert_eq!(breaches[1].name, "Shop Leak");
        assert_eq!(breaches[1].link, "", "names with spaces get no link");
        assert_eq!(breaches[1].records, 12);
        assert_eq!(breaches[1].facts, vec!["Unverified breach"]);
        let pastes: Vec<&Finding> = a
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::Paste)
            .collect();
        assert_eq!(pastes.len(), 2);
        assert_eq!(pastes[0].link, "https://pastebin.com/8Q0BvKD8");
        assert_eq!(pastes[1].link, "", "only known paste sites are linked");
        let sites: Vec<&str> = a
            .findings
            .iter()
            .filter(|f| f.kind == FindingKind::StealerSite)
            .map(|f| f.domain.as_str())
            .collect();
        assert_eq!(sites, vec!["netflix.com", "spotify.com"]);
        assert!(a.note.is_empty());
    }

    #[test]
    fn hibp_errors_and_plans() {
        let t = Recorded::new()
            .with(HIBP_HOST, "/api/v3/breachedaccount/", 404, "")
            .with(HIBP_HOST, "/api/v3/pasteaccount/", 404, "")
            .with(HIBP_HOST, "/api/v3/stealerlogsbyemail/", 403, "");
        let a = check(
            SourceId::Hibp,
            &t,
            QueryKind::Email,
            "alex@example.com",
            Some("key1"),
            &no_wait,
        )
        .unwrap();
        assert!(a.findings.is_empty());
        assert!(a.note.starts_with("Stealer logs need an HIBP Pro plan"));
        let t = Recorded::new().with(HIBP_HOST, "/api/v3/breachedaccount/", 401, "");
        assert_eq!(
            check(
                SourceId::Hibp,
                &t,
                QueryKind::Email,
                "alex@example.com",
                Some("key1"),
                &no_wait
            ),
            Err(SourceError::BadKey)
        );
        assert_eq!(t.seen().len(), 1, "stops at the first refusal");
        let t = Recorded::new().with(HIBP_HOST, "/api/v3/breachedaccount/", 429, "");
        assert_eq!(
            check(
                SourceId::Hibp,
                &t,
                QueryKind::Email,
                "alex@example.com",
                Some("key1"),
                &no_wait
            ),
            Err(SourceError::RateLimited)
        );
        // A key with odd characters is refused before anything is sent.
        let t = Recorded::new();
        assert_eq!(
            check(
                SourceId::Hibp,
                &t,
                QueryKind::Email,
                "alex@example.com",
                Some("a b\r\nX: y"),
                &no_wait
            ),
            Err(SourceError::BadKey)
        );
        assert!(t.seen().is_empty());
        // HIBP's API has no documented phone search: nothing is sent.
        let t = Recorded::new();
        assert_eq!(
            check(
                SourceId::Hibp,
                &t,
                QueryKind::Phone,
                "+44 7700 900123",
                Some("key1"),
                &no_wait
            ),
            Err(SourceError::Unsupported)
        );
        assert!(t.seen().is_empty());
    }

    #[test]
    fn hibp_domain_and_site_list() {
        let t = Recorded::new()
            .with(
                HIBP_HOST,
                "/api/v3/breaches?domain=photocloud.example",
                200,
                HIBP_BREACHES,
            )
            .with(HIBP_HOST, "/api/v3/breaches", 200, HIBP_BREACHES);
        let a = check(
            SourceId::HibpDomain,
            &t,
            QueryKind::Domain,
            "https://www.photocloud.example/x",
            None,
            &no_wait,
        )
        .unwrap();
        assert_eq!(a.findings.len(), 2);
        assert!(a
            .findings
            .iter()
            .all(|f| f.kind == FindingKind::SiteBreach && f.source == SourceId::HibpDomain));
        // No key header goes to the free endpoints.
        assert!(t.seen()[0].ends_with("| "));
        let all = hibp_all_breaches(&t).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(t.seen()[1], format!("{HIBP_HOST}/api/v3/breaches | "));
        assert_eq!(
            parse_hibp_breaches(200, b"{}", FindingKind::SiteBreach),
            Err(SourceError::Malformed)
        );
    }

    #[test]
    fn leak_lookup() {
        let t = Recorded::new().with(
            LEAKLOOKUP_HOST,
            "/api/search",
            200,
            r#"{"error":"false","message":{"photocloud.example":[],"old-forum.example":[{"password":"never-read"}]}}"#,
        );
        assert_eq!(
            check(
                SourceId::LeakLookup,
                &t,
                QueryKind::Email,
                "alex@example.com",
                None,
                &no_wait
            ),
            Err(SourceError::NeedsKey)
        );
        let a = check(
            SourceId::LeakLookup,
            &t,
            QueryKind::Username,
            "alex_m",
            Some("abc123"),
            &no_wait,
        )
        .unwrap();
        let names: Vec<&str> = a.findings.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, vec!["old-forum.example", "photocloud.example"]);
        assert!(!format!("{:?}", a).contains("never-read"));
        let seen = t.seen();
        assert_eq!(seen.len(), 1);
        assert!(seen[0].contains("body key=abc123&type=username&query=alex_m"));
        assert_eq!(
            parse_leak_lookup(
                200,
                br#"{"error":"true","message":"REQUEST LIMIT REACHED"}"#
            ),
            Err(SourceError::RateLimited)
        );
        assert_eq!(
            parse_leak_lookup(200, br#"{"error":"true","message":"INVALID API KEY"}"#),
            Err(SourceError::BadKey)
        );
        assert_eq!(
            parse_leak_lookup(200, br#"{"error":"false","message":{}}"#),
            Ok(Answer::default())
        );
        assert_eq!(
            parse_leak_lookup(200, br#"{"error":"false","message":42}"#),
            Err(SourceError::Malformed)
        );
    }
}
