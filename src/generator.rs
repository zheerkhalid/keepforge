//! Password, passphrase, username, PIN and token generators.
//! All randomness comes from the operating system's CSPRNG, and every pick
//! from a range uses rejection sampling so it is uniform.

use crate::secret::SecretString;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A source of random bytes (the OS generator, or a fixed one in tests).
pub trait Rng {
    fn fill(&mut self, buf: &mut [u8]);
}

pub struct OsRng;

impl Rng for OsRng {
    fn fill(&mut self, buf: &mut [u8]) {
        crate::secret::random_bytes(buf);
    }
}

/// A uniform number in `0..n` by rejection sampling.
pub fn uniform(rng: &mut dyn Rng, n: u32) -> u32 {
    assert!(n > 0);
    if n == 1 {
        return 0;
    }
    // Largest multiple of n that fits in 2^32: values at or above it are rejected.
    let zone = (u64::from(u32::MAX) + 1) / u64::from(n) * u64::from(n);
    loop {
        let mut b = [0u8; 4];
        rng.fill(&mut b);
        let v = u64::from(u32::from_le_bytes(b));
        if v < zone {
            return (v % u64::from(n)) as u32;
        }
    }
}

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.?/";
/// Characters that are easy to confuse with each other.
const LOOKALIKES: &str = "0O1lI|5S2Z8B";

pub const MIN_LENGTH: usize = 8;
pub const MAX_LENGTH: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordOptions {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_lookalikes: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        PasswordOptions {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            exclude_lookalikes: false,
        }
    }
}

impl PasswordOptions {
    /// The chosen character classes, after removing look-alikes if asked.
    pub fn classes(&self) -> Vec<Vec<char>> {
        let pick = |on: bool, set: &str| -> Option<Vec<char>> {
            on.then(|| {
                set.chars()
                    .filter(|c| !(self.exclude_lookalikes && LOOKALIKES.contains(*c)))
                    .collect()
            })
        };
        let mut classes: Vec<Vec<char>> = [
            pick(self.lower, LOWER),
            pick(self.upper, UPPER),
            pick(self.digits, DIGITS),
            pick(self.symbols, SYMBOLS),
        ]
        .into_iter()
        .flatten()
        .collect();
        if classes.is_empty() {
            classes.push(pick(true, LOWER).unwrap_or_default());
        }
        classes
    }

    pub fn length(&self) -> usize {
        self.length.clamp(MIN_LENGTH, MAX_LENGTH)
    }

    /// Exact entropy in bits: log2 of the number of passwords of this length
    /// that contain at least one character of every chosen class.
    pub fn entropy_bits(&self) -> f64 {
        let sizes: Vec<f64> = self.classes().iter().map(|c| c.len() as f64).collect();
        let total: f64 = sizes.iter().sum();
        let len = self.length() as i32;
        // Inclusion–exclusion over the classes left out.
        let mut count = 0.0f64;
        for mask in 0u32..(1 << sizes.len()) {
            let removed: f64 = sizes
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, s)| *s)
                .sum();
            let sign = if mask.count_ones() % 2 == 0 {
                1.0
            } else {
                -1.0
            };
            count += sign * (total - removed).powi(len);
        }
        count.max(1.0).log2()
    }
}

/// A random password with at least one character from every chosen class.
/// Whole candidates are drawn uniformly and rejected until every class is
/// present, so the result is uniform over all valid passwords.
pub fn password(opts: &PasswordOptions, rng: &mut dyn Rng) -> SecretString {
    let classes = opts.classes();
    let pool: Vec<char> = classes.iter().flatten().copied().collect();
    let len = opts.length();
    let mut out = Zeroizing::new(String::with_capacity(len * 4));
    loop {
        out.clear();
        for _ in 0..len {
            out.push(pool[uniform(rng, pool.len() as u32) as usize]);
        }
        if classes
            .iter()
            .all(|class| out.chars().any(|c| class.contains(&c)))
        {
            return out;
        }
    }
}

// --------------------------------------------------------------------------------------
// Passphrases
// --------------------------------------------------------------------------------------

static WORDLIST: &str = include_str!("../res/eff_large_wordlist.txt");

/// The EFF large wordlist (7,776 words; CC BY 3.0 US, see NOTICE).
pub fn words() -> &'static [&'static str] {
    static WORDS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    WORDS.get_or_init(|| WORDLIST.lines().filter(|l| !l.is_empty()).collect())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PhraseOptions {
    pub words: usize,
    pub separator: String,
    pub capitalise: bool,
    pub add_number: bool,
}

impl Default for PhraseOptions {
    fn default() -> Self {
        PhraseOptions {
            words: 5,
            separator: "-".into(),
            capitalise: false,
            add_number: false,
        }
    }
}

impl PhraseOptions {
    pub fn word_count(&self) -> usize {
        self.words.clamp(3, 12)
    }

    /// Entropy in bits: each word is one of 7,776; the optional digit adds
    /// one of ten values at one of `words` positions.
    pub fn entropy_bits(&self) -> f64 {
        let n = self.word_count() as f64;
        let mut bits = n * (words().len() as f64).log2();
        if self.add_number {
            bits += 10f64.log2() + n.log2();
        }
        bits
    }
}

fn capitalised(word: &str) -> String {
    let mut c = word.chars();
    match c.next() {
        Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

pub fn passphrase(opts: &PhraseOptions, rng: &mut dyn Rng) -> SecretString {
    let list = words();
    let n = opts.word_count();
    let digit_at = opts.add_number.then(|| uniform(rng, n as u32) as usize);
    let mut out = Zeroizing::new(String::with_capacity(n * 12 + 8));
    for i in 0..n {
        if i > 0 {
            out.push_str(&opts.separator);
        }
        let word = list[uniform(rng, list.len() as u32) as usize];
        if opts.capitalise {
            out.push_str(&capitalised(word));
        } else {
            out.push_str(word);
        }
        if digit_at == Some(i) {
            out.push(char::from(b'0' + uniform(rng, 10) as u8));
        }
    }
    out
}

// --------------------------------------------------------------------------------------
// Usernames, PINs, tokens
// --------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsernameOptions {
    pub words: usize,
    pub capitalise: bool,
    pub add_number: bool,
    pub separator: String,
}

impl Default for UsernameOptions {
    fn default() -> Self {
        UsernameOptions {
            words: 2,
            capitalise: true,
            add_number: true,
            separator: String::new(),
        }
    }
}

/// A readable user name such as `CalmOtter42`. Not a secret: it only needs
/// to be unlikely to collide and unconnected to your other names.
pub fn username(opts: &UsernameOptions, rng: &mut dyn Rng) -> String {
    let list = words();
    let n = opts.words.clamp(1, 4);
    let mut out = String::new();
    for i in 0..n {
        if i > 0 {
            out.push_str(&opts.separator);
        }
        let word = list[uniform(rng, list.len() as u32) as usize];
        if opts.capitalise {
            out.push_str(&capitalised(word));
        } else {
            out.push_str(word);
        }
    }
    if opts.add_number {
        out.push_str(&format!("{}", 10 + uniform(rng, 90)));
    }
    out
}

pub const PIN_MIN: usize = 4;
pub const PIN_MAX: usize = 12;

/// PINs people pick far too often.
const COMMON_PINS: [&str; 16] = [
    "1234", "0000", "1111", "1212", "7777", "1004", "2000", "4444", "2222", "6969", "9999", "3333",
    "5555", "6666", "1122", "1313",
];

/// Whether a PIN is trivially guessable: one repeated digit, a straight run
/// up or down, a repeated block (1212, 123123), a mirror of two halves
/// (1221), a year (19xx / 20xx) or a well-known favourite.
pub fn pin_is_trivial(pin: &str) -> bool {
    let d: Vec<u8> = pin.bytes().map(|b| b.wrapping_sub(b'0')).collect();
    if d.len() < 2 {
        return true;
    }
    if d.iter().all(|x| *x == d[0]) {
        return true;
    }
    let run = |step: u8| d.windows(2).all(|w| w[1] == (w[0] + step) % 10);
    if run(1) || run(9) {
        return true;
    }
    for block in 1..=d.len() / 2 {
        if d.len().is_multiple_of(block) && d.chunks(block).all(|c| c == &d[..block]) {
            return true;
        }
    }
    if d.len().is_multiple_of(2) {
        let (a, b) = d.split_at(d.len() / 2);
        if a.iter().eq(b.iter().rev()) {
            return true;
        }
    }
    if d.len() == 4 && (pin.starts_with("19") || pin.starts_with("20")) {
        return true;
    }
    COMMON_PINS.contains(&pin)
}

/// A random numeric PIN that is not one of the trivial ones.
pub fn pin(length: usize, rng: &mut dyn Rng) -> SecretString {
    let len = length.clamp(PIN_MIN, PIN_MAX);
    let mut out = Zeroizing::new(String::with_capacity(len));
    loop {
        out.clear();
        for _ in 0..len {
            out.push(char::from(b'0' + uniform(rng, 10) as u8));
        }
        if !pin_is_trivial(&out) {
            return out;
        }
    }
}

/// Bits of entropy of a PIN of this length (slightly under `len × log2 10`,
/// because trivial PINs are excluded; the upper bound is shown).
pub fn pin_entropy_bits(length: usize) -> f64 {
    length.clamp(PIN_MIN, PIN_MAX) as f64 * 10f64.log2()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenFormat {
    Hex,
    Base64,
}

/// A random token of `bytes` bytes (16–64), as hex or base64.
pub fn token(bytes: usize, format: TokenFormat, rng: &mut dyn Rng) -> SecretString {
    let n = bytes.clamp(16, 64);
    let mut raw = Zeroizing::new(vec![0u8; n]);
    rng.fill(&mut raw);
    Zeroizing::new(match format {
        TokenFormat::Hex => crate::util::hex(&raw),
        TokenFormat::Base64 => crate::util::base64(&raw),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A fixed, fast generator so tests are repeatable (not for real use).
    pub(crate) struct TestRng(pub u64);

    impl Rng for TestRng {
        fn fill(&mut self, buf: &mut [u8]) {
            for b in buf {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 7;
                self.0 ^= self.0 << 17;
                *b = (self.0 >> 24) as u8;
            }
        }
    }

    #[test]
    fn every_chosen_class_is_present() {
        let mut rng = OsRng;
        for length in [8, 9, 16, 64, 128] {
            for mask in 1u8..16 {
                let opts = PasswordOptions {
                    length,
                    lower: mask & 1 != 0,
                    upper: mask & 2 != 0,
                    digits: mask & 4 != 0,
                    symbols: mask & 8 != 0,
                    exclude_lookalikes: mask % 3 == 0,
                };
                let pw = password(&opts, &mut rng);
                assert_eq!(pw.chars().count(), length);
                assert_eq!(opts.lower, pw.chars().any(|c| c.is_ascii_lowercase()));
                assert_eq!(opts.upper, pw.chars().any(|c| c.is_ascii_uppercase()));
                assert_eq!(opts.digits, pw.chars().any(|c| c.is_ascii_digit()));
                assert_eq!(opts.symbols, pw.chars().any(|c| SYMBOLS.contains(c)));
                if opts.exclude_lookalikes {
                    assert!(!pw.chars().any(|c| LOOKALIKES.contains(c)));
                }
            }
        }
        // Length limits are enforced; no classes falls back to lower case.
        let none = PasswordOptions {
            length: 3,
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            exclude_lookalikes: false,
        };
        let pw = password(&none, &mut rng);
        assert_eq!(pw.len(), MIN_LENGTH);
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
        let long = PasswordOptions {
            length: 5000,
            ..Default::default()
        };
        assert_eq!(password(&long, &mut rng).len(), MAX_LENGTH);
    }

    #[test]
    fn uniform_is_in_range_and_roughly_flat() {
        let mut rng = TestRng(0x9E37_79B9_7F4A_7C15);
        for n in [1u32, 2, 3, 10, 94, 7776, u32::MAX] {
            for _ in 0..200 {
                assert!(uniform(&mut rng, n) < n);
            }
        }
        // Chi-square sanity check over 94 buckets with the real generator.
        let mut os = OsRng;
        let buckets = 94usize;
        let draws = 94_000usize;
        let mut counts = vec![0u32; buckets];
        for _ in 0..draws {
            counts[uniform(&mut os, buckets as u32) as usize] += 1;
        }
        let expected = (draws / buckets) as f64;
        let chi: f64 = counts
            .iter()
            .map(|c| (*c as f64 - expected).powi(2) / expected)
            .sum();
        // 93 degrees of freedom: mean 93, and 200 is far beyond the 99.9999th percentile.
        assert!(chi < 200.0, "chi-square {chi}");
        assert!(counts.iter().all(|c| *c > 700 && *c < 1300));
    }

    #[test]
    fn rejection_sampling_has_no_modulo_bias() {
        // With n just above 2^31, a plain modulo would return small values
        // twice as often. Rejection sampling keeps both halves equal.
        let n = (1u32 << 31) + 1;
        let mut rng = OsRng;
        let low = (0..20_000).filter(|_| uniform(&mut rng, n) < n / 2).count();
        assert!((9_300..10_700).contains(&low), "low half: {low}");
    }

    #[test]
    fn entropy_maths() {
        let digits_only = PasswordOptions {
            length: 8,
            lower: false,
            upper: false,
            digits: true,
            symbols: false,
            exclude_lookalikes: false,
        };
        assert!((digits_only.entropy_bits() - 8.0 * 10f64.log2()).abs() < 1e-9);
        // Two classes, length 8: (36^8 - 26^8 - 10^8) passwords.
        let two = PasswordOptions {
            lower: true,
            ..digits_only.clone()
        };
        let exact = (36f64.powi(8) - 26f64.powi(8) - 10f64.powi(8)).log2();
        assert!((two.entropy_bits() - exact).abs() < 1e-9);
        // The class guarantee costs a little compared with the naive figure.
        let all = PasswordOptions::default();
        let naive = 20.0 * 86f64.log2();
        assert!(all.entropy_bits() < naive && all.entropy_bits() > naive - 1.0);
        let long = PasswordOptions {
            length: 128,
            ..Default::default()
        };
        assert!(long.entropy_bits().is_finite() && long.entropy_bits() > 800.0);

        let phrase = PhraseOptions::default();
        assert!((phrase.entropy_bits() - 5.0 * 7776f64.log2()).abs() < 1e-9);
        let with_number = PhraseOptions {
            add_number: true,
            ..Default::default()
        };
        assert!(
            (with_number.entropy_bits() - (5.0 * 7776f64.log2() + 10f64.log2() + 5f64.log2()))
                .abs()
                < 1e-9
        );
        assert!((pin_entropy_bits(6) - 19.93).abs() < 0.01);
    }

    #[test]
    fn passphrases() {
        assert_eq!(words().len(), 7776);
        assert_eq!(words()[0], "abacus");
        assert_eq!(words()[7775], "zoom");
        let mut rng = OsRng;
        let p = passphrase(&PhraseOptions::default(), &mut rng);
        let parts: Vec<&str> = p.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert!(parts.iter().all(|w| words().contains(w)));
        let opts = PhraseOptions {
            words: 4,
            separator: " ".into(),
            capitalise: true,
            add_number: true,
        };
        let p = passphrase(&opts, &mut rng);
        assert_eq!(p.split(' ').count(), 4);
        assert_eq!(p.chars().filter(|c| c.is_ascii_digit()).count(), 1);
        assert!(p
            .split(' ')
            .all(|w| w.chars().next().unwrap().is_uppercase()));
        assert_eq!(
            PhraseOptions {
                words: 99,
                ..Default::default()
            }
            .word_count(),
            12
        );
    }

    #[test]
    fn pins_usernames_tokens() {
        for trivial in [
            "0000", "1234", "4321", "9012", "1212", "123123", "1221", "1987", "2024", "7777777",
            "6969", "89012345",
        ] {
            assert!(pin_is_trivial(trivial), "{trivial}");
        }
        for fine in ["4829", "907153", "31846", "5073916482"] {
            assert!(!pin_is_trivial(fine), "{fine}");
        }
        let mut rng = OsRng;
        for len in PIN_MIN..=PIN_MAX {
            let p = pin(len, &mut rng);
            assert_eq!(p.len(), len);
            assert!(p.chars().all(|c| c.is_ascii_digit()));
            assert!(!pin_is_trivial(&p));
        }
        assert_eq!(pin(1, &mut rng).len(), PIN_MIN);
        let u = username(&UsernameOptions::default(), &mut rng);
        assert!(u.chars().next().unwrap().is_uppercase());
        assert!(u.ends_with(|c: char| c.is_ascii_digit()));
        assert_eq!(token(16, TokenFormat::Hex, &mut rng).len(), 32);
        assert_eq!(token(64, TokenFormat::Hex, &mut rng).len(), 128);
        assert_eq!(token(1, TokenFormat::Hex, &mut rng).len(), 32);
        assert_eq!(token(32, TokenFormat::Base64, &mut rng).len(), 44);
        assert_ne!(
            *token(32, TokenFormat::Hex, &mut rng),
            *token(32, TokenFormat::Hex, &mut rng)
        );
    }
}
