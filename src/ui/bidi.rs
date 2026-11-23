//! Display of right-to-left scripts (Kurdish Sorani, Arabic, Persian, Urdu,
//! Hebrew…).
//!
//! egui lays text out one glyph per character, left to right, and never joins
//! letters, so a Kurdish or Arabic title comes out backwards and in pieces.
//! Substituting "presentation form" characters is not enough either: several
//! Kurdish letters (ڕ ڵ ە ێ) have none, so words still break apart.
//!
//! Instead, text that contains such letters is drawn by Windows itself (GDI,
//! which shapes every script and orders mixed text the way File Explorer
//! does) into a small white-on-transparent bitmap, kept as an egui texture and
//! tinted with the wanted colour. Everything else still goes through egui, so
//! ordinary text costs one character scan.
//!
//! The bitmaps are a second copy of what is on screen. They are dropped when
//! the vault locks ([`clear`]); bitmaps of revealed secrets are dropped as
//! soon as a frame goes by without them being shown ([`end_frame`]).

use eframe::egui::{
    self, pos2, vec2, Color32, ColorImage, Rect, Sense, TextureHandle, TextureOptions, Ui, Vec2,
};
use std::cell::RefCell;
use std::collections::HashMap;

fn is_rtl_char(c: char) -> bool {
    matches!(c as u32, 0x0590..=0x08FF | 0xFB1D..=0xFDFF | 0xFE70..=0xFEFF)
}

/// Whether `s` contains right-to-left letters that egui cannot draw properly.
pub fn needs_native(s: &str) -> bool {
    s.chars().any(is_rtl_char)
}

/// Whether a paragraph reads right to left: decided by its first letter.
pub fn starts_rtl(s: &str) -> bool {
    s.chars()
        .find(|c| c.is_alphabetic())
        .map(is_rtl_char)
        .unwrap_or(false)
}

/// A rendered piece of text: white, with coverage in the alpha channel.
struct Rendered {
    pixels: Vec<u8>,
    width: usize,
    height: usize,
    cut: bool,
}

#[derive(Hash, PartialEq, Eq, Clone)]
struct Key {
    text: String,
    size_px: u32,
    bold: bool,
    max_px: u32,
    wrap: bool,
}

struct Entry {
    tex: TextureHandle,
    size_px: [usize; 2],
    cut: bool,
    secret: bool,
    used: u64,
}

/// The cache is emptied when it grows large.
const CACHE_LIMIT: usize = 800;
/// Ordinary lines are dropped after this many frames without use.
const KEEP_FRAMES: u64 = 600;
/// The tallest paragraph that is drawn (physical pixels).
const MAX_HEIGHT_PX: i32 = 6000;

thread_local! {
    static CACHE: RefCell<HashMap<Key, Entry>> = RefCell::new(HashMap::new());
}

/// Drops every rendered bitmap (called when the vault locks).
pub fn clear() {
    CACHE.with(|c| c.borrow_mut().clear());
}

/// Call once per frame, after drawing: forgets bitmaps of secrets that were
/// not shown in this frame, and ordinary ones that have not been shown for a
/// while.
pub fn end_frame(ctx: &egui::Context) {
    let frame = ctx.cumulative_pass_nr();
    CACHE.with(|c| {
        c.borrow_mut().retain(|_, e| {
            if e.secret {
                e.used + 1 >= frame
            } else {
                e.used + KEEP_FRAMES >= frame
            }
        })
    });
}

#[cfg(windows)]
fn render(text: &str, size_px: u32, bold: bool, max_px: u32, wrap: bool) -> Option<Rendered> {
    use windows::core::w;
    use windows::Win32::Foundation::{COLORREF, RECT};
    use windows::Win32::Graphics::Gdi::*;

    let mut wide: Vec<u16> = text.encode_utf16().collect();
    if wide.is_empty() || size_px == 0 {
        return None;
    }
    let max_px = max_px.clamp(1, 16_000) as i32;
    // SAFETY: plain GDI calls on a memory DC, a font and a DIB section that
    // are created here and released before returning; `bits` points at
    // `width * height * 4` bytes owned by the DIB section while it is alive.
    unsafe {
        let dc = CreateCompatibleDC(None);
        if dc.is_invalid() {
            return None;
        }
        let mut face = [0u16; 32];
        let name = w!("Segoe UI");
        let name = name.as_wide();
        face[..name.len()].copy_from_slice(name);
        let lf = LOGFONTW {
            lfHeight: -(size_px as i32),
            lfWeight: if bold { 600 } else { 400 },
            lfCharSet: DEFAULT_CHARSET,
            lfOutPrecision: OUT_TT_PRECIS,
            lfClipPrecision: CLIP_DEFAULT_PRECIS,
            lfQuality: ANTIALIASED_QUALITY,
            lfFaceName: face,
            ..Default::default()
        };
        let font = CreateFontIndirectW(&lf);
        let old_font = SelectObject(dc, font);

        let rtl = starts_rtl(text);
        let base = if wrap {
            let mut f = DT_WORDBREAK | DT_NOPREFIX | DT_EXPANDTABS | DT_EDITCONTROL;
            if rtl {
                f |= DT_RTLREADING | DT_RIGHT;
            }
            f
        } else {
            DT_SINGLELINE | DT_NOPREFIX
        };
        let mut measure = RECT {
            left: 0,
            top: 0,
            right: if wrap { max_px } else { 0 },
            bottom: 0,
        };
        DrawTextW(dc, &mut wide, &mut measure, base | DT_CALCRECT);
        let natural = measure.right.max(1);
        let height = measure.bottom.clamp(1, MAX_HEIGHT_PX) as usize;
        let cut = if wrap {
            measure.bottom > MAX_HEIGHT_PX
        } else {
            natural > max_px
        };
        // A right-to-left paragraph of several lines keeps the full width, so
        // that its lines end at the right edge. One that fits on a single
        // line is only as wide as its text, like any other value.
        let mut full_width = wrap && rtl;
        if full_width && !text.contains('\n') {
            let mut one = RECT::default();
            DrawTextW(
                dc,
                &mut wide,
                &mut one,
                DT_SINGLELINE | DT_NOPREFIX | DT_CALCRECT,
            );
            full_width = one.right > max_px;
        }
        let width = if full_width {
            max_px
        } else {
            natural.min(max_px)
        } as usize;

        let header = BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width as i32,
            biHeight: -(height as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        };
        let info = BITMAPINFO {
            bmiHeader: header,
            ..Default::default()
        };
        let mut bits: *mut core::ffi::c_void = std::ptr::null_mut();
        let result = match CreateDIBSection(dc, &info, DIB_RGB_COLORS, &mut bits, None, 0) {
            Ok(bmp) if !bits.is_null() => {
                let old_bmp = SelectObject(dc, bmp);
                SetBkMode(dc, TRANSPARENT);
                SetTextColor(dc, COLORREF(0x00FF_FFFF));
                let mut area = RECT {
                    left: 0,
                    top: 0,
                    right: width as i32,
                    bottom: height as i32,
                };
                let mut flags = base;
                if !wrap {
                    flags |= DT_LEFT | DT_VCENTER;
                    if cut {
                        flags |= DT_END_ELLIPSIS;
                    }
                }
                DrawTextW(dc, &mut wide, &mut area, flags);
                let _ = GdiFlush();
                let src = std::slice::from_raw_parts_mut(bits as *mut u8, width * height * 4);
                let mut pixels = Vec::with_capacity(width * height * 4);
                for px in src.as_chunks::<4>().0 {
                    // Grey-scale anti-aliasing: any channel is the coverage.
                    // A mild curve thins the edges to match egui's own text weight.
                    let c = px[0].max(px[1]).max(px[2]);
                    let a = (255.0 * (f32::from(c) / 255.0).powf(1.45)).round() as u8;
                    pixels.extend_from_slice(&[255, 255, 255, a]);
                }
                // The GDI copy is not needed any more.
                src.fill(0);
                SelectObject(dc, old_bmp);
                let _ = DeleteObject(bmp);
                Some(Rendered {
                    pixels,
                    width,
                    height,
                    cut,
                })
            }
            _ => None,
        };
        zeroize::Zeroize::zeroize(&mut wide);
        SelectObject(dc, old_font);
        let _ = DeleteObject(font);
        let _ = DeleteDC(dc);
        result
    }
}

#[cfg(not(windows))]
fn render(_: &str, _: u32, _: bool, _: u32, _: bool) -> Option<Rendered> {
    None
}

/// Looks up or renders a piece of text. Sizes are in physical pixels.
fn cached(
    ctx: &egui::Context,
    text: &str,
    size_px: u32,
    bold: bool,
    max_px: u32,
    wrap: bool,
    secret: bool,
) -> Option<([usize; 2], egui::TextureId, bool)> {
    let frame = ctx.cumulative_pass_nr();
    CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        // Looked up by reference first, so a hit does not copy the text.
        if let Some(e) = cache.iter_mut().find_map(|(k, e)| {
            (k.size_px == size_px
                && k.bold == bold
                && k.max_px == max_px
                && k.wrap == wrap
                && k.text == text)
                .then_some(e)
        }) {
            e.used = frame;
            e.secret |= secret;
            return Some((e.size_px, e.tex.id(), e.cut));
        }
        let mut r = render(text, size_px, bold, max_px, wrap)?;
        let image = ColorImage::from_rgba_unmultiplied([r.width, r.height], &r.pixels);
        zeroize::Zeroize::zeroize(&mut r.pixels);
        let tex = ctx.load_texture("rtl-text", image, TextureOptions::NEAREST);
        if cache.len() >= CACHE_LIMIT {
            cache.clear();
        }
        let out = ([r.width, r.height], tex.id(), r.cut);
        cache.insert(
            Key {
                text: text.to_string(),
                size_px,
                bold,
                max_px,
                wrap,
            },
            Entry {
                tex,
                size_px: [r.width, r.height],
                cut: r.cut,
                secret,
                used: frame,
            },
        );
        Some(out)
    })
}

fn snap(v: f32, ppp: f32) -> f32 {
    (v * ppp).round() / ppp
}

const UV: Rect = Rect {
    min: pos2(0.0, 0.0),
    max: pos2(1.0, 1.0),
};

/// Paints `text` on one line inside `rect`, vertically centred, cut with an
/// ellipsis when too wide. Returns `None` when native drawing is unavailable,
/// otherwise whether the text was cut.
pub fn paint(
    ui: &Ui,
    rect: Rect,
    text: &str,
    size_pt: f32,
    bold: bool,
    color: Color32,
    right: bool,
) -> Option<bool> {
    let ppp = ui.ctx().pixels_per_point();
    let size_px = (size_pt * ppp).round() as u32;
    let max_px = (rect.width() * ppp).floor().max(1.0) as u32;
    let (size, tex, cut) = cached(ui.ctx(), text, size_px, bold, max_px, false, false)?;
    let size_pt = vec2(size[0] as f32, size[1] as f32) / ppp;
    let x = if right {
        rect.right() - size_pt.x
    } else {
        rect.left()
    };
    let y = rect.center().y - size_pt.y / 2.0;
    // Snapped to whole pixels so the bitmap is drawn 1:1, without blurring.
    let min = pos2(snap(x, ppp), snap(y, ppp));
    ui.painter()
        .image(tex, Rect::from_min_size(min, size_pt), UV, color);
    Some(cut)
}

/// The size `text` would take on one line, in points.
pub fn measure(ui: &Ui, text: &str, size_pt: f32, bold: bool) -> Option<Vec2> {
    let ppp = ui.ctx().pixels_per_point();
    let size_px = (size_pt * ppp).round() as u32;
    let (size, _, _) = cached(ui.ctx(), text, size_px, bold, 16_000, false, false)?;
    Some(vec2(size[0] as f32, size[1] as f32) / ppp)
}

/// A one-line label that truncates, drawn natively. Returns `None` (and
/// draws nothing) when the text does not need it or it is unavailable.
pub fn label(
    ui: &mut Ui,
    text: &str,
    size_pt: f32,
    bold: bool,
    color: Color32,
) -> Option<egui::Response> {
    if !needs_native(text) {
        return None;
    }
    let natural = measure(ui, text, size_pt, bold)?;
    let width = natural.x.min(ui.available_width()).max(1.0);
    let (rect, response) = ui.allocate_exact_size(vec2(width, natural.y), Sense::hover());
    let cut = paint(ui, rect, text, size_pt, bold, color, false).unwrap_or(false);
    Some(if cut {
        response.on_hover_text(text)
    } else {
        response
    })
}

/// A wrapped paragraph as wide as the space available, drawn natively.
/// `secret` bitmaps are forgotten as soon as they are no longer shown.
/// Returns `None` (and draws nothing) when the text does not need it.
pub fn paragraph(
    ui: &mut Ui,
    text: &str,
    size_pt: f32,
    color: Color32,
    secret: bool,
) -> Option<egui::Response> {
    if !needs_native(text) {
        return None;
    }
    let ppp = ui.ctx().pixels_per_point();
    let size_px = (size_pt * ppp).round() as u32;
    let max_px = (ui.available_width() * ppp).floor().max(8.0) as u32;
    let (size, tex, _) = cached(ui.ctx(), text, size_px, false, max_px, true, secret)?;
    let size_pt = vec2(size[0] as f32, size[1] as f32) / ppp;
    let (rect, response) = ui.allocate_exact_size(size_pt, Sense::hover());
    let min = pos2(snap(rect.left(), ppp), snap(rect.top(), ppp));
    ui.painter()
        .image(tex, Rect::from_min_size(min, size_pt), UV, color);
    Some(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ink(r: &Rendered) -> usize {
        r.pixels
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|p| p[3] > 128)
            .count()
    }

    #[test]
    fn only_rtl_text_takes_the_native_path() {
        assert!(!needs_native("Example Mail"));
        assert!(!needs_native("alex.morgan@example.com"));
        assert!(!needs_native("Café Zürich ☕"));
        assert!(needs_native("بانکی نموونە"));
        assert!(needs_native("Mail ئیمەیڵ"));
        assert!(needs_native("תיקייה"));
        assert!(starts_rtl("١٢٣ ژمارە"));
        assert!(starts_rtl("  بانک (bank)"));
        assert!(!starts_rtl("Bank بانک"));
        assert!(!starts_rtl("12345"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_draws_kurdish_text() {
        let r = render("بەڵگەنامەکان ڕاپۆرت", 20, false, 2000, false).expect("rendered");
        assert!(r.width > 40 && r.height >= 18, "{}x{}", r.width, r.height);
        assert!(!r.cut);
        assert!(ink(&r) > 50, "expected visible letters");
        // Joined letters take less room than the same letters drawn apart.
        let apart = render("ب ە ڵ گ ە ن ا م ە ک ا ن", 20, false, 2000, false).expect("rendered");
        let joined = render("بەڵگەنامەکان", 20, false, 2000, false).expect("rendered");
        assert!(joined.width < apart.width);
    }

    #[cfg(windows)]
    #[test]
    fn long_lines_are_cut_and_paragraphs_wrap() {
        let text = "ڕاپۆرتی ساڵانەی بەڵگەنامەکانی کوردستان";
        let r = render(text, 20, false, 60, false).expect("rendered");
        assert!(r.cut);
        assert_eq!(r.width, 60);
        let one = render(text, 20, false, 4000, true).expect("rendered");
        let wrapped = render(text, 20, false, 120, true).expect("rendered");
        assert_eq!(wrapped.width, 120);
        assert!(wrapped.height > one.height * 2, "the paragraph wraps");
        assert!(ink(&wrapped) > 50);
        // Line breaks in the text are kept.
        let two = render("یەک\nدوو", 20, false, 4000, true).expect("rendered");
        assert!(two.height >= one.height * 2 - 2);
        // So is a short right-to-left one; only longer ones fill the width.
        let short = render("بانک", 20, false, 4000, true).expect("rendered");
        assert!(short.width < 200, "{}", short.width);
        // A left-to-right paragraph with a Kurdish word is only as wide as needed.
        let mixed = render("Bank بانک", 20, false, 4000, true).expect("rendered");
        assert!(mixed.width < 400);
    }
}
