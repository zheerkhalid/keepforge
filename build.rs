//! Build script: renders the KeepForge icon (vector, via tiny-skia) into a
//! multi-size .ico and a PNG for the window, then embeds the icon, manifest and version info.

#![allow(clippy::field_reassign_with_default)]

use std::{env, fs, path::PathBuf};
use tiny_skia::*;

fn rounded_rect(x0: f32, y0: f32, x1: f32, y1: f32, r: f32) -> Path {
    let mut pb = PathBuilder::new();
    pb.move_to(x0 + r, y0);
    pb.line_to(x1 - r, y0);
    pb.quad_to(x1, y0, x1, y0 + r);
    pb.line_to(x1, y1 - r);
    pb.quad_to(x1, y1, x1 - r, y1);
    pb.line_to(x0 + r, y1);
    pb.quad_to(x0, y1, x0, y1 - r);
    pb.line_to(x0, y0 + r);
    pb.quad_to(x0, y0, x0 + r, y0);
    pb.close();
    pb.finish().expect("rounded rect")
}

fn render_icon(size: u32) -> Vec<u8> {
    let mut pm = Pixmap::new(size, size).expect("pixmap");
    let s = size as f32 / 256.0;
    let id = Transform::identity();
    let small = size <= 24;

    // Background: rounded square, teal -> indigo diagonal gradient.
    let (x0, y0, x1, y1) = (8.0 * s, 8.0 * s, 248.0 * s, 248.0 * s);
    let bg = rounded_rect(x0, y0, x1, y1, 56.0 * s);
    let gradient = || {
        LinearGradient::new(
            Point::from_xy(x0, y0),
            Point::from_xy(x1, y1),
            vec![
                GradientStop::new(0.0, Color::from_rgba8(0x0f, 0xb5, 0xa6, 255)),
                GradientStop::new(1.0, Color::from_rgba8(0x3b, 0x3f, 0xd8, 255)),
            ],
            SpreadMode::Pad,
            id,
        )
        .expect("gradient")
    };
    let mut paint = Paint::default();
    paint.anti_alias = true;
    paint.shader = gradient();
    pm.fill_path(&bg, &paint, FillRule::Winding, id, None);

    // White shield. Small sizes get a slightly larger one so it stays readable.
    let k = if small { 1.12 } else { 1.0 };
    let p = |x: f32, y: f32| ((128.0 + (x - 128.0) * k) * s, (130.0 + (y - 130.0) * k) * s);
    let mut pb = PathBuilder::new();
    let (mx, my) = p(128.0, 44.0);
    pb.move_to(mx, my);
    let c = |pb: &mut PathBuilder, a: (f32, f32), b: (f32, f32), e: (f32, f32)| {
        let (a, b, e) = (p(a.0, a.1), p(b.0, b.1), p(e.0, e.1));
        pb.cubic_to(a.0, a.1, b.0, b.1, e.0, e.1);
    };
    c(&mut pb, (150.0, 60.0), (176.0, 68.0), (200.0, 70.0));
    let (lx, ly) = p(200.0, 124.0);
    pb.line_to(lx, ly);
    c(&mut pb, (200.0, 168.0), (172.0, 198.0), (128.0, 216.0));
    c(&mut pb, (84.0, 198.0), (56.0, 168.0), (56.0, 124.0));
    let (lx, ly) = p(56.0, 70.0);
    pb.line_to(lx, ly);
    c(&mut pb, (80.0, 68.0), (106.0, 60.0), (128.0, 44.0));
    pb.close();
    let shield = pb.finish().expect("shield");
    let mut white = Paint::default();
    white.anti_alias = true;
    white.set_color_rgba8(0xff, 0xff, 0xff, 255);
    pm.fill_path(&shield, &white, FillRule::Winding, id, None);

    // Keyhole cut into the shield: a circle and a tapered slot, in the dark
    // end of the gradient.
    let mut dark = Paint::default();
    dark.anti_alias = true;
    dark.set_color_rgba8(0x2f, 0x35, 0xc4, 255);
    let (r, half_top, half_bottom, bottom) = if small {
        (27.0, 12.0, 20.0, 178.0)
    } else {
        (21.0, 9.0, 17.0, 172.0)
    };
    let mut pb = PathBuilder::new();
    pb.push_circle(128.0 * s, 112.0 * s, r * s);
    let hole = pb.finish().expect("hole");
    pm.fill_path(&hole, &dark, FillRule::Winding, id, None);
    let mut pb = PathBuilder::new();
    pb.move_to((128.0 - half_top) * s, 118.0 * s);
    pb.line_to((128.0 + half_top) * s, 118.0 * s);
    pb.line_to((128.0 + half_bottom) * s, bottom * s);
    pb.line_to((128.0 - half_bottom) * s, bottom * s);
    pb.close();
    let slot = pb.finish().expect("slot");
    pm.fill_path(&slot, &dark, FillRule::Winding, id, None);

    pm.encode_png().expect("png")
}

fn write_ico(path: &PathBuf, sizes: &[u32]) {
    let pngs: Vec<Vec<u8>> = sizes.iter().map(|&s| render_icon(s)).collect();
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]);
    out.extend_from_slice(&(sizes.len() as u16).to_le_bytes());
    let mut offset = 6 + 16 * sizes.len() as u32;
    for (i, &s) in sizes.iter().enumerate() {
        let b = if s >= 256 { 0 } else { s as u8 };
        out.extend_from_slice(&[b, b, 0, 0, 1, 0, 32, 0]);
        out.extend_from_slice(&(pngs[i].len() as u32).to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += pngs[i].len() as u32;
    }
    for p in &pngs {
        out.extend_from_slice(p);
    }
    fs::write(path, out).expect("write ico");
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let out = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let ico = out.join("keepforge.ico");
    write_ico(&ico, &[16, 20, 24, 32, 40, 48, 64, 256]);
    let png = render_icon(256);
    fs::write(out.join("icon-256.png"), &png).expect("write png");
    for small in [16u32, 32, 48] {
        fs::write(out.join(format!("icon-{small}.png")), render_icon(small))
            .expect("write small png");
    }
    let docs_png = PathBuf::from("docs/assets/keepforge-icon.png");
    if fs::read(&docs_png).ok().as_deref() != Some(&png[..]) {
        let _ = fs::create_dir_all("docs/assets");
        let _ = fs::write(&docs_png, &png);
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let ver = env::var("CARGO_PKG_VERSION").expect("version");
    let parts: Vec<u16> = ver
        .split(['.', '-'])
        .take(3)
        .map(|p| p.parse().unwrap_or(0))
        .collect();
    let (ma, mi, pa) = (
        parts[0],
        parts.get(1).copied().unwrap_or(0),
        parts.get(2).copied().unwrap_or(0),
    );
    let ver4 = format!("{ma}.{mi}.{pa}.0");
    println!("cargo:rerun-if-changed=res/keepforge.manifest.in");
    let manifest = fs::read_to_string("res/keepforge.manifest.in")
        .expect("manifest")
        .replace("@VERSION4@", &ver4);
    let manifest_path = out.join("keepforge.manifest");
    fs::write(&manifest_path, manifest).expect("write manifest");
    let esc = |p: &PathBuf| p.display().to_string().replace('\\', "\\\\");
    let rc = format!(
        r#"#pragma code_page(65001)
1 ICON "{ico}"
1 24 "{manifest}"
1 VERSIONINFO
FILEVERSION {ma},{mi},{pa},0
PRODUCTVERSION {ma},{mi},{pa},0
FILEOS 0x40004
FILETYPE 0x1
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "Zheer Khalid (zheer.dev)"
      VALUE "FileDescription", "KeepForge password manager"
      VALUE "FileVersion", "{ver}"
      VALUE "InternalName", "KeepForge"
      VALUE "LegalCopyright", "Copyright (c) 2026 Zheer Khalid. MIT License."
      VALUE "OriginalFilename", "KeepForge.exe"
      VALUE "ProductName", "KeepForge"
      VALUE "ProductVersion", "{ver}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        ico = esc(&ico),
        manifest = esc(&manifest_path),
    );
    let rc_path = out.join("keepforge.rc");
    fs::write(&rc_path, rc).expect("write rc");
    embed_resource::compile(&rc_path, embed_resource::NONE);
    println!("cargo:rustc-link-arg-bins=/MANIFEST:NO");
}
