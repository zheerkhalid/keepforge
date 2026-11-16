//! The emergency sheet: a page to print, fill in by hand and keep somewhere
//! safe. KeepForge never writes the master password into it.

use crate::util;

fn esc(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The sheet as a self-contained HTML page (no scripts, no external files).
pub fn html(
    vault_name: &str,
    vault_path: &str,
    uses_key_file: bool,
    kdf: &str,
    now: i64,
) -> String {
    let key_file = if uses_key_file {
        "<div class=\"box\"><h2>Key file</h2><p>This vault also needs its <b>key file</b>. \
         Keep a copy of the key file somewhere safe, separate from the vault file. \
         Without it the vault cannot be opened, even with the right password.</p>\
         <p>Where my key file copy is kept:</p><div class=\"line\"></div></div>"
    } else {
        ""
    };
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>KeepForge emergency sheet</title>
<style>
body{{font-family:"Segoe UI",Arial,sans-serif;color:#14202a;max-width:720px;margin:40px auto;padding:0 24px;line-height:1.5}}
h1{{font-size:26px;margin-bottom:4px}} h2{{font-size:16px;margin:0 0 6px}}
.sub{{color:#566572;margin-top:0}}
.box{{border:1px solid #c9d3da;border-radius:10px;padding:16px 18px;margin:16px 0}}
.line{{border-bottom:1.5px solid #14202a;height:38px;margin:6px 0 14px}}
.mono{{font-family:Consolas,monospace;word-break:break-all}}
.warn{{border-color:#e03d31}} .small{{color:#566572;font-size:13px}}
@media print{{body{{margin:10mm auto}}}}
</style></head><body>
<h1>KeepForge emergency sheet</h1>
<p class="sub">Print this page, fill it in by hand, and keep it somewhere safe (a locked drawer, a safe, with someone you trust).</p>
<div class="box"><h2>Vault</h2>
<p>Name: <b>{name}</b><br>File: <span class="mono">{path}</span><br>Sheet created: {date}</p>
<p class="small">Protection: {kdf}, XChaCha20-Poly1305.</p></div>
<div class="box"><h2>Master password</h2>
<p>Write the master password here by hand. It is not printed, on purpose.</p>
<div class="line"></div><div class="line"></div></div>
{key_file}
<div class="box warn"><h2>Read this</h2>
<p>There is no "forgot password" for a KeepForge vault. Nobody, including the developer, can open it without the master password{and_key}. If both the password and this sheet are lost, the contents are lost.</p>
<p>Anyone who has this sheet and the vault file can read everything in the vault. Do not store a photo or scan of the filled-in sheet on a computer or phone.</p></div>
<p class="small">To open the vault on another PC: install KeepForge, choose "Open an existing vault", pick the vault file and type the master password.</p>
</body></html>
"#,
        name = esc(vault_name),
        path = esc(vault_path),
        date = util::fmt_date(now),
        kdf = esc(kdf),
        key_file = key_file,
        and_key = if uses_key_file {
            " and the key file"
        } else {
            ""
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sheet_is_escaped_and_holds_no_password_field_value() {
        let page = html(
            "My <vault> & \"co\"",
            "C:\\Vaults\\a<b>.kfv",
            true,
            "Argon2id, 256 MiB",
            0,
        );
        assert!(page.contains("My &lt;vault&gt; &amp; &quot;co&quot;"));
        assert!(page.contains("a&lt;b&gt;.kfv"));
        assert!(!page.contains("<vault>"));
        assert!(page.contains("Key file"));
        assert!(!page.contains("<script"));
        let plain = html("V", "v.kfv", false, "x", 0);
        assert!(!plain.contains("Where my key file copy is kept"));
    }
}
