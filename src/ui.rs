//! 彩色 TUI 输出 helpers（与 qqshark 同款配色栈：anstream + anstyle）。
//!
//! 启动横幅是硬编码的 ansi_shadow 艺术字 + 逐列青→品红 truecolor 渐变；
//! `section`/`field`/`ok` 用 anstyle 配色；定位结果用圆角方框框起来，
//! 顶部标注架构/ABI，正文含各级锚点与最终签名函数 RVA。

use anstyle::{AnsiColor, Color, RgbColor, Style};
use std::io::Write;

use crate::art::BANNER_ART;

fn styled(style: Style, text: &str) -> String {
    format!("{style}{text}{style:#}")
}

fn fg(c: AnsiColor) -> Style {
    Style::new().fg_color(Some(Color::Ansi(c)))
}

/// Linear cyan(0,255,255)→magenta(255,0,255) at position `t` in [0,1].
fn gradient(t: f32) -> Style {
    let t = t.clamp(0.0, 1.0);
    let r = (t * 255.0).round() as u8;
    let g = ((1.0 - t) * 255.0).round() as u8;
    Style::new()
        .fg_color(Some(Color::Rgb(RgbColor(r, g, 255))))
        .bold()
}

/// 结构化输出的语义色板。
pub mod palette {
    use anstyle::{AnsiColor, Color, RgbColor, Style};

    fn c(col: AnsiColor) -> Style {
        Style::new().fg_color(Some(Color::Ansi(col)))
    }

    /// 暗色：标签、标点、次要信息。
    pub fn dim() -> Style {
        c(AnsiColor::BrightBlack)
    }
    /// 强调：最终结果。
    pub fn accent() -> Style {
        c(AnsiColor::BrightGreen).bold()
    }
    /// 主色：section 标题 / 方框边框。
    pub fn primary() -> Style {
        c(AnsiColor::Cyan).bold()
    }
    /// 锚点链条。
    pub fn chain() -> Style {
        c(AnsiColor::BrightCyan)
    }
    /// RVA 数值（暖金色，跳出冷色调的锚点链）。
    pub fn addr() -> Style {
        Style::new()
            .fg_color(Some(Color::Rgb(RgbColor(255, 200, 90))))
            .bold()
    }
    /// 文件名/路径。
    pub fn path() -> Style {
        c(AnsiColor::BrightWhite).bold()
    }
}

/// 给一段文本套上颜色。
pub fn paint(style: Style, text: &str) -> String {
    styled(style, text)
}

/// 打印启动横幅：渐变艺术字 + 副标题。
pub fn app_banner(subtitle: &str) {
    let mut out = anstream::stdout();
    let _ = writeln!(out);
    let width = BANNER_ART
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(1)
        .max(1) as f32;
    for line in BANNER_ART {
        let mut painted = String::new();
        for (col, ch) in line.chars().enumerate() {
            if ch == ' ' {
                painted.push(' ');
            } else {
                let g = gradient(col as f32 / width);
                painted.push_str(&format!("{g}{ch}{g:#}"));
            }
        }
        let _ = writeln!(out, "{painted}");
    }
    let _ = writeln!(out, "  {}\n", styled(fg(AnsiColor::BrightBlack), subtitle));
}

pub fn ok(msg: &str) {
    let mut out = anstream::stdout();
    let _ = writeln!(
        out,
        "{}  {msg}",
        styled(fg(AnsiColor::Green).bold(), "[ ok ]")
    );
}

pub fn warn(msg: &str) {
    let mut out = anstream::stderr();
    let _ = writeln!(
        out,
        "{} {msg}",
        styled(fg(AnsiColor::Yellow).bold(), "[warn]")
    );
}

pub fn error(msg: &str) {
    let mut out = anstream::stderr();
    let _ = writeln!(out, "{} {msg}", styled(fg(AnsiColor::Red).bold(), "[fail]"));
}

/// 一个字符的显示宽度：CJK 全角/emoji 记 2 列，其余 1 列。
fn char_width(c: char) -> usize {
    let u = c as u32;
    if (0x1100..=0x115F).contains(&u)
        || (0x2E80..=0xA4CF).contains(&u)
        || (0xAC00..=0xD7A3).contains(&u)
        || (0xF900..=0xFAFF).contains(&u)
        || (0xFE30..=0xFE4F).contains(&u)
        || (0xFF00..=0xFF60).contains(&u)
        || (0xFFE0..=0xFFE6).contains(&u)
        || (0x1F300..=0x1FAFF).contains(&u)
    {
        2
    } else {
        1
    }
}

/// 显示宽度：跳过 ANSI CSI 转义序列（颜色不计宽），其余按 `char_width` 累加。
fn display_width(s: &str) -> usize {
    let mut width = 0;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for e in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&e) {
                        break;
                    }
                }
            }
            continue;
        }
        width += char_width(c);
    }
    width
}

fn pad_to(s: &str, cols: usize) -> String {
    let w = display_width(s);
    if w >= cols {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(cols - w))
    }
}

/// 圆角方框渲染：正文可含 ANSI 颜色，宽度按可见字符计算。
/// 返回纯文本（带边框字符），由 `panel` 负责上色后打印。
pub fn render_box(header: &str, body: &[String], min_width: usize) -> String {
    let head_w = display_width(header);
    let max_body = body.iter().map(|l| display_width(l)).max().unwrap_or(0);
    let content_w = max_body.max(head_w + 4).max(min_width);
    // 顶行 = head_w + 5 + dashes，正文行 = content_w + 4；令二者相等。
    let dashes = content_w.saturating_sub(head_w + 1);
    let mut out = String::new();
    out.push('╭');
    out.push('─');
    out.push(' ');
    out.push_str(header);
    out.push(' ');
    out.push_str(&"─".repeat(dashes));
    out.push('╮');
    out.push('\n');
    for line in body {
        out.push_str("│ ");
        out.push_str(&pad_to(line, content_w));
        out.push_str(" │\n");
    }
    out.push('╰');
    out.push_str(&"─".repeat(content_w + 2));
    out.push('╯');
    out
}

/// 彩色圆角方框：边框染 `accent`，首行标题加粗。
pub fn panel(accent: Style, header: &str, body: &[String], min_width: usize) {
    let plain = render_box(header, body, min_width);
    let mut out = anstream::stdout();
    for (i, line) in plain.lines().enumerate() {
        let painted = if i == 0 {
            styled(accent, line)
        } else {
            // 只给首尾框线着色，内容保持原样。
            let chars: Vec<char> = line.chars().collect();
            if chars.len() >= 2 {
                let mid: String = chars[1..chars.len() - 1].iter().collect();
                format!(
                    "{}{}{}",
                    styled(accent, &chars[0].to_string()),
                    mid,
                    styled(accent, &chars[chars.len() - 1].to_string())
                )
            } else {
                line.to_string()
            }
        };
        let _ = writeln!(out, "{painted}");
    }
}

/// 锚点链一行：`label  value`，label 用 chain 色。
pub fn chain_line(label: &str, value: &str) -> String {
    format!(
        "{} {}",
        paint(palette::chain(), &format!("{label:<10}")),
        value
    )
}

/// 数值（RVA/偏移）加色。
pub fn addr(v: u64) -> String {
    paint(palette::addr(), &format!("0x{v:x}"))
}

/// 次要用例文本。
pub fn dim(text: &str) -> String {
    paint(palette::dim(), text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn box_lines_share_width() {
        let b = render_box(
            "aarch64 · Itanium",
            &["hello".into(), "world!!".into(), "中文内容".into()],
            40,
        );
        let lines: Vec<&str> = b.lines().collect();
        assert_eq!(lines.len(), 5); // 上 + 3 + 下
        assert!(lines[0].starts_with('╭') && lines[0].ends_with('╮'));
        assert!(lines[4].starts_with('╰') && lines[4].ends_with('╯'));
        let w = display_width(lines[0]);
        for l in &lines {
            assert_eq!(display_width(l), w, "line width mismatch: {l:?}");
        }
    }

    #[test]
    fn ansi_sequences_do_not_count_toward_width() {
        let plain = format!("{:<10} {}", "chain", "0x10");
        let painted = format!(
            "{} {}",
            paint(palette::chain(), &format!("{:<10}", "chain")),
            paint(palette::addr(), "0x10")
        );
        assert_eq!(display_width(&plain), display_width(&painted));
    }

    #[test]
    fn gradient_stays_in_range() {
        assert_eq!(
            gradient(-1.0).get_fg_color(),
            Some(Color::Rgb(RgbColor(0, 255, 255)))
        );
        assert_eq!(
            gradient(2.0).get_fg_color(),
            Some(Color::Rgb(RgbColor(255, 0, 255)))
        );
    }

    #[test]
    fn colored_body_fits_box() {
        let body = vec![chain_line("sign", &addr(0xdead_beef))];
        let b = render_box("x86-64", &body, 60);
        let lines: Vec<&str> = b.lines().collect();
        let w = display_width(lines[0]);
        for l in &lines {
            assert_eq!(display_width(l), w, "line width mismatch: {l:?}");
        }
    }
}
