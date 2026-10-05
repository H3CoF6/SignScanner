//! signscanner — 静态定位 QQ `wrapper.node` 里的签名函数。
//!
//! 传入一个 `wrapper.node`（ELF / PE / Mach-O universal），自动识别容器、
//! 架构与 C++ ABI，再沿稳定的 RTTI/名字锚点链定位签名核函数：
//!
//! ```text
//! Itanium (Linux/macOS): name -> typeinfo -> vtable -> MSFSign -> sign core
//! MSVC    (Windows):     type descriptor -> COL -> vtable -> MSFSign -> sign core
//! ```
//!
//! 全程不做事先的字节特征匹配——除了那串 RTTI 类型名本身。

mod art;
mod ui;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use signscanner::image::{Abi, Image, View};
use signscanner::locate::{self, Location};

#[derive(Parser)]
#[command(
    name = "signscanner",
    version,
    about = "静态定位 QQ wrapper.node 的签名函数（名字/RTTI 锚点，零字节特征）",
    long_about = "signscanner — 静态定位 QQ wrapper.node 里的签名函数。\n\
        \n\
        传入一个 wrapper.node（ELF / PE / Mach-O universal），自动识别容器、架构与\n\
        C++ ABI，再沿稳定的 RTTI/名字锚点链定位签名核函数：\n\
        \n\
        \x20 Itanium (Linux/macOS): name -> typeinfo -> vtable -> MSFSign -> sign core\n\
        \x20 MSVC    (Windows):     type descriptor -> COL -> vtable -> MSFSign -> sign core\n\
        \n\
        全程不做事先的字节特征匹配——除了那串 RTTI 类型名本身。"
)]
struct Cli {
    /// wrapper.node 路径（ELF / PE / Mach-O universal；自动识别架构）
    path: PathBuf,

    /// 以 JSON 输出（便于脚本消费；不打印 banner/TUI）
    #[arg(long)]
    json: bool,

    /// 覆盖 RTTI 锚点名（默认按 ABI 自动选择）
    #[arg(long, value_name = "NAME")]
    typeinfo: Option<String>,

    /// 不打印启动 banner
    #[arg(long)]
    no_banner: bool,

    /// 只输出最终签名函数 RVA（每切片一行，便于脚本）
    #[arg(short, long)]
    quiet: bool,
}

fn anchor_for(abi: Abi) -> &'static str {
    match abi {
        Abi::Itanium => locate::TYPEINFO_NAME_ITANIUM,
        Abi::MsVc => locate::TYPEINFO_NAME_MSVC,
    }
}

fn rva(base: u64, addr: u64) -> u64 {
    addr.wrapping_sub(base)
}

/// 文本模式：渲染一个切片的定位结果（圆角方框）。
fn report_text(view: &View, loc: &Location, index: usize, total: usize) {
    let base = view.image_base();
    let mut body = vec![
        ui::chain_line("anchor", &ui::dim(&loc.typeinfo_name)),
        ui::chain_line("typeinfo", &ui::addr(rva(base, loc.typeinfo_addr))),
        ui::chain_line(
            "vtable",
            &format!(
                "{} {}",
                ui::addr(rva(base, loc.vtable_addr)),
                ui::dim(&format!("({} code slots)", loc.vtable_slots))
            ),
        ),
        ui::chain_line(
            "MSFSign",
            &format!(
                "{} {}",
                ui::addr(rva(base, loc.callback_addr)),
                ui::dim(&format!("({} direct calls)", loc.callback_calls))
            ),
        ),
        ui::chain_line("sign core", &ui::addr(rva(base, loc.sign_fn_addr))),
    ];
    if let Some(off) = loc.file_offset(view) {
        body.push(ui::chain_line("file offset", &ui::addr(off as u64)));
    }
    body.push(String::new());
    body.push(format!(
        "{}  {}",
        ui::paint(
            ui::palette::accent(),
            &format!("0x{:x}", rva(base, loc.sign_fn_addr))
        ),
        ui::dim("← 签名函数 RVA（定位目标）")
    ));

    let header = format!("slice {}/{} · {}", index + 1, total, view.describe());
    ui::panel(ui::palette::accent(), &header, &body, 64);
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn json_item(view: &View, loc: &Location) -> String {
    let base = view.image_base();
    let off = loc
        .file_offset(view)
        .map(|o| format!("\"0x{o:x}\""))
        .unwrap_or_else(|| "null".into());
    format!(
        "{{\"format\":\"{}\",\"abi\":\"{}\",\"arch\":\"{}\",\
         \"typeinfo_name\":\"{}\",\"typeinfo\":\"0x{:x}\",\
         \"vtable\":\"0x{:x}\",\"vtable_slots\":{},\
         \"callback\":\"0x{:x}\",\"callback_calls\":{},\
         \"sign_function\":\"0x{:x}\",\
         \"sign_function_file_offset\":{off}}}",
        json_escape(&view.describe()),
        view.abi().name(),
        view.arch().name(),
        json_escape(&loc.typeinfo_name),
        rva(base, loc.typeinfo_addr),
        rva(base, loc.vtable_addr),
        loc.vtable_slots,
        rva(base, loc.callback_addr),
        loc.callback_calls,
        rva(base, loc.sign_fn_addr),
    )
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let show_tui = !cli.json && !cli.quiet;
    if show_tui && !cli.no_banner {
        ui::app_banner("wrapper.node 签名函数静态定位 · 名字/RTTI 锚点，零字节特征");
    }

    let image = match Image::open(&cli.path) {
        Ok(i) => i,
        Err(e) => {
            ui::error(&e);
            return ExitCode::from(1);
        }
    };

    if image.slices.is_empty() {
        ui::error(&format!(
            "无法识别的容器：{}（期望 ELF / PE / Mach-O）",
            cli.path.display()
        ));
        return ExitCode::from(1);
    }

    let views = image.views();
    let total = views.len();

    if show_tui {
        let summary = vec![
            ui::chain_line("file", &ui::paint(ui::palette::path(), &image.path)),
            ui::chain_line("format", image.format_name()),
            ui::chain_line("slices", &total.to_string()),
        ];
        ui::panel(ui::palette::primary(), "target", &summary, 60);
    }

    let mut json_items: Vec<String> = Vec::new();
    let mut failures = 0usize;

    for (i, view) in views.iter().enumerate() {
        let name = cli
            .typeinfo
            .clone()
            .unwrap_or_else(|| anchor_for(view.abi()).to_string());
        match locate::locate(view, &name) {
            Ok(loc) => {
                if cli.json {
                    json_items.push(json_item(view, &loc));
                } else if cli.quiet {
                    println!("0x{:x}", rva(view.image_base(), loc.sign_fn_addr));
                } else {
                    if i > 0 {
                        println!();
                    }
                    report_text(view, &loc, i, total);
                }
            }
            Err(e) => {
                failures += 1;
                if cli.json {
                    json_items.push(format!(
                        "{{\"format\":\"{}\",\"abi\":\"{}\",\"arch\":\"{}\",\"error\":\"{}\"}}",
                        json_escape(&view.describe()),
                        view.abi().name(),
                        view.arch().name(),
                        json_escape(&e),
                    ));
                } else if cli.quiet {
                    println!("error: slice {}/{}: {e}", i + 1, total);
                } else {
                    ui::warn(&format!("slice {}/{} {}: {e}", i + 1, total, view.describe()));
                }
            }
        }
    }

    if cli.json {
        println!("[{}]", json_items.join(","));
    } else if show_tui {
        println!();
        if failures == 0 {
            ui::ok(&format!("定位完成：{total} 个切片全部命中。"));
        } else {
            ui::warn(&format!(
                "定位结束：{total} 个切片，{} 成功 / {failures} 失败。",
                total - failures
            ));
        }
    }

    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
