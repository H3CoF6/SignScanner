//! SignScanner — statically locate the QQ `wrapper.node` sign function using
//! stable name/RTTI anchors (no byte-pattern signatures).
//!
//! Usage:
//!   SignScanner <wrapper.node> [--json] [--typeinfo NAME] [--quiet]

use std::path::PathBuf;
use std::process::ExitCode;

use signscanner::image::{Abi, Image, View};
use signscanner::locate;
use signscanner::locate::Location;

struct Args {
    path: PathBuf,
    json: bool,
    quiet: bool,
    typeinfo: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut path: Option<PathBuf> = None;
    let mut json = false;
    let mut quiet = false;
    let mut typeinfo: Option<String> = None;

    while let Some(a) = args.next() {
        match a.as_str() {
            "--json" => json = true,
            "--quiet" | "-q" => quiet = true,
            "--typeinfo" => {
                typeinfo = Some(
                    args.next()
                        .ok_or_else(|| "--typeinfo needs a value".to_string())?,
                );
            }
            "-h" | "--help" => {
                print_help();
                std::process::exit(0);
            }
            other if other.starts_with("--") => {
                return Err(format!("unknown flag {other}"));
            }
            other => {
                if path.is_some() {
                    return Err(format!("unexpected extra argument {other}"));
                }
                path = Some(PathBuf::from(other));
            }
        }
    }

    let path = path.ok_or_else(|| "missing <wrapper.node> path".to_string())?;
    Ok(Args { path, json, quiet, typeinfo })
}

fn print_help() {
    println!("SignScanner — locate the QQ wrapper.node sign function (stable RTTI anchors)");
    println!();
    println!("USAGE:");
    println!("  SignScanner <wrapper.node> [--json] [--quiet] [--typeinfo NAME]");
    println!();
    println!("Itanium: RTTI name -> typeinfo -> vtable -> MSFSign -> sign core");
    println!("MSVC:    type descriptor -> COL -> vtable -> MSFSign -> sign core");
}

fn anchor_for(abi: Abi) -> &'static str {
    match abi {
        Abi::Itanium => locate::TYPEINFO_NAME_ITANIUM,
        Abi::MsVc => locate::TYPEINFO_NAME_MSVC,
    }
}

fn report_text(view: &View, loc: &Location, index: usize, total: usize, quiet: bool) {
    let base = view.image_base();
    if total > 1 {
        println!("[slice {}/{}] {}", index + 1, total, view.describe());
    }
    println!("[anchor] RTTI name        {}", loc.typeinfo_name);
    println!("[anchor] typeinfo         @ RVA 0x{:x}", loc.typeinfo_addr - base);
    println!(
        "[anchor] vtable           @ RVA 0x{:x}  ({} code slots)",
        loc.vtable_addr - base,
        loc.vtable_slots
    );
    println!(
        "[chain ] MSFSign callback  RVA 0x{:x}  ({} direct calls)",
        loc.callback_addr - base,
        loc.callback_calls
    );
    println!(
        "[chain ] sign core         RVA 0x{:x}  (writes out +0xFF/+0x1FF/+0x2FF)",
        loc.sign_fn_addr - base
    );
    if let Some(off) = loc.file_offset(view) {
        println!("        file offset       0x{off:x}");
    }
    println!();
    println!("=> sign function RVA: 0x{:x}", loc.sign_fn_addr - base);
    if quiet {
        // still print the closed form above; nothing extra
    }
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

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("try --help");
            return ExitCode::from(2);
        }
    };

    let image = match Image::open(&args.path) {
        Ok(i) => i,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(1);
        }
    };

    if image.slices.is_empty() {
        eprintln!(
            "error: unrecognised container {} (expected ELF, PE or Mach-O)",
            args.path.display()
        );
        return ExitCode::from(1);
    }

    let views = image.views();
    let total = views.len();
    let mut json_items: Vec<String> = Vec::new();
    let mut failures = 0usize;

    if !args.json {
        println!("SignScanner — QQ wrapper.node sign-function locator");
        println!();
        println!("file        {}", image.path);
        println!("format      {}", image.format_name());
        println!("slices      {total}");
        println!();
    }

    for (i, view) in views.iter().enumerate() {
        let name = args
            .typeinfo
            .clone()
            .unwrap_or_else(|| anchor_for(view.abi()).to_string());
        match locate::locate(view, &name) {
            Ok(loc) => {
                if args.json {
                    let base = view.image_base();
                    let off = loc
                        .file_offset(view)
                        .map(|o| format!("\"0x{o:x}\""))
                        .unwrap_or_else(|| "null".into());
                    json_items.push(format!(
                        "{{\"format\":\"{}\",\"abi\":\"{}\",\"arch\":\"{}\",\
                         \"typeinfo_name\":\"{}\",\"typeinfo\":\"0x{:x}\",\
                         \"vtable\":\"0x{:x}\",\"callback\":\"0x{:x}\",\
                         \"sign_function\":\"0x{:x}\",\
                         \"sign_function_file_offset\":{off},\"vtable_slots\":{}}}",
                        json_escape(&view.describe()),
                        view.abi().name(),
                        view.arch().name(),
                        json_escape(&loc.typeinfo_name),
                        loc.typeinfo_addr - base,
                        loc.vtable_addr - base,
                        loc.callback_addr - base,
                        loc.sign_fn_addr - base,
                        loc.vtable_slots,
                    ));
                } else {
                    report_text(view, &loc, i, total, args.quiet);
                    if i + 1 < total {
                        println!();
                    }
                }
            }
            Err(e) => {
                failures += 1;
                if args.json {
                    json_items.push(format!(
                        "{{\"format\":\"{}\",\"arch\":\"{}\",\"error\":\"{}\"}}",
                        json_escape(&view.describe()),
                        view.arch().name(),
                        json_escape(&e),
                    ));
                } else {
                    eprintln!("[slice {}/{}] {}: error: {e}", i + 1, total, view.describe());
                }
            }
        }
    }

    if args.json {
        println!("[{}]", json_items.join(","));
    }

    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
