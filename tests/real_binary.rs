//! Integration checks against real QQ `wrapper.node` builds.
//!
//! Each test is skipped when its binary is not present, so the suite still runs
//! on a plain checkout. Expected values are the ones this scanner finds for the
//! builds used during development and were cross-checked against
//! `llvm-objdump` (every located core stores the result lengths at
//! `+0xFF`/`+0x1FF`/`+0x2FF`).

use std::path::PathBuf;

use signscanner::image::{Arch, Image};
use signscanner::locate;

fn binary(env: &str, default: &str) -> Option<PathBuf> {
    let candidates = [std::env::var(env).ok(), Some(default.to_string())];
    for c in candidates.into_iter().flatten() {
        let p = PathBuf::from(&c);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

#[test]
fn linux_x64() {
    let Some(path) = binary("QQ_WRAPPER_NODE", "/opt/QQ/resources/app/wrapper.node") else {
        eprintln!("skipping: no Linux x64 wrapper.node");
        return;
    };
    let image = Image::open(&path).expect("open");
    assert_eq!(image.slices.len(), 1);
    let view = &image.views()[0];
    assert_eq!(view.arch(), Arch::X86_64);
    let loc = locate::locate(view, locate::TYPEINFO_NAME_ITANIUM).expect("locate");
    assert_eq!(loc.typeinfo_addr, 0x8e1c838, "typeinfo");
    assert_eq!(loc.vtable_addr, 0x8e1c810, "vtable");
    assert_eq!(loc.callback_addr, 0x34ee370, "MSFSign");
    assert_eq!(loc.sign_fn_addr, 0x67f28d4, "sign core");
    assert!(view.is_exec(loc.sign_fn_addr));
}

#[test]
fn linux_arm64() {
    let Some(path) = binary(
        "QQ_ARM64_WRAPPER",
        "/tmp/ntqq_extract/rootarm/opt/QQ/resources/app/wrapper.node",
    ) else {
        eprintln!("skipping: no Linux arm64 wrapper.node");
        return;
    };
    let image = Image::open(&path).expect("open");
    let view = &image.views()[0];
    assert_eq!(view.arch(), Arch::AArch64);
    let loc = locate::locate(view, locate::TYPEINFO_NAME_ITANIUM).expect("locate");
    assert_eq!(loc.typeinfo_addr, 0x892a0b0);
    assert_eq!(loc.vtable_addr, 0x892a088);
    assert_eq!(loc.callback_addr, 0x13a2210);
    assert_eq!(loc.sign_fn_addr, 0x43d07dc);
    assert!(view.is_exec(loc.sign_fn_addr));
}

#[test]
fn windows_x64() {
    let Some(path) = binary("QQ_WIN_X64_WRAPPER", "/tmp/ntqq_extract/win64/wrapper.node") else {
        eprintln!("skipping: no Windows x64 wrapper.node");
        return;
    };
    let image = Image::open(&path).expect("open");
    let view = &image.views()[0];
    assert_eq!(view.arch(), Arch::X86_64);
    let loc = locate::locate(view, locate::TYPEINFO_NAME_MSVC).expect("locate");
    assert_eq!(loc.typeinfo_addr, 0x185fcc560);
    assert_eq!(loc.vtable_addr, 0x1840ffce8);
    assert_eq!(loc.callback_addr, 0x18074d4dc);
    assert_eq!(loc.sign_fn_addr, 0x180beea20);
    assert!(view.is_exec(loc.sign_fn_addr));
}

#[test]
fn windows_arm64() {
    let Some(path) = binary("QQ_WIN_ARM64_WRAPPER", "/tmp/ntqq_extract/winarm/wrapper.node") else {
        eprintln!("skipping: no Windows arm64 wrapper.node");
        return;
    };
    let image = Image::open(&path).expect("open");
    let view = &image.views()[0];
    assert_eq!(view.arch(), Arch::AArch64);
    let loc = locate::locate(view, locate::TYPEINFO_NAME_MSVC).expect("locate");
    assert_eq!(loc.typeinfo_addr, 0x185bd5440);
    assert_eq!(loc.vtable_addr, 0x183ef9e68);
    assert_eq!(loc.callback_addr, 0x1807310a4);
    assert_eq!(loc.sign_fn_addr, 0x180bcdae8);
    assert!(view.is_exec(loc.sign_fn_addr));
}

#[test]
fn macos_universal() {
    let Some(path) = binary("QQ_MAC_WRAPPER", "/tmp/ntqq_extract/mac/wrapper.node") else {
        eprintln!("skipping: no macOS wrapper.node");
        return;
    };
    let image = Image::open(&path).expect("open");
    assert_eq!(image.slices.len(), 2, "universal binary has two slices");

    let expected: [(Arch, u64, u64, u64, u64); 2] = [
        // x86-64 slice.
        (Arch::X86_64, 0x5b08d98, 0x5b08d60, 0x6df91a, 0x304e2d7),
        // arm64 slice.
        (Arch::AArch64, 0x51039f0, 0x51039b8, 0x68887c, 0x2b30e10),
    ];
    let views = image.views();
    for view in &views {
        let want = expected
            .iter()
            .find(|(a, ..)| *a == view.arch())
            .expect("slice arch");
        let loc = locate::locate(view, locate::TYPEINFO_NAME_ITANIUM).expect("locate");
        assert_eq!((loc.typeinfo_addr, loc.vtable_addr), (want.1, want.2));
        assert_eq!((loc.callback_addr, loc.sign_fn_addr), (want.3, want.4));
        assert!(view.is_exec(loc.sign_fn_addr));
    }
    assert_eq!(views.len(), 2);
}

// 真值回归（默认跳过）。
//
// 把若干已知版本的 `wrapper.node` 放进一个目录，用
// `SIGNSCANNER_FIXTURES=<dir>` 指过去，再运行：
// `cargo test --test real_binary -- --ignored locate_known_fixtures`
//
// 文件名里带上表里的键（如 `7.0.1`、`3.2.32-linux`）就会顺带断言 RVA 精确
// 相等；任何文件都会验证**核心不变量**：命中的签名函数必须在自己真实函数
// 体内写满 `+0xFF/+0x1FF/+0x2FF`。这正是旧实现（跨函数合并 / 固定窗口）会
// 破坏、从而返回一个无关函数的那条性质。
#[test]
#[ignore = "needs real QQ wrapper.node fixtures"]
fn locate_known_fixtures() {
    use signscanner::image::{Arch, Image};
    use signscanner::locate;
    use std::path::PathBuf;

    // 版本键 -> 期望 RVA（真实签名函数入口）。
    const EXPECTED: &[(&str, u64)] = &[
        ("7.0.1.arm64", 0x2aedbf0),
        ("7.0.1", 0x2fffda7),
        ("7.0.0.arm64", 0x2ad1d98),
        ("7.0.0", 0x2f4f60f),
        ("6.9.99", 0x2f0f22f),
        ("3.2.29-linux", 0x5bd3ea1),
        ("3.2.32-linux", 0x65e55d1),
        ("9.9.33-win", 0xba22b0),
    ];

    let dir = match std::env::var("SIGNSCANNER_FIXTURES") {
        Ok(d) => PathBuf::from(d),
        Err(_) => {
            eprintln!("SIGNSCANNER_FIXTURES not set; skipping");
            return;
        }
    };

    let mut checked = 0usize;
    for entry in std::fs::read_dir(&dir).expect("read fixtures dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|s| s.to_str()) != Some("node") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().to_string();

        // 逐个切片定位：universal Mach-O 有两个切片，各自都要满足不变量。
        let img = Image::open(&path).expect("open");
        let want = EXPECTED.iter().find(|(k, _)| name.contains(k)).map(|(_, v)| *v);
        let mut checked_slices = 0usize;
        for view in img.views() {
            let loc = match locate::locate(&view, locate::TYPEINFO_NAME_ITANIUM)
                .or_else(|_| locate::locate(&view, locate::TYPEINFO_NAME_MSVC))
            {
                Ok(l) => l,
                Err(e) => panic!("{name}: locate failed on {}: {e}", view.describe()),
            };

            // 不变量：命中函数在自己边界内写满三个结果偏移。
            let end = view
                .function_end(loc.sign_fn_addr)
                .unwrap_or(loc.sign_fn_addr + 0x40000);
            let bytes = view
                .read(loc.sign_fn_addr, (end - loc.sign_fn_addr) as usize)
                .expect("body bytes");
            let hits = match view.arch() {
                Arch::X86_64 => signscanner::x86::buffer_hits(bytes, loc.sign_fn_addr),
                Arch::AArch64 => signscanner::aarch64::buffer_hits(bytes, loc.sign_fn_addr),
                _ => continue,
            };
            assert!(
                hits.all(),
                "{name} [{}]: located body 0x{:x} (+{:#x}) does not fill all three result offsets: {hits:?}",
                view.describe(),
                loc.sign_fn_addr,
                end - loc.sign_fn_addr
            );
            eprintln!(
                "{name} [{}]: rva=0x{:x} slots={} calls={}",
                view.describe(),
                loc.sign_fn_addr,
                loc.vtable_slots,
                loc.callback_calls
            );

            // 仅在文件名唯一地指向某一个切片版本时断言精确 RVA。
            if let Some(want) = want
                && ((name.contains(".arm64") && view.arch() == Arch::AArch64)
                    || (!name.contains(".arm64") && view.arch() == Arch::X86_64))
            {
                assert_eq!(
                    loc.sign_fn_addr - view.image_base(),
                    want,
                    "{name}: expected rva 0x{want:x}, got 0x{:x}",
                    loc.sign_fn_addr - view.image_base()
                );
            }
            checked_slices += 1;
        }
        assert!(checked_slices > 0, "{name}: no decodable slices?");
        checked += 1;
    }
    assert!(checked > 0, "no *.node fixtures found in {}", dir.display());
}
