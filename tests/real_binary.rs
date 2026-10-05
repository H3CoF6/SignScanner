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
