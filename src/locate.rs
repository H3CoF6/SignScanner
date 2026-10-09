//! Locate the QQ sign function using stable, name-anchored structure rather
//! than byte signatures.
//!
//! Two C++ ABIs appear across the platforms QQ ships:
//!
//! **Itanium** (Linux, macOS) - one `typeinfo` object per class:
//! ```text
//! RTTI name "N2nt8internal23MSFSecuritySignCallbackE"
//!   -> typeinfo        (the site storing &name lives at typeinfo + 8)
//!   -> vtable          (the site storing &typeinfo lives at vtable - 8)
//!   -> virtual fns     (vtable slots are RELATIVE relocations into .text)
//!   -> MSFSign         (the vtable slot that calls the sign core)
//!   -> sign function   (the callee that writes the caller's result buffer)
//! ```
//!
//! **MSVC** (Windows) - the type descriptor is not pointed at by a relocation,
//! so the chain starts one step differently:
//! ```text
//! type descriptor ".?AVMSFSecuritySignCallback@internal@nt@@"
//!   -> _RTTICompleteObjectLocator (its pTypeDescriptor RVA == td_rva)
//!   -> vtable          (the site storing &COL is vtable - 8)
//!   -> ... same as above
//! ```
//!
//! Every step is an invariant of the C++ object model, so it survives address
//! changes between QQ versions; and no step matches bytes other than the RTTI
//! name itself.

use crate::aarch64;
use crate::decode::BufferHits;
use crate::image::{Abi, Arch, Format, View};
use crate::x86;

/// Itanium-ABI RTTI name (Linux, macOS).
pub const TYPEINFO_NAME_ITANIUM: &str = "N2nt8internal23MSFSecuritySignCallbackE";
/// MSVC-ABI type descriptor name (Windows).
pub const TYPEINFO_NAME_MSVC: &str = ".?AVMSFSecuritySignCallback@internal@nt@@";
/// Back-compat default.
pub const TYPEINFO_NAME: &str = TYPEINFO_NAME_ITANIUM;

const MAX_FUNCTION_SCAN: u64 = 0x2000;

#[derive(Clone, Debug)]
pub struct Location {
    pub typeinfo_name: String,
    /// Itanium `typeinfo` address, or MSVC type-descriptor address.
    pub typeinfo_addr: u64,
    pub vtable_addr: u64,
    /// `MSFSecuritySignCallback::MSFSign` (the vtable slot driving the sign).
    pub callback_addr: u64,
    /// The sign core the reference projects call: `f(cmd, src, len, seq, out)`.
    pub sign_fn_addr: u64,
    pub vtable_slots: usize,
    pub callback_calls: usize,
}

impl Location {
    pub fn file_offset(&self, view: &View) -> Option<usize> {
        view.addr_to_offset(self.sign_fn_addr)
    }
}

fn read_region<'v>(view: &'v View<'_>, start: u64, end: u64) -> &'v [u8] {
    let end = end.max(start);
    match view.read(start, (end - start) as usize) {
        Some(b) => b,
        None => {
            // Clamp to whatever the mapping still allows.
            let mut hi = end;
            while hi > start && view.read(start, (hi - start) as usize).is_none() {
                hi = start + (hi - start) / 2;
            }
            view.read(start, (hi - start) as usize).unwrap_or(&[])
        }
    }
}

fn direct_calls(view: &View, addr: u64, end: u64) -> Vec<u64> {
    let bytes = read_region(view, addr, end);
    match view.arch() {
        Arch::X86_64 => x86::direct_calls(bytes, addr),
        Arch::AArch64 => aarch64::direct_calls(bytes, addr),
        _ => Vec::new(),
    }
}

/// Collect the virtual functions of the vtable at `vtable_addr`.
fn vtable_functions(view: &View, vtable_addr: u64) -> Vec<u64> {
    let mut funcs = Vec::new();
    for k in 0..16u64 {
        let Some(ptr) = view.resolve_ptr(vtable_addr + k * 8) else {
            break;
        };
        if ptr == 0 {
            continue;
        }
        if view.is_exec(ptr) {
            funcs.push(ptr);
        } else {
            // First resolved non-code pointer marks the end of the vtable.
            break;
        }
    }
    funcs
}

struct VtableHit {
    callback: u64,
    sign_fn: u64,
    calls: usize,
    slots: usize,
}

/// How many contiguous `.pdata` partitions may be folded into one logical
/// function before we stop (guards against pathological metadata).
const MAX_PDATA_MERGE: usize = 64;

/// Upper bound for forward decoding when a container carries no function
/// boundary metadata (ELF). Big enough for the largest sign core seen
/// (~82 KB on Windows x64) while still cheap to disassemble once.
const MAX_TERMINATOR_SCAN: u64 = 0x40000;

/// True when the bytes immediately before `end` mark a real function boundary:
/// a terminator instruction or alignment padding. QQ's PE `.pdata` sometimes
/// splits one function at ordinary instruction boundaries (no prologue, no
/// `CHAININFO`), so such a split is only genuine when the previous code cannot
/// fall through into it.
fn ends_function(view: &View, end: u64) -> bool {
    if end < 2 {
        return true;
    }
    let Some(b0) = view.read(end - 1, 1).and_then(|s| s.first().copied()) else {
        return true;
    };
    // ret / retf / ret imm / int3 / jmp: the previous code cannot fall through
    // into `end` on any of these, so the split is genuine. This only feeds the
    // PE `.pdata` fold now; Mach-O and ELF use exact bounds (see below).
    if matches!(b0, 0xC2 | 0xC3 | 0xCA | 0xCB | 0xCC | 0xE9 | 0xEB) {
        return true;
    }
    // Two or more consecutive zero bytes are alignment padding.
    b0 == 0x00
        && matches!(
            view.read(end - 2, 1).and_then(|s| s.first().copied()),
            Some(0x00)
        )
}

/// Forward-decode from `addr` until the first terminator, returning the
/// exclusive end of that instruction run. Used for containers without boundary
/// metadata (ELF); falls back to `MAX_TERMINATOR_SCAN` if no terminator is seen.
fn decode_to_terminator(view: &View, addr: u64) -> u64 {
    let end = addr.saturating_add(MAX_TERMINATOR_SCAN);
    let bytes = read_region(view, addr, end);
    match view.arch() {
        Arch::X86_64 => x86::function_end(bytes, addr),
        Arch::AArch64 => aarch64::function_end(bytes, addr),
        _ => addr.saturating_add(MAX_FUNCTION_SCAN),
    }
}

/// The authoritative end of the function that *starts* at `addr`, chosen by
/// container:
///
/// * PE - `.pdata`, folding contiguous split entries (QQ emits several).
/// * Mach-O - `LC_FUNCTION_STARTS` is exact; the next start is the end.
/// * ELF - no metadata, so decode forward to the first terminator.
///
/// `addr` is always a real function entry here, so none of these may silently
/// extend into a neighbouring function: that is exactly the bug that used to
/// make the locator return an unrelated helper.
fn function_end(view: &View, addr: u64) -> u64 {
    match view.format() {
        Format::Pe => {
            let mut end = view.function_end(addr).unwrap_or(addr + MAX_FUNCTION_SCAN);
            for _ in 0..MAX_PDATA_MERGE {
                if ends_function(view, end) {
                    break;
                }
                match view.function_end(end) {
                    Some(next) if next > end => end = next,
                    _ => break,
                }
            }
            end
        }
        Format::MachO => view
            .function_end(addr)
            .unwrap_or_else(|| decode_to_terminator(view, addr)),
        Format::Elf => decode_to_terminator(view, addr),
    }
}

fn scan_vtable(view: &View, vtable_addr: u64) -> Option<VtableHit> {
    let funcs = vtable_functions(view, vtable_addr);
    if funcs.is_empty() {
        return None;
    }
    for &f in &funcs {
        let calls = direct_calls(view, f, function_end(view, f));
        for &callee in &calls {
            if !view.is_exec(callee) {
                continue;
            }
            // The sign core can be a large function (Windows x64's is ~82 KB),
            // so scan all the way to its real end and skip the decoder for
            // candidates that cannot contain the three result offsets.
            let end = function_end(view, callee);
            let bytes = read_region(view, callee, end);
            if view.arch() == Arch::X86_64 && !x86::maybe_writes_result_buffer(bytes) {
                continue;
            }
            let hits = match view.arch() {
                Arch::X86_64 => x86::buffer_hits(bytes, callee),
                Arch::AArch64 => aarch64::buffer_hits(bytes, callee),
                _ => BufferHits::default(),
            };
            if hits.all() {
                return Some(VtableHit {
                    callback: f,
                    sign_fn: callee,
                    calls: calls.len(),
                    slots: funcs.len(),
                });
            }
        }
    }
    None
}

pub fn locate(view: &View, name: &str) -> Result<Location, String> {
    match view.arch() {
        Arch::X86_64 | Arch::AArch64 => {}
        other => {
            return Err(format!(
                "the sign core lives in {} code; this build decodes x86-64 and aarch64 only",
                other.name()
            ));
        }
    }
    match view.abi() {
        Abi::Itanium => locate_itanium(view, name),
        Abi::MsVc => locate_msvc(view, name),
    }
}

fn locate_itanium(view: &View, name: &str) -> Result<Location, String> {
    let occurrences = view.find_all(name.as_bytes());
    if occurrences.is_empty() {
        return Err(format!("RTTI typeinfo name {name:?} not found"));
    }

    let mut diag: Vec<String> = Vec::new();
    for off in occurrences {
        let Some(name_addr) = view.offset_to_addr(off) else {
            continue;
        };
        for site in view.sites_pointing_to(name_addr) {
            if site < 8 {
                continue;
            }
            let typeinfo_addr = site - 8;
            for vsite in view.sites_pointing_to(typeinfo_addr) {
                let vtable_addr = vsite + 8;
                if let Some(h) = scan_vtable(view, vtable_addr) {
                    return Ok(Location {
                        typeinfo_name: name.to_string(),
                        typeinfo_addr,
                        vtable_addr,
                        callback_addr: h.callback,
                        sign_fn_addr: h.sign_fn,
                        vtable_slots: h.slots,
                        callback_calls: h.calls,
                    });
                }
                diag.push(format!(
                    "vtable 0x{vtable_addr:x}: no sign core among callees"
                ));
            }
        }
    }

    if diag.is_empty() {
        Err("found the typeinfo name but could not resolve a vtable from it".into())
    } else {
        Err(format!("no sign function found ({})", diag.join("; ")))
    }
}

fn locate_msvc(view: &View, name: &str) -> Result<Location, String> {
    let occurrences = view.find_all(name.as_bytes());
    if occurrences.is_empty() {
        return Err(format!("RTTI type descriptor {name:?} not found"));
    }
    let base = view.image_base();

    let mut diag: Vec<String> = Vec::new();
    for off in occurrences {
        let Some(name_addr) = view.offset_to_addr(off) else {
            continue;
        };
        if name_addr < 16 || name_addr < base {
            continue;
        }
        // _TypeDescriptor = { pVFTable, spare, name[] }; name lives at +16.
        let td = name_addr - 16;
        let td_rva = td - base;
        if td_rva == 0 || td_rva > u32::MAX as u64 {
            continue;
        }
        // The COL stores pTypeDescriptor as an RVA, so that is what we search
        // for; validate each candidate against the COL signature and pSelf.
        for field in view.find_u32_le(td_rva as u32) {
            if field < 12 || field < base {
                continue;
            }
            let col = field - 12;
            let Some(sig) = view.read_u32(col) else { continue };
            if sig > 1 {
                continue;
            }
            let Some(pself) = view.read_u32(col + 20) else {
                continue;
            };
            if pself as u64 != col - base {
                continue;
            }
            for vsite in view.sites_pointing_to(col) {
                let vtable_addr = vsite + 8;
                if let Some(h) = scan_vtable(view, vtable_addr) {
                    return Ok(Location {
                        typeinfo_name: name.to_string(),
                        typeinfo_addr: td,
                        vtable_addr,
                        callback_addr: h.callback,
                        sign_fn_addr: h.sign_fn,
                        vtable_slots: h.slots,
                        callback_calls: h.calls,
                    });
                }
                diag.push(format!("vtable 0x{vtable_addr:x}: no sign core among callees"));
            }
        }
    }

    if diag.is_empty() {
        Err("found the type descriptor but could not resolve its COL/vtable".into())
    } else {
        Err(format!("no sign function found ({})", diag.join("; ")))
    }
}
