//! Minimal Mach-O parser (64-bit, little-endian) for thin and fat files.
//!
//! Two pieces of dyld metadata matter here:
//!
//! * the `LC_DYLD_INFO[_ONLY]` **rebase** opcode stream, which describes every
//!   site holding a rebased pointer - the Mach-O analogue of ELF relocations;
//! * `LC_FUNCTION_STARTS`, a run of ULEB128 deltas giving every function start,
//!   which lets the locator bound a callee instead of guessing a byte window.
//!
//! Sections are parsed so `is_exec` reflects real code (`__text`, `__stubs`,
//! ...) rather than the whole `__TEXT` segment, whose page 0 also holds the
//! Mach-O header and load commands.

use crate::reloc::Relocs;

pub const MH_MAGIC_64: u32 = 0xfeedfacf;
pub const FAT_MAGIC: u32 = 0xcafebabe;
pub const FAT_MAGIC_64: u32 = 0xcafebabf;
pub const CPU_X86_64: u32 = 0x0100_0007;
pub const CPU_ARM64: u32 = 0x0100_000c;

pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
pub const LC_FUNCTION_STARTS: u32 = 0x26;

pub const VM_PROT_EXECUTE: u32 = 0x4;

// Section attribute flags (from <mach-o/loader.h>).
const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;
const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

// Rebase opcodes (from <mach-o/loader.h>).
const REBASE_OPCODE_MASK: u8 = 0xf0;
const REBASE_IMMEDIATE_MASK: u8 = 0x0f;
const REBASE_OPCODE_DONE: u8 = 0x00;
const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

const REBASE_TYPE_POINTER: u32 = 1;

#[derive(Clone, Debug)]
pub struct Segment {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub initprot: u32,
}

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub addr: u64,
    pub size: u64,
    pub exec: bool,
}

pub struct MachO {
    pub cputype: u32,
    pub segments: Vec<Segment>,
    pub sections: Vec<Section>,
    /// Sorted function starts from `LC_FUNCTION_STARTS`.
    pub func_starts: Vec<u64>,
    pub relocs: Relocs,
}

impl MachO {
    /// In-slice file offset for a vm address.
    pub fn vm_to_offset(&self, vm: u64) -> Option<usize> {
        for s in &self.segments {
            if vm >= s.vmaddr && vm - s.vmaddr < s.vmsize {
                let delta = vm - s.vmaddr;
                if delta < s.filesize {
                    return Some((s.fileoff + delta) as usize);
                }
            }
        }
        None
    }

    /// Whether `addr` lies in a section belonging to an executable segment.
    pub fn is_exec(&self, addr: u64) -> bool {
        self.sections
            .iter()
            .any(|s| s.exec && addr >= s.addr && addr < s.addr + s.size)
    }

    /// End of the function starting at `addr` (next known start), if known.
    pub fn function_end(&self, addr: u64) -> Option<u64> {
        let i = self.func_starts.binary_search(&addr).ok()?;
        self.func_starts.get(i + 1).copied()
    }
}

fn be_u32(d: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn le_u32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn le_u64(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[o..o + 8]);
    u64::from_le_bytes(b)
}

pub fn is_thin(data: &[u8]) -> bool {
    data.len() >= 4 && le_u32(data, 0) == MH_MAGIC_64
}

pub fn is_fat(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }
    let m = be_u32(data, 0);
    m == FAT_MAGIC || m == FAT_MAGIC_64
}

/// `(cputype, file offset, size)` for each architecture slice of a fat file.
pub fn fat_archs(data: &[u8]) -> Result<Vec<(u32, usize, usize)>, String> {
    if !is_fat(data) {
        return Err("not a fat Mach-O".into());
    }
    let magic = be_u32(data, 0);
    let nfat = be_u32(data, 4) as usize;
    let entry = if magic == FAT_MAGIC_64 { 32 } else { 20 };
    let mut out = Vec::with_capacity(nfat);
    for i in 0..nfat {
        let b = 8 + i * entry;
        if b + entry > data.len() {
            break;
        }
        let cputype = be_u32(data, b);
        let (off, size) = if entry == 32 {
            (le_u64(data, b + 8), le_u64(data, b + 16))
        } else {
            (be_u32(data, b + 8) as u64, be_u32(data, b + 12) as u64)
        };
        out.push((cputype, off as usize, size as usize));
    }
    Ok(out)
}

fn uleb(d: &[u8], mut i: usize) -> (u64, usize) {
    let mut r = 0u64;
    let mut sh = 0u32;
    loop {
        if i >= d.len() {
            return (r, i);
        }
        let b = d[i];
        i += 1;
        r |= ((b & 0x7f) as u64) << sh;
        sh += 7;
        if b & 0x80 == 0 {
            break;
        }
    }
    (r, i)
}

pub fn parse_thin(data: &[u8]) -> Result<MachO, String> {
    if !is_thin(data) {
        return Err("not a 64-bit little-endian Mach-O".into());
    }
    let ncmds = le_u32(data, 16) as usize;
    let mut cputype = le_u32(data, 4);
    let mut segments: Vec<Segment> = Vec::new();
    let mut sections: Vec<Section> = Vec::new();
    let mut func_range: Option<(usize, usize)> = None;
    let mut rebase: Option<(usize, usize)> = None;

    let mut p = 32usize;
    for _ in 0..ncmds {
        if p + 8 > data.len() {
            break;
        }
        let cmd = le_u32(data, p);
        let cmdsize = le_u32(data, p + 4) as usize;
        if cmdsize == 0 {
            break;
        }
        match cmd {
            LC_SEGMENT_64 if p + 72 <= data.len() => {
                let name = data[p + 8..p + 24]
                    .iter()
                    .take_while(|&&c| c != 0)
                    .map(|&c| c as char)
                    .collect();
                let initprot = le_u32(data, p + 60);
                let nsects = le_u32(data, p + 64) as usize;
                let this = segments.len();
                segments.push(Segment {
                    name,
                    vmaddr: le_u64(data, p + 24),
                    vmsize: le_u64(data, p + 32),
                    fileoff: le_u64(data, p + 40),
                    filesize: le_u64(data, p + 48),
                    initprot,
                });
                let _ = this;
                let sec_base = p + 72;
                // Only instruction-bearing sections count as code; __TEXT also
                // contains the Mach-O header page and read-only data.
                let seg_exec = initprot & VM_PROT_EXECUTE != 0;
                for k in 0..nsects {
                    let b = sec_base + k * 80;
                    if b + 80 > data.len() {
                        break;
                    }
                    let sname: String = data[b..b + 16]
                        .iter()
                        .take_while(|&&c| c != 0)
                        .map(|&c| c as char)
                        .collect();
                    let flags = le_u32(data, b + 64);
                    let is_code =
                        flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0;
                    sections.push(Section {
                        name: sname,
                        addr: le_u64(data, b + 32),
                        size: le_u64(data, b + 40),
                        exec: seg_exec && is_code,
                    });
                }
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY if p + 48 <= data.len() => {
                let ro = le_u32(data, p + 8) as usize;
                let rs = le_u32(data, p + 12) as usize;
                if rs != 0 {
                    rebase = Some((ro, rs));
                }
            }
            LC_FUNCTION_STARTS if p + 16 <= data.len() => {
                let ro = le_u32(data, p + 8) as usize;
                let rs = le_u32(data, p + 12) as usize;
                if rs != 0 {
                    func_range = Some((ro, rs));
                }
            }
            _ => {}
        }
        p += cmdsize;
    }

    cputype |= 0; // keep the field explicit

    let macho = MachO {
        cputype,
        segments,
        sections,
        func_starts: Vec::new(),
        relocs: Relocs::default(),
    };
    let func_starts = parse_function_starts(data, func_range);
    let relocs = parse_rebase(data, &macho, rebase);
    Ok(MachO {
        cputype,
        segments: macho.segments,
        sections: macho.sections,
        func_starts,
        relocs,
    })
}

/// `LC_FUNCTION_STARTS` is a ULEB128 delta chain starting at the first
/// `__TEXT` vm address (normally 0).
fn parse_function_starts(data: &[u8], range: Option<(usize, usize)>) -> Vec<u64> {
    let Some((off, size)) = range else {
        return Vec::new();
    };
    let end = (off + size).min(data.len());
    let mut starts = Vec::new();
    let mut addr = 0u64;
    let mut i = off;
    while i < end {
        let (delta, ni) = uleb(data, i);
        i = ni;
        if delta == 0 {
            break;
        }
        addr += delta;
        starts.push(addr);
    }
    starts.sort_unstable();
    starts
}

fn parse_rebase(data: &[u8], macho: &MachO, range: Option<(usize, usize)>) -> Relocs {
    let mut relocs = Relocs::default();
    let Some((ro, rsz)) = range else {
        return relocs;
    };
    let end = (ro + rsz).min(data.len());
    let mut i = ro;
    let mut segi: i64 = -1;
    let mut segoff: u64 = 0;
    let mut typ: u32 = 0;
    let mut sites: Vec<(usize, u64)> = Vec::new();

    while i < end {
        let byte = data[i];
        i += 1;
        let op = byte & REBASE_OPCODE_MASK;
        let imm = byte & REBASE_IMMEDIATE_MASK;
        match op {
            REBASE_OPCODE_DONE => break,
            REBASE_OPCODE_SET_TYPE_IMM => typ = imm as u32,
            REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                segi = imm as i64;
                let (v, ni) = uleb(data, i);
                i = ni;
                segoff = v;
            }
            REBASE_OPCODE_ADD_ADDR_ULEB => {
                let (v, ni) = uleb(data, i);
                i = ni;
                segoff += v;
            }
            REBASE_OPCODE_ADD_ADDR_IMM_SCALED => segoff += imm as u64 * 8,
            REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                for _ in 0..imm {
                    push_site(&mut sites, segi, segoff, typ);
                    segoff += 8;
                }
            }
            REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                let (count, ni) = uleb(data, i);
                i = ni;
                for _ in 0..count {
                    push_site(&mut sites, segi, segoff, typ);
                    segoff += 8;
                }
            }
            REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                push_site(&mut sites, segi, segoff, typ);
                segoff += 8;
                let (v, ni) = uleb(data, i);
                i = ni;
                segoff += v;
            }
            REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                let (count, ni) = uleb(data, i);
                i = ni;
                let (skip, ni2) = uleb(data, i);
                i = ni2;
                for _ in 0..count {
                    push_site(&mut sites, segi, segoff, typ);
                    segoff += 8 + skip;
                }
            }
            _ => break,
        }
    }

    for (si, off) in sites {
        let Some(seg) = macho.segments.get(si) else {
            continue;
        };
        let site = seg.vmaddr + off;
        if let Some(o) = macho.vm_to_offset(site)
            && o + 8 <= data.len() {
                let target = le_u64(data, o);
                relocs.add(site, target);
            }
    }
    relocs.finish();
    relocs
}

fn push_site(sites: &mut Vec<(usize, u64)>, segi: i64, segoff: u64, typ: u32) {
    if typ == REBASE_TYPE_POINTER && segi >= 0 {
        sites.push((segi as usize, segoff));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_thin_magic() {
        // MH_MAGIC_64 little-endian on disk.
        assert!(is_thin(&[0xcf, 0xfa, 0xed, 0xfe]));
        assert!(!is_thin(b"not macho"));
    }

    #[test]
    fn reads_uleb() {
        assert_eq!(uleb(&[0x7f], 0), (0x7f, 1));
        assert_eq!(uleb(&[0x80, 0x01], 0), (0x80, 2));
        assert_eq!(uleb(&[0xff, 0x01], 0), (0xff, 2));
    }

    #[test]
    fn function_starts_are_cumulative_deltas() {
        // deltas 0x10, 0x20, 0 (terminator) -> starts 0x10, 0x30.
        let data = [0x10, 0x20, 0x00];
        assert_eq!(parse_function_starts(&data, Some((0, 3))), vec![0x10, 0x30]);
    }
}
