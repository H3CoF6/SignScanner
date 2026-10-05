//! Minimal ELF64 parser (little-endian) plus the pieces we need for anchor
//! resolution: sections, program headers and dynamic relocations.
//!
//! We deliberately avoid external ELF crates so the scanner stays pure-Rust
//! and fully in control of how relocations (the static equivalent of RTTI
//! pointers) are interpreted.

use crate::reloc::Relocs;

pub const PT_LOAD: u32 = 1;
pub const SHT_RELA: u32 = 4;
pub const SHF_ALLOC: u64 = 0x2;
pub const SHF_EXECINSTR: u64 = 0x4;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_AARCH64_RELATIVE: u32 = 1027;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub sh_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub entsize: u64,
}

#[derive(Clone, Copy, Debug)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
}

/// `p_flags` bit: segment is executable.
pub const PF_X: u32 = 0x1;

pub struct Elf {
    pub machine: u16,
    pub sections: Vec<Section>,
    pub phdrs: Vec<ProgramHeader>,
    pub relocs: Relocs,
}

pub const EM_X86_64: u16 = 62;
pub const EM_AARCH64: u16 = 183;
pub const EM_386: u16 = 3;
pub const EM_ARM: u16 = 40;

fn u16at(d: &[u8], o: usize) -> u64 {
    u16::from_le_bytes([d[o], d[o + 1]]) as u64
}
fn u32at(d: &[u8], o: usize) -> u64 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]) as u64
}
fn u64at(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[o..o + 8]);
    u64::from_le_bytes(b)
}

pub fn parse(data: &[u8]) -> Result<Elf, String> {
    if data.len() < 64 || &data[0..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    if data[4] != 2 {
        return Err("32-bit ELF not supported yet".into());
    }
    if data[5] != 1 {
        return Err("big-endian ELF not supported yet".into());
    }

    let e_shoff = u64at(data, 0x28);
    let e_shentsize = u16at(data, 0x3a) as usize;
    let e_shnum = u16at(data, 0x3c) as usize;
    let e_shstrndx = u16at(data, 0x3e) as usize;
    let e_machine = u16at(data, 0x12) as u16;
    let e_phoff = u64at(data, 0x20);
    let e_phentsize = u16at(data, 0x36) as usize;
    let e_phnum = u16at(data, 0x38) as usize;

    // Raw (name_offset, section) pairs first; names resolved after we know the
    // string table.
    let mut raw: Vec<(usize, Section)> = Vec::new();
    let mut shstr_off = 0u64;
    if e_shoff != 0 && e_shnum != 0 && e_shentsize != 0 {
        for i in 0..e_shnum {
            let base = (e_shoff as usize) + i * e_shentsize;
            if base + 64 > data.len() {
                break;
            }
            let name_off = u32at(data, base) as usize;
            let s = Section {
                name: String::new(),
                sh_type: u32at(data, base + 4) as u32,
                flags: u64at(data, base + 8),
                addr: u64at(data, base + 0x10),
                offset: u64at(data, base + 0x18),
                size: u64at(data, base + 0x20),
                entsize: u64at(data, base + 0x38),
            };
            if i == e_shstrndx {
                shstr_off = s.offset;
            }
            raw.push((name_off, s));
        }
    }

    let mut sections = Vec::with_capacity(raw.len());
    for (name_off, mut s) in raw {
        if shstr_off != 0 {
            let start = shstr_off as usize + name_off;
            if start < data.len() {
                let end = data[start..]
                    .iter()
                    .position(|&c| c == 0)
                    .map(|p| start + p)
                    .unwrap_or(start);
                s.name = String::from_utf8_lossy(&data[start..end]).into_owned();
            }
        }
        sections.push(s);
    }

    let mut phdrs = Vec::new();
    if e_phoff != 0 && e_phnum != 0 && e_phentsize != 0 {
        for i in 0..e_phnum {
            let base = (e_phoff as usize) + i * e_phentsize;
            if base + 56 > data.len() {
                break;
            }
            phdrs.push(ProgramHeader {
                p_type: u32at(data, base) as u32,
                flags: u32at(data, base + 4) as u32,
                offset: u64at(data, base + 8),
                vaddr: u64at(data, base + 0x10),
                filesz: u64at(data, base + 0x20),
            });
        }
    }

    let mut relocs = Relocs::default();
    for s in &sections {
        if s.sh_type != SHT_RELA {
            continue;
        }
        let entsize = if s.entsize != 0 { s.entsize as usize } else { 24 };
        if entsize < 24 {
            continue;
        }
        let count = s.size as usize / entsize;
        for i in 0..count {
            let base = s.offset as usize + i * entsize;
            if base + 24 > data.len() {
                break;
            }
            let r_offset = u64at(data, base);
            let r_info = u64at(data, base + 8);
            let r_addend = u64at(data, base + 0x10);
            let r_type = (r_info & 0xffff_ffff) as u32;
            if r_type == R_X86_64_RELATIVE || r_type == R_AARCH64_RELATIVE {
                relocs.add(r_offset, r_addend);
            }
        }
    }
    relocs.finish();

    Ok(Elf { machine: e_machine, sections, phdrs, relocs })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_elf() {
        assert!(parse(b"not an elf file at all").is_err());
    }
}
