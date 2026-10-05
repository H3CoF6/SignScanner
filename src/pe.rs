//! Minimal PE32+ parser plus the base-relocation table, which is the PE
//! equivalent of ELF `RELATIVE` relocations: it tells us every site that holds
//! an absolute pointer (and therefore every site the RTTI anchor walk may need
//! to follow).
//!
//! Addresses are kept in the *native* PE address space (image base + RVA), so
//! the values stored in the image - and hence the `(site, target)` pairs - are
//! directly comparable with `offset_to_addr`/`find_all` results.

use crate::reloc::Relocs;

pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const IMAGE_REL_BASED_HIGHLOW: u16 = 3;
pub const IMAGE_REL_BASED_DIR64: u16 = 10;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: usize = 5;

#[derive(Clone, Debug)]
pub struct Section {
    pub name: String,
    pub vaddr: u32,
    pub vsize: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

pub struct Pe {
    pub machine: u16,
    pub image_base: u64,
    pub sections: Vec<Section>,
    /// Sorted function-start RVAs from the exception directory (`.pdata`).
    pub func_starts: Vec<u32>,
    pub relocs: Relocs,
}

impl Pe {
    pub fn rva_to_offset(&self, rva: u64) -> Option<usize> {
        for s in &self.sections {
            let span = s.vsize.max(s.raw_size) as u64;
            if rva >= s.vaddr as u64 && rva - (s.vaddr as u64) < span {
                return Some((s.raw_ptr as u64 + (rva - s.vaddr as u64)) as usize);
            }
        }
        None
    }

    pub fn offset_to_rva(&self, off: u64) -> Option<u32> {
        for s in &self.sections {
            if off >= s.raw_ptr as u64 && off - (s.raw_ptr as u64) < s.raw_size as u64 {
                return Some(s.vaddr + (off - s.raw_ptr as u64) as u32);
            }
        }
        None
    }

    pub fn section_at_rva(&self, rva: u64) -> Option<&Section> {
        self.sections.iter().find(|s| {
            let span = s.vsize.max(s.raw_size) as u64;
            rva >= s.vaddr as u64 && rva - (s.vaddr as u64) < span
        })
    }

    /// End (exclusive) of the function whose entry point is `va`, from
    /// `.pdata`; the next function start is the end of the previous one.
    pub fn function_end(&self, va: u64) -> Option<u64> {
        if va < self.image_base {
            return None;
        }
        let rva = (va - self.image_base) as u32;
        let i = self.func_starts.binary_search(&rva).ok()?;
        self.func_starts
            .get(i + 1)
            .map(|&end| self.image_base + end as u64)
    }

    /// Address (native space) of the section containing `va`.
    pub fn contains_va(&self, va: u64) -> Option<&Section> {
        if va < self.image_base {
            return None;
        }
        self.section_at_rva(va - self.image_base)
    }
}

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

pub fn parse(data: &[u8]) -> Result<Pe, String> {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return Err("not a PE file".into());
    }
    let e_lfanew = u32at(data, 0x3c) as usize;
    if e_lfanew + 24 > data.len() || &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err("bad PE signature".into());
    }
    let coff = e_lfanew + 4;
    let machine = u16at(data, coff) as u16;
    let nsec = u16at(data, coff + 2) as usize;
    let size_opt = u16at(data, coff + 16) as usize;
    let opt = coff + 20;
    if opt + 2 > data.len() {
        return Err("truncated PE optional header".into());
    }
    let magic = u16at(data, opt);
    if magic != 0x20b {
        return Err("only PE32+ (64-bit) is supported".into());
    }
    let image_base = u64at(data, opt + 24);

    let sec_off = opt + size_opt;
    let mut sections = Vec::with_capacity(nsec);
    for i in 0..nsec {
        let b = sec_off + i * 40;
        if b + 40 > data.len() {
            break;
        }
        let name = data[b..b + 8]
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as char)
            .collect();
        sections.push(Section {
            name,
            vsize: u32at(data, b + 8) as u32,
            vaddr: u32at(data, b + 12) as u32,
            raw_size: u32at(data, b + 16) as u32,
            raw_ptr: u32at(data, b + 20) as u32,
            characteristics: u32at(data, b + 36) as u32,
        });
    }

    // Base relocation directory (data directory index 5).
    let num_dirs = u32at(data, opt + 108) as usize;
    let mut pe = Pe { machine, image_base, sections, func_starts: Vec::new(), relocs: Relocs::default() };
    if num_dirs > IMAGE_DIRECTORY_ENTRY_BASERELOC {
        let dir = opt + 112 + IMAGE_DIRECTORY_ENTRY_BASERELOC * 8;
        let rel_rva = u32at(data, dir);
        let rel_size = u32at(data, dir + 4);
        let mut relocs = Relocs::default();
        parse_base_relocs(data, &pe, rel_rva, rel_size, &mut relocs);
        relocs.finish();
        pe.relocs = relocs;
    }

    // Exception directory (`.pdata`): one entry per function. x86-64 entries
    // are 12 bytes (Begin, End, Unwind); ARM/ARM64 entries are 8 bytes
    // (Begin, Unwind).
    if num_dirs > 3 {
        let dir = opt + 112 + 3 * 8;
        let pdata_rva = u32at(data, dir);
        let pdata_size = u32at(data, dir + 4);
        pe.func_starts = parse_function_starts(data, &pe, machine, pdata_rva, pdata_size);
    }

    Ok(pe)
}

fn parse_function_starts(
    data: &[u8],
    pe: &Pe,
    machine: u16,
    rva: u64,
    size: u64,
) -> Vec<u32> {
    if rva == 0 || size == 0 {
        return Vec::new();
    }
    let stride = if machine == 0x8664 { 12 } else { 8 };
    let Some(start) = pe.rva_to_offset(rva) else {
        return Vec::new();
    };
    let end = (start + size as usize).min(data.len());
    let mut out = Vec::new();
    let mut p = start;
    while p + stride <= end {
        out.push(u32at(data, p) as u32);
        p += stride;
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn parse_base_relocs(data: &[u8], pe: &Pe, rva: u64, size: u64, relocs: &mut Relocs) {
    if rva == 0 || size == 0 {
        return;
    }
    let Some(start) = pe.rva_to_offset(rva) else {
        return;
    };
    let end = (start + size as usize).min(data.len());
    let mut p = start;
    while p + 8 <= end {
        let page = u32at(data, p);
        let block_size = u32at(data, p + 4) as usize;
        if block_size < 8 {
            break;
        }
        let mut q = p + 8;
        let block_end = (p + block_size).min(end);
        while q + 2 <= block_end {
            let entry = u16at(data, q) as u16;
            q += 2;
            let typ = entry >> 12;
            let ofs = entry & 0x0fff;
            let site_rva = page + ofs as u64;
            let Some(off) = pe.rva_to_offset(site_rva) else {
                continue;
            };
            let site = pe.image_base + site_rva;
            match typ {
                IMAGE_REL_BASED_DIR64 if off + 8 <= data.len() => {
                    let target = u64at(data, off);
                    relocs.add(site, target);
                }
                IMAGE_REL_BASED_HIGHLOW if off + 4 <= data.len() => {
                    let target = u32at(data, off);
                    relocs.add(site, target);
                }
                _ => {}
            }
        }
        p += block_size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_pe() {
        assert!(parse(b"MZ but not really a PE file").is_err());
    }
}
