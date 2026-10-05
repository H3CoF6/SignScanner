//! A memory-mapped binary plus a format-agnostic view over one architecture
//! slice of it.
//!
//! `wrapper.node` ships as ELF on Linux, PE on Windows and a *universal*
//! Mach-O (two slices) on macOS. A fat file therefore yields several `Slice`s,
//! each with its own address space; `View` ties a slice to the bytes it lives
//! in and offers the small interface the locator needs (`read`,
//! `addr_to_offset`, `resolve_ptr`, `sites_pointing_to`, `is_exec`), so
//! `locate.rs` never has to know which container it is walking.

use std::fs::File;
use std::path::Path;

use memmap2::Mmap;

use crate::elf::{self, PF_X, SHF_ALLOC, SHF_EXECINSTR};
use crate::macho;

use crate::pe::{self, IMAGE_SCN_MEM_EXECUTE};
use crate::reloc::Relocs;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    Elf,
    Pe,
    MachO,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arch {
    X86_64,
    AArch64,
    I386,
    Arm,
    Unknown,
}

impl Arch {
    pub fn name(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86-64",
            Arch::AArch64 => "aarch64",
            Arch::I386 => "i386",
            Arch::Arm => "arm",
            Arch::Unknown => "unknown",
        }
    }
}

/// The C++ ABI decides how RTTI is laid out, and therefore which anchor chain
/// `locate.rs` runs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Abi {
    /// Itanium C++ ABI (Linux, macOS): typeinfo -> vtable -> ...
    Itanium,
    /// Microsoft C++ ABI (Windows): type descriptor -> COL -> vtable -> ...
    MsVc,
}

impl Abi {
    pub fn name(self) -> &'static str {
        match self {
            Abi::Itanium => "Itanium",
            Abi::MsVc => "MSVC",
        }
    }
}

pub enum Container {
    Elf(elf::Elf),
    Pe(pe::Pe),
    MachO(macho::MachO),
}

/// One architecture inside the file: for ELF/PE that is the whole file, for a
/// fat Mach-O one slice of it.
pub struct Slice {
    pub arch: Arch,
    pub abi: Abi,
    pub format: Format,
    pub data_off: usize,
    pub data_len: usize,
    pub container: Container,
}

impl Slice {
    fn relocs(&self) -> &Relocs {
        match &self.container {
            Container::Elf(e) => &e.relocs,
            Container::Pe(p) => &p.relocs,
            Container::MachO(m) => &m.relocs,
        }
    }

    pub fn describe(&self) -> String {
        match self.format {
            Format::Elf => format!("ELF64 (little-endian, {})", self.arch.name()),
            Format::Pe => format!("PE32+ ({})", self.arch.name()),
            Format::MachO => format!("Mach-O 64 ({})", self.arch.name()),
        }
    }
}

pub struct Image {
    pub path: String,
    pub data: Mmap,
    pub slices: Vec<Slice>,
}

fn arch_from_elf_machine(m: u16) -> Arch {
    match m {
        elf::EM_X86_64 => Arch::X86_64,
        elf::EM_AARCH64 => Arch::AArch64,
        elf::EM_386 => Arch::I386,
        elf::EM_ARM => Arch::Arm,
        _ => Arch::Unknown,
    }
}

fn arch_from_pe_machine(m: u16) -> Arch {
    match m {
        0x8664 => Arch::X86_64,
        0xaa64 => Arch::AArch64,
        0x014c => Arch::I386,
        0x01c0 | 0x01c4 => Arch::Arm,
        _ => Arch::Unknown,
    }
}

fn arch_from_cputype(c: u32) -> Arch {
    match c {
        macho::CPU_X86_64 => Arch::X86_64,
        macho::CPU_ARM64 => Arch::AArch64,
        _ => Arch::Unknown,
    }
}

impl Image {
    pub fn open(path: &Path) -> Result<Image, String> {
        let file = File::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        let data = unsafe { Mmap::map(&file) }.map_err(|e| format!("mmap: {e}"))?;
        let slices = Self::parse(&data);
        Ok(Image { path: path.display().to_string(), data, slices })
    }

    fn parse(data: &[u8]) -> Vec<Slice> {
        let head = &data[..data.len().min(8)];
        let mut slices = Vec::new();

        if head.starts_with(b"\x7fELF") {
            if let Ok(e) = elf::parse(data) {
                let arch = arch_from_elf_machine(e.machine);
                slices.push(Slice {
                    arch,
                    abi: Abi::Itanium,
                    format: Format::Elf,
                    data_off: 0,
                    data_len: data.len(),
                    container: Container::Elf(e),
                });
            }
        } else if head.starts_with(b"MZ") {
            if let Ok(p) = pe::parse(data) {
                let arch = arch_from_pe_machine(p.machine);
                slices.push(Slice {
                    arch,
                    abi: Abi::MsVc,
                    format: Format::Pe,
                    data_off: 0,
                    data_len: data.len(),
                    container: Container::Pe(p),
                });
            }
        } else if macho::is_fat(data) {
            if let Ok(archs) = macho::fat_archs(data) {
                for (ct, off, size) in archs {
                    if off + size > data.len() || size < 32 {
                        continue;
                    }
                    if let Ok(m) = macho::parse_thin(&data[off..off + size]) {
                        slices.push(Slice {
                            arch: arch_from_cputype(ct),
                            abi: Abi::Itanium,
                            format: Format::MachO,
                            data_off: off,
                            data_len: size,
                            container: Container::MachO(m),
                        });
                    }
                }
            }
        } else if macho::is_thin(data)
            && let Ok(m) = macho::parse_thin(data) {
                let arch = arch_from_cputype(m.cputype);
                slices.push(Slice {
                    arch,
                    abi: Abi::Itanium,
                    format: Format::MachO,
                    data_off: 0,
                    data_len: data.len(),
                    container: Container::MachO(m),
                });
            }

        slices
    }

    pub fn views(&self) -> Vec<View<'_>> {
        self.slices
            .iter()
            .map(|s| View { slice: s, data: &self.data[s.data_off..s.data_off + s.data_len] })
            .collect()
    }

    pub fn format_name(&self) -> &'static str {
        match self.slices.first().map(|s| s.format) {
            Some(Format::Elf) => "ELF64",
            Some(Format::Pe) => "PE (Windows)",
            Some(Format::MachO) => "Mach-O (macOS)",
            None => "unknown",
        }
    }
}

/// A single architecture slice plus the bytes backing it.
pub struct View<'a> {
    pub slice: &'a Slice,
    pub data: &'a [u8],
}

impl<'a> View<'a> {
    pub fn arch(&self) -> Arch {
        self.slice.arch
    }

    pub fn abi(&self) -> Abi {
        self.slice.abi
    }

    pub fn describe(&self) -> String {
        self.slice.describe()
    }

    /// Preferred load address for PE (0 for position-independent ELF/Mach-O).
    pub fn image_base(&self) -> u64 {
        match &self.slice.container {
            Container::Pe(p) => p.image_base,
            _ => 0,
        }
    }

    pub fn reloc_count(&self) -> usize {
        self.slice.relocs().len()
    }

    /// Read `len` bytes of virtual address space starting at `addr`.
    pub fn read(&self, addr: u64, len: usize) -> Option<&[u8]> {
        let off = self.addr_to_offset(addr)?;
        self.data.get(off..off.checked_add(len)?)
    }

    pub fn read_u32(&self, addr: u64) -> Option<u32> {
        let b = self.read(addr, 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Map a virtual address to an offset inside this slice.
    pub fn addr_to_offset(&self, addr: u64) -> Option<usize> {
        match &self.slice.container {
            Container::Elf(e) => {
                for s in &e.sections {
                    if s.flags & SHF_ALLOC != 0 && addr >= s.addr && addr < s.addr + s.size {
                        return Some((s.offset + (addr - s.addr)) as usize);
                    }
                }
                for p in &e.phdrs {
                    if p.p_type == elf::PT_LOAD && addr >= p.vaddr && addr < p.vaddr + p.filesz {
                        return Some((p.offset + (addr - p.vaddr)) as usize);
                    }
                }
                None
            }
            Container::Pe(p) => {
                if addr < p.image_base {
                    return None;
                }
                p.rva_to_offset(addr - p.image_base)
            }
            Container::MachO(m) => m.vm_to_offset(addr),
        }
    }

    /// Inverse of `addr_to_offset`.
    pub fn offset_to_addr(&self, off: usize) -> Option<u64> {
        match &self.slice.container {
            Container::Elf(e) => {
                let off = off as u64;
                for s in &e.sections {
                    if s.flags & SHF_ALLOC != 0 && off >= s.offset && off < s.offset + s.size {
                        return Some(s.addr + (off - s.offset));
                    }
                }
                for p in &e.phdrs {
                    if p.p_type == elf::PT_LOAD && off >= p.offset && off < p.offset + p.filesz {
                        return Some(p.vaddr + (off - p.offset));
                    }
                }
                None
            }
            Container::Pe(p) => {
                let off = off as u64;
                p.offset_to_rva(off).map(|rva| p.image_base + rva as u64)
            }
            Container::MachO(m) => {
                let off = off as u64;
                for s in &m.segments {
                    if off >= s.fileoff && off < s.fileoff + s.filesize {
                        return Some(s.vmaddr + (off - s.fileoff));
                    }
                }
                None
            }
        }
    }

    pub fn is_exec(&self, addr: u64) -> bool {
        match &self.slice.container {
            Container::Elf(e) => {
                if e.sections.iter().any(|s| {
                    s.flags & SHF_EXECINSTR != 0 && addr >= s.addr && addr < s.addr + s.size
                }) {
                    return true;
                }
                e.phdrs.iter().any(|p| {
                    p.p_type == elf::PT_LOAD
                        && p.flags & PF_X != 0
                        && addr >= p.vaddr
                        && addr < p.vaddr + p.filesz
                })
            }
            Container::Pe(p) => p
                .contains_va(addr)
                .map(|s| s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0)
                .unwrap_or(false),
            Container::MachO(m) => m.is_exec(addr),
        }
    }

    /// The exclusive end of the function starting at `addr`, when the container
    /// carries function-boundary metadata (PE `.pdata`, Mach-O
    /// `LC_FUNCTION_STARTS`). ELF is stripped, so callers fall back to a window.
    pub fn function_end(&self, addr: u64) -> Option<u64> {
        match &self.slice.container {
            Container::Pe(p) => p.function_end(addr),
            Container::MachO(m) => m.function_end(addr),
            Container::Elf(_) => None,
        }
    }

    /// Resolve the pointer stored at virtual address `site` (honouring the
    /// container's relocation model, then falling back to the raw 8 bytes).
    pub fn resolve_ptr(&self, site: u64) -> Option<u64> {
        if let Some(t) = self.slice.relocs().target_at(site) {
            return Some(t);
        }
        let raw = self.read(site, 8)?;
        Some(u64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]))
    }

    /// Every virtual address that holds a relocated pointer to `target`.
    pub fn sites_pointing_to(&self, target: u64) -> Vec<u64> {
        self.slice.relocs().sites_pointing_to(target)
    }

    /// All offsets where `needle` occurs.
    pub fn find_all(&self, needle: &[u8]) -> Vec<usize> {
        let mut out = Vec::new();
        if needle.is_empty() || needle.len() > self.data.len() {
            return out;
        }
        let hay = self.data;
        let mut start = 0usize;
        while start + needle.len() <= hay.len() {
            match hay[start..].windows(needle.len()).position(|w| w == needle) {
                Some(p) => {
                    let at = start + p;
                    out.push(at);
                    start = at + 1;
                }
                None => break,
            }
        }
        out
    }

    /// Addresses where the little-endian 32-bit `value` is stored. Used for the
    /// MSVC type descriptor's RVA, which is stored inline rather than relocated.
    pub fn find_u32_le(&self, value: u32) -> Vec<u64> {
        let mut out = Vec::new();
        let needle = value.to_le_bytes();
        let d = self.data;
        let mut i = 0usize;
        while i + 4 <= d.len() {
            if d[i] == needle[0]
                && d[i + 1] == needle[1]
                && d[i + 2] == needle[2]
                && d[i + 3] == needle[3]
                && let Some(a) = self.offset_to_addr(i) {
                    out.push(a);
                }
            i += 1;
        }
        out
    }
}
