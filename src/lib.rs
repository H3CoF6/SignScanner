//! SignScanner library: stable, name-anchored location of the QQ
//! `wrapper.node` sign function.
//!
//! Containers: ELF (Linux), PE (Windows) and Mach-O (macOS universal).
//! ABIs: Itanium (Linux/macOS) and MSVC (Windows). Architectures: x86-64
//! (via iced-x86) and aarch64 (hand-rolled minimal decoder).

pub mod aarch64;
pub mod decode;
pub mod elf;
pub mod image;
pub mod locate;
pub mod macho;
pub mod pe;
pub mod reloc;
pub mod x86;
