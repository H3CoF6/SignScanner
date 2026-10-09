//! Hand-rolled AArch64 decoder, small on purpose.
//!
//! `iced-x86` only knows x86, so for aarch64 we decode just the two
//! instruction classes the locator needs, straight from the fixed-width 4-byte
//! encoding:
//!
//! * `BL <imm26>` - direct calls, the aarch64 analogue of `call rel32`;
//! * `STRB`/`STURB` immediate stores - how the sign core fills the caller's
//!   result buffer at `+0xFF` / `+0x1FF` / `+0x2FF`.
//!
//! Keeping it to a handful of masks avoids pulling a whole disassembler for the
//! remaining architectures.

use crate::decode::BufferHits;

/// Sign-extend the low `bits` of `v` to a signed 64-bit value.
fn sext(v: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

fn word_at(data: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]])
}

/// `BL` (branch with link): `100101 imm26`.
fn is_bl(w: u32) -> bool {
    (w & 0xFC00_0000) == 0x9400_0000
}

/// `STRB` (immediate, unsigned offset): `size=00 111 V=0 01 opc=00 imm12 Rn Rt`.
fn is_strb_unsigned(w: u32) -> bool {
    (w & 0xFFC0_0000) == 0x3900_0000
}

/// `STURB` / `STRB` (immediate unscaled, pre/post-index): `size=00 111 V=0 00
/// opc=00 imm9 op2 Rn Rt`. Bit 21 = 0 distinguishes the immediate form from the
/// register-offset form.
fn is_strb_unscaled(w: u32) -> bool {
    (w & 0xFFE0_0000) == 0x3800_0000
}

/// `RET` (with any register): `1101011 0 0 10 11111 000000 Rn 00000`.
fn is_ret(w: u32) -> bool {
    (w & 0xFFFF_FC1F) == 0xD65F_0000
}

/// `BR` (branch to register, e.g. a tail call): `1101011 0000 11111 000000 Rn
/// 00000`. Treated as an end when it closes a run — the body cannot fall
/// through, and unlike x86 AArch64 has no switch-dispatch-via-branch idiom in
/// the middle of these functions.
fn is_br(w: u32) -> bool {
    (w & 0xFFFF_FC1F) == 0xD61F_0000
}

/// `B` (unconditional branch, `imm26`): `000101 imm26`. Only ends a run when it
/// targets the function itself (an infinite loop); ordinary `B`/`BL` stay
/// inside the function, so we do not stop on them.
fn is_b(w: u32) -> bool {
    (w & 0xFC00_0000) == 0x1400_0000
}

/// Exclusive end of the instruction run starting at `ip`: just past the first
/// `RET`/`BR`. Containers without boundary metadata (ELF) use this to bound a
/// function instead of guessing a fixed window. If none is found the whole
/// `data` slice is returned.
pub fn function_end(data: &[u8], ip: u64) -> u64 {
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let w = word_at(data, i);
        if is_ret(w) || is_br(w) {
            return ip + (i as u64) + 4;
        }
        if is_b(w) {
            // `b .` (branch to self) terminates; nothing else does.
            let off = sext(((w & 0x03FF_FFFF) as u64) << 2, 28);
            if off == 0 {
                return ip + (i as u64) + 4;
            }
        }
        i += 4;
    }
    ip + data.len() as u64
}

/// Every direct `BL` target in `data` (first instruction at virtual address
/// `ip`).
pub fn direct_calls(data: &[u8], ip: u64) -> Vec<u64> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let w = word_at(data, i);
        if is_bl(w) {
            let imm = (w & 0x03FF_FFFF) as u64;
            let off = sext(imm << 2, 28);
            out.push((ip + i as u64).wrapping_add(off as u64));
        }
        i += 4;
    }
    out
}

/// Which result-buffer offsets (`+0xFF`, `+0x1FF`, `+0x2FF`) the code stores to.
pub fn buffer_hits(data: &[u8], _ip: u64) -> BufferHits {
    let mut hits = BufferHits::default();
    let mut i = 0usize;
    while i + 4 <= data.len() {
        let w = word_at(data, i);
        if is_strb_unsigned(w) {
            hits.record(((w >> 10) & 0xFFF) as u64);
        } else if is_strb_unscaled(w) {
            let off = sext(((w >> 12) & 0x1FF) as u64, 9);
            if off >= 0 {
                hits.record(off as u64);
            }
        }
        i += 4;
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `bl #+0x100` at ip 0x1000 -> target 0x1100.
    #[test]
    fn resolves_bl_target() {
        let imm: u32 = 0x100 >> 2;
        let w = 0x9400_0000u32 | imm;
        let code = w.to_le_bytes();
        assert_eq!(direct_calls(&code, 0x1000), vec![0x1100]);
    }

    /// `bl #-4` (loop to self) at ip 0x1000 -> 0xffc.
    #[test]
    fn resolves_negative_bl_target() {
        let imm: u32 = (-4i32 >> 2) as u32 & 0x03FF_FFFF;
        let w = 0x9400_0000u32 | imm;
        let code = w.to_le_bytes();
        assert_eq!(direct_calls(&code, 0x1000), vec![0xffc]);
    }

    /// `strb w8, [x0, #0xff]` = 0x3903FC08.
    #[test]
    fn finds_strb_unsigned_offsets() {
        let strb = |imm12: u32| (0x3900_0000u32 | (imm12 << 10) | 0x8).to_le_bytes();
        let mut code = Vec::new();
        code.extend_from_slice(&strb(0xFF));
        code.extend_from_slice(&strb(0x1FF));
        code.extend_from_slice(&strb(0x2FF));
        let hits = buffer_hits(&code, 0);
        assert!(hits.all(), "expected all three result offsets, got {hits:?}");
    }

    /// `sturb w8, [x0, #0xff]` (imm9 form) = 0x3800FF08.
    #[test]
    fn finds_sturb_unscaled_offset() {
        let w = 0x3800_0000u32 | (0xFF << 12) | 0x8;
        let hits = buffer_hits(&w.to_le_bytes(), 0);
        assert!(hits.token);
        assert!(!hits.all());
    }

    #[test]
    fn ignores_non_store_instructions() {
        // ret
        let code = 0xD65F_03C0u32.to_le_bytes();
        assert_eq!(buffer_hits(&code, 0), BufferHits::default());
        assert!(direct_calls(&code, 0).is_empty());
    }

    #[test]
    fn function_end_stops_past_ret() {
        // nop ; ret  -> end is just past the `ret`.
        let mut code = Vec::new();
        code.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // nop
        code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // ret
        assert_eq!(function_end(&code, 0x1000), 0x1008);
    }

    #[test]
    fn function_end_does_not_stop_on_an_interior_branch() {
        // bl +0 (a normal call) is not an end; the `ret` past it is.
        let mut code = Vec::new();
        code.extend_from_slice(&0x9400_0000u32.to_le_bytes()); // bl .
        code.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // ret
        assert_eq!(function_end(&code, 0x2000), 0x2008);
    }
}
