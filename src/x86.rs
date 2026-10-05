//! Thin wrappers over iced-x86 used to reason about code *semantically* rather
//! than by matching opaque byte signatures.

use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind};

use crate::decode::BufferHits;

/// Disassemble `data` (whose first byte lives at virtual address `ip`) and
/// return every direct `call rel32` target.
pub fn direct_calls(data: &[u8], ip: u64) -> Vec<u64> {
    let mut dec = Decoder::with_ip(64, data, ip, DecoderOptions::NONE);
    let mut out = Vec::new();
    while dec.can_decode() {
        let pos = dec.position();
        let insn = dec.decode();
        if insn.code() == Code::INVALID {
            let _ = dec.set_position(pos + 1);
            continue;
        }
        if insn.mnemonic() == Mnemonic::Call && insn.op0_kind() == OpKind::NearBranch64 {
            out.push(insn.near_branch64());
        }
    }
    out
}

/// Decode `data` and report which result-buffer offsets it stores into. A hit
/// requires a memory operand on the destination side (`op0`) with the exact
/// displacement, which is the observable contract the sign core fulfils when it
/// fills the caller's output buffer.
pub fn buffer_hits(data: &[u8], ip: u64) -> BufferHits {
    let mut dec = Decoder::with_ip(64, data, ip, DecoderOptions::NONE);
    let mut hits = BufferHits::default();
    while dec.can_decode() {
        let pos = dec.position();
        // Stop at compiler padding: that is the function boundary in practice.
        if data.get(dec.position()).copied() == Some(0xCC) {
            break;
        }
        let insn = dec.decode();
        if insn.code() == Code::INVALID {
            let _ = dec.set_position(pos + 1);
            continue;
        }
        if insn.op0_kind() == OpKind::Memory && !insn.is_ip_rel_memory_operand() {
            hits.record(insn.memory_displacement64());
        }
    }
    hits
}

/// Cheap raw-byte prefilter: could this code possibly store to the three
/// result offsets? Only used to avoid disassembling large functions that
/// obviously cannot be the core; the decoder still makes the final call.
pub fn maybe_writes_result_buffer(data: &[u8]) -> bool {
    fn has(data: &[u8], needle: &[u8]) -> bool {
        data.windows(needle.len()).any(|w| w == needle)
    }
    has(data, &[0xff, 0x00, 0x00, 0x00])
        && has(data, &[0xff, 0x01, 0x00, 0x00])
        && has(data, &[0xff, 0x02, 0x00, 0x00])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_call_is_resolved_to_absolute_target() {
        // call rel32 with rel = 0, placed at ip 0x1000 -> target 0x1005.
        let code = [0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
        assert_eq!(direct_calls(&code, 0x1000), vec![0x1005]);
    }

    #[test]
    fn direct_call_uses_relative_displacement() {
        // call rel32 with rel = 0x100 -> target ip + 5 + 0x100.
        let code = [0xE8, 0x00, 0x01, 0x00, 0x00, 0xC3];
        assert_eq!(direct_calls(&code, 0x2000), vec![0x2105]);
    }

    #[test]
    fn non_call_has_no_targets() {
        let code = [0x55, 0x48, 0x89, 0xE5, 0xC3]; // push rbp; mov rbp,rsp; ret
        assert!(direct_calls(&code, 0x1000).is_empty());
    }

    #[test]
    fn buffer_hits_finds_result_offsets() {
        // mov byte ptr [rbx+0xFF], al   ; 88 83 FF 00 00 00
        // mov byte ptr [rbx+0x1FF], al  ; 88 83 FF 01 00 00
        // mov byte ptr [rbx+0x2FF], al  ; 88 83 FF 02 00 00
        let code = [
            0x88, 0x83, 0xFF, 0x00, 0x00, 0x00, 0x88, 0x83, 0xFF, 0x01, 0x00, 0x00, 0x88, 0x83, 0xFF,
            0x02, 0x00, 0x00, 0xC3,
        ];
        let hits = buffer_hits(&code, 0x1000);
        assert!(hits.all(), "expected all three result offsets, got {hits:?}");
    }

    #[test]
    fn buffer_hits_ignores_unrelated_displacement() {
        // mov byte ptr [rbx+0x10], al
        let code = [0x88, 0x43, 0x10, 0xC3];
        assert!(!buffer_hits(&code, 0x1000).all());
    }

    #[test]
    fn prefilter_accepts_result_displacements() {
        let code = [
            0x88, 0x83, 0xFF, 0x00, 0x00, 0x00, 0x88, 0x83, 0xFF, 0x01, 0x00, 0x00, 0x88, 0x83, 0xFF,
            0x02, 0x00, 0x00,
        ];
        assert!(maybe_writes_result_buffer(&code));
    }

    #[test]
    fn buffer_hits_ignores_ip_relative_operands() {
        // mov byte ptr [rip+0x2FF], al -> must not count as a result-buffer store.
        let code = [0x88, 0x05, 0xFF, 0x02, 0x00, 0x00, 0xC3];
        assert!(!buffer_hits(&code, 0x1000).all());
    }
}
