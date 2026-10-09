//! Thin wrappers over iced-x86 used to reason about code *semantically* rather
//! than by matching opaque byte signatures.

use iced_x86::{Code, Decoder, DecoderOptions, Mnemonic, OpKind};

use crate::decode::BufferHits;

/// Exclusive end of the instruction run starting at `ip`, i.e. the address just
/// past its first `ret`/`retf`/`int3`. Containers without function-boundary
/// metadata (ELF) use this to bound a function without guessing a fixed window.
///
/// Only *return* and `int3` padding end a run: a `jmp` is usually the
/// compiler's switch/tail-call spelling and the body continues past it, so
/// stopping there would truncate the sign core. If no terminator is found the
/// whole `data` slice is returned, letting the caller fall back to its own cap.
pub fn function_end(data: &[u8], ip: u64) -> u64 {
    let mut dec = Decoder::with_ip(64, data, ip, DecoderOptions::NONE);
    while dec.can_decode() {
        let pos = dec.position();
        let insn = dec.decode();
        if insn.code() == Code::INVALID {
            let _ = dec.set_position(pos + 1);
            continue;
        }
        match insn.mnemonic() {
            Mnemonic::Ret | Mnemonic::Retf => return ip + dec.position() as u64,
            Mnemonic::Int3 => return ip + pos as u64,
            _ => {}
        }
    }
    ip + data.len() as u64
}

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

    #[test]
    fn function_end_stops_past_the_first_return() {
        // push rbp; mov rbp,rsp; ...; ret  (0x55 0x48 0x89 0xE5 0xC3 0xCC 0xCC)
        let code = [0x55, 0x48, 0x89, 0xE5, 0xC3, 0xCC, 0xCC];
        assert_eq!(function_end(&code, 0x1000), 0x1005);
    }

    #[test]
    fn function_end_does_not_stop_on_an_interior_jump() {
        // A `jmp` is switch/tail-call spelling, not an end: the real `ret` is
        // further down, so the body must run all the way to it.
        // jmp +0 ; nop ; ret
        let code = [0xEB, 0x00, 0x90, 0xC3];
        assert_eq!(function_end(&code, 0x2000), 0x2004);
    }

    #[test]
    fn function_end_falls_back_to_the_whole_slice() {
        // No terminator at all -> clamp to the slice end (caller caps further).
        let code = [0x90, 0x90, 0x90, 0x90];
        assert_eq!(function_end(&code, 0x3000), 0x3004);
    }
}
