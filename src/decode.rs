//! Instruction-decoder-agnostic result contract.
//!
//! The sign core is identified *semantically*: it writes the three caller
//! result fields at `+0xFF` (SecToken length), `+0x1FF` (SecExtra length) and
//! `+0x2FF` (SecSign length). Every architecture decoder reports the same
//! `BufferHits`, so the locator does not care whether it is looking at x86-64
//! or aarch64 code.

#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferHits {
    pub token: bool,
    pub extra: bool,
    pub sign: bool,
}

impl BufferHits {
    pub fn all(&self) -> bool {
        self.token && self.extra && self.sign
    }

    /// Record a byte-displacement seen on the destination of a store.
    pub fn record(&mut self, displacement: u64) {
        match displacement {
            0xFF => self.token = true,
            0x1FF => self.extra = true,
            0x2FF => self.sign = true,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_the_three_result_offsets() {
        let mut h = BufferHits::default();
        h.record(0xFF);
        assert!(!h.all());
        h.record(0x1FF);
        h.record(0x2FF);
        assert!(h.all());
    }

    #[test]
    fn ignores_unrelated_offsets() {
        let mut h = BufferHits::default();
        h.record(0x10);
        h.record(0x100);
        assert!(!h.all());
    }
}
