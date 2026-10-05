//! Relocation tables shared by every container format.
//!
//! A relocation is a `(site, target)` pair: the image stores at virtual address
//! `site` a pointer that resolves to `target`. ELF records the target as an
//! addend inside the relocation entry, while PE (base relocations) and Mach-O
//! (dyld rebase info) store it inline at the site. Either way the pair is the
//! only thing the anchor walk needs, so all three containers produce the same
//! two sorted projections and the locator stays container-agnostic.
//!
//! Keeping both projections sorted makes `target_at` and `sites_pointing_to`
//! O(log n), which matters because a large `wrapper.node` carries hundreds of
//! thousands of relocations.

#[derive(Default)]
pub struct Relocs {
    by_site: Vec<(u64, u64)>,
    by_target: Vec<(u64, u64)>,
}

impl Relocs {
    pub fn add(&mut self, site: u64, target: u64) {
        self.by_site.push((site, target));
        self.by_target.push((target, site));
    }

    pub fn finish(&mut self) {
        self.by_site.sort_unstable();
        self.by_target
            .sort_unstable_by_key(|&(target, site)| (target, site));
    }

    /// The target recorded for `site`, if the site holds a relocated pointer.
    pub fn target_at(&self, site: u64) -> Option<u64> {
        self.by_site
            .binary_search_by_key(&site, |&(s, _)| s)
            .ok()
            .map(|i| self.by_site[i].1)
    }

    /// Every relocation site whose target equals `target` (every pointer in the
    /// image that resolves to `target`).
    pub fn sites_pointing_to(&self, target: u64) -> Vec<u64> {
        let lo = self.by_target.partition_point(|&(t, _)| t < target);
        let hi = self.by_target.partition_point(|&(t, _)| t <= target);
        self.by_target[lo..hi].iter().map(|&(_, s)| s).collect()
    }

    pub fn len(&self) -> usize {
        self.by_site.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_site.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relocs(entries: &[(u64, u64)]) -> Relocs {
        let mut r = Relocs::default();
        for &(site, target) in entries {
            r.add(site, target);
        }
        r.finish();
        r
    }

    #[test]
    fn resolves_pointer_at_site() {
        let r = relocs(&[(0x1000, 0x2000), (0x1008, 0x3000)]);
        assert_eq!(r.target_at(0x1000), Some(0x2000));
        assert_eq!(r.target_at(0x1008), Some(0x3000));
        assert_eq!(r.target_at(0x1004), None);
    }

    #[test]
    fn finds_every_site_pointing_to_a_target() {
        let r = relocs(&[(0x1000, 0x2000), (0x1010, 0x2000), (0x1020, 0x3000)]);
        assert_eq!(r.sites_pointing_to(0x2000), vec![0x1000, 0x1010]);
        assert_eq!(r.sites_pointing_to(0x3000), vec![0x1020]);
        assert!(r.sites_pointing_to(0x9999).is_empty());
    }
}
