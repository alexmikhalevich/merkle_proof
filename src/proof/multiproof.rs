use crate::proof::types::{PageAddress, ProofHash};

/// Multiproof entry is a hash that is used to complement the missing pages in the page cache.
/// `address_low` and `address_high` define the memory range that the `hash` is calculated for.
pub struct MultiproofEntry {
    pub address_low: PageAddress,
    pub address_high: PageAddress,
    pub hash: ProofHash,
}

/// Multiproof is a collection of hashes that are used to complement the missing pages in the page
/// cache. Multiproof is used to calculate the Merkle tree root hash.
pub struct Multiproof {
    pub hashes: Vec<MultiproofEntry>,
}

impl Multiproof {
    /// Get next available entry from the multiproof.
    pub fn get_next(&mut self) -> Option<MultiproofEntry> {
        self.hashes.pop()
    }

    /// Check if the multiproof has the next entry necessary for calculating the hash.
    /// Multiproof should complement the missing pages.
    pub fn has_next(&self, address_low: PageAddress, address_high: PageAddress) -> bool {
        self.hashes.last().map_or(false, |entry| {
            entry.address_low == address_low && entry.address_high == address_high
        })
    }
}
