use crate::proof::{
    multiproof::Multiproof,
    page_cache::PageCache,
    types::{PageAddress, ProofHash, HASH_SIZE, MEMORY_LOG2_SIZE, PAGE_LOG2_SIZE},
};
use tiny_keccak::{Hasher, Keccak};

/// Represents a Merkle proof. Based on the given `page_cache` and `multiproof`, calculates the
/// root of the Merkle tree for the corresponding memory chunk. The memory chunk is divided into
/// pages, and the Merkle tree `tree` is built from the bottom up. The leaf nodes of the tree
/// are the hashes of the pages. The internal nodes are the hashes of the concatenation of the
/// hashes of their children.
/// If a page is missing in the `page_cache`, it is complemented by the corresponding entry from
/// the `multiproof`.
pub struct MerkleProof {
    tree: Vec<Option<ProofHash>>,
    page_cache: PageCache,
    multiproof: Multiproof,
}

impl MerkleProof {
    pub fn new(page_cache: PageCache, multiproof: Multiproof) -> Self {
        let mut tree: Vec<Option<ProofHash>> = Vec::new();
        // reserve enough space for the last level of the tree (leaf nodes)
        tree.reserve(1 << (MEMORY_LOG2_SIZE - PAGE_LOG2_SIZE));
        Self {
            tree,
            page_cache,
            multiproof,
        }
    }

    fn merge_hashes(left: ProofHash, right: ProofHash) -> ProofHash {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; HASH_SIZE];
        hasher.update(&left);
        hasher.update(&right);
        hasher.finalize(&mut output);
        output
    }

    /// Fills the first level of the tree with the hashes of the pages.
    fn init(&mut self) {
        log::debug!(">>> Initializing the tree");
        let mut page_address: PageAddress = 0;
        while page_address < (1 << MEMORY_LOG2_SIZE) {
            if self.page_cache.has_next(page_address) {
                let page = self.page_cache.get_next().unwrap();
                log::debug!("Reading page from cache, page address: {:x}", page.address);
                self.tree.push(Some(page.hash()));
            } else if self.multiproof.has_next(page_address, page_address) {
                let entry = self.multiproof.get_next().unwrap();
                log::debug!(
                    "Reading page from multiproof, page address: {:x}",
                    page_address
                );
                self.tree.push(Some(entry.hash));
            } else {
                // if we hit this branch then for some pair of pages should have a multiproof
                // entry at another tree level
                log::debug!("No data for page address: {:x}", page_address);
                self.tree.push(None);
            }
            page_address += 1 << PAGE_LOG2_SIZE;
        }
    }

    /// Moves a level up. Bubbles up the hashes from the previous level to the next.
    fn bubble_up(&mut self) {
        // the size of the memory chunk that is encoded by an entry at the current merkle tree level
        let entry_size = (1 << MEMORY_LOG2_SIZE) / (self.tree.len() >> 1);
        log::debug!(">>> Bubbling up, entry size: {}", entry_size);
        // we read two child nodes' hashes at a time
        let read_range = (0..self.tree.len()).step_by(2);
        // we write one parent node hash in-place
        let write_range = 0..self.tree.len();
        // bubble up the hashes
        for (r, w) in read_range.zip(write_range) {
            let left = self.tree[r];
            let right = self.tree[r + 1];
            if left.is_none() || right.is_none() {
                // in fact, both should be none. if only one is none, we have an excessive data
                if self.multiproof.has_next(
                    (w * entry_size) as u64,
                    (w * entry_size + entry_size - 1) as u64,
                ) {
                    let entry = self.multiproof.get_next().unwrap();
                    log::debug!(
                        "Reading multiproof entry, address_low: {:x}, address_high: {:x}",
                        entry.address_low,
                        entry.address_high
                    );
                    self.tree[w] = Some(entry.hash);
                } else {
                    log::debug!(
                        "No data for node: {:x} - {:x}",
                        (w * entry_size),
                        (w * entry_size + entry_size - 1)
                    );
                    self.tree[w] = None;
                }
            } else {
                log::debug!(
                    "Merging hashes for node: {:x} - {:x}",
                    (w * entry_size),
                    (w * entry_size + entry_size - 1)
                );
                let merged_hash = MerkleProof::merge_hashes(left.unwrap(), right.unwrap());
                self.tree[w] = Some(merged_hash);
            }
        }
        self.tree.truncate(self.tree.len() >> 1);
    }

    /// Calculates the Merkle tree root which is a final proof.
    /// Returns `None` if the data provided in `page_cache` and `multiproof` is incomplete.
    pub fn calculate_root(&mut self) -> Result<ProofHash, ()> {
        self.init();
        while self.tree.len() > 1 {
            self.bubble_up();
        }
        match self.tree[0] {
            Some(hash) => Ok(hash),
            // None means that at some point there was not enough data provided (in the page cache
            // or in the multiproof) to calculate the hash. This None was bubbled up to the root.
            None => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::{multiproof::MultiproofEntry, page_cache::Page, types::HASH_SIZE};

    #[test_log::test]
    fn test_merkle_proof() {
        const EXPECTED_ROOT_HASH: [u8; HASH_SIZE] = [
            0xac, 0x22, 0xaa, 0x42, 0x2a, 0x1f, 0x3e, 0x1a, 0x56, 0x36, 0xc4, 0x63, 0x17, 0xd1,
            0x35, 0xd3, 0x45, 0xae, 0x03, 0xad, 0xdc, 0x64, 0xe6, 0x91, 0x85, 0x9a, 0xe6, 0xe5,
            0x9b, 0x5a, 0x69, 0xe3,
        ];

        let page_cache = PageCache::new(vec![
            Page {
                data: [1u8; 1 << PAGE_LOG2_SIZE],
                address: 0x4,
            },
            Page {
                data: [2u8; 1 << PAGE_LOG2_SIZE],
                address: 0xc,
            },
            Page {
                data: [3u8; 1 << PAGE_LOG2_SIZE],
                address: 0x14,
            },
        ]);

        let multiproof = Multiproof {
            hashes: vec![
                MultiproofEntry {
                    address_low: 0x18,
                    address_high: 0x1f,
                    hash: [0xdu8; HASH_SIZE],
                },
                MultiproofEntry {
                    address_low: 0x10,
                    address_high: 0x10,
                    hash: [0xcu8; HASH_SIZE],
                },
                MultiproofEntry {
                    address_low: 0x8,
                    address_high: 0x8,
                    hash: [0xbu8; HASH_SIZE],
                },
                MultiproofEntry {
                    address_low: 0x0,
                    address_high: 0x0,
                    hash: [0xau8; HASH_SIZE],
                },
            ],
        };

        let mut merkle_proof = MerkleProof::new(page_cache, multiproof);
        let calculated_root = merkle_proof.calculate_root().expect("Invalid input data");
        assert_eq!(calculated_root, EXPECTED_ROOT_HASH);
    }
}
