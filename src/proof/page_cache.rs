use crate::proof::types::{PageAddress, PageData, ProofHash, HASH_SIZE};
use tiny_keccak::{Hasher, Keccak};

/// A memory page.
pub struct Page {
    pub data: PageData,
    pub address: PageAddress,
}

impl Page {
    pub fn hash(&self) -> ProofHash {
        let mut hasher = Keccak::v256();
        let mut output = [0u8; HASH_SIZE];
        hasher.update(&self.data);
        hasher.finalize(&mut output);
        output
    }
}

/// A collection of memory pages.
pub struct PageCache {
    pages: Vec<Page>,
}

impl PageCache {
    /// Create a new page cache with the given pages.
    /// We keep the pages sorted by address in descending order so that we get the first page by
    /// popping the last element.
    pub fn new(mut pages: Vec<Page>) -> Self {
        pages.sort_by(|a, b| a.address.cmp(&b.address).reverse());
        Self { pages }
    }

    /// Get next available page from the cache.
    pub fn get_next(&mut self) -> Option<Page> {
        self.pages.pop()
    }

    /// Check if the cache has the next page necessary for calculating the hash.
    /// The cache may not have all the pages. Multiproof should complement the missing pages.
    pub fn has_next(&self, address: PageAddress) -> bool {
        self.pages
            .last()
            .map_or(false, |page| page.address == address)
    }
}
