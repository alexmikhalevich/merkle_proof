pub const MEMORY_LOG2_SIZE: usize = 5;
pub const PAGE_LOG2_SIZE: usize = 2;
pub const HASH_SIZE: usize = 32;

pub type PageData = [u8; 1 << PAGE_LOG2_SIZE];
pub type ProofHash = [u8; HASH_SIZE];
pub type PageAddress = u64;
