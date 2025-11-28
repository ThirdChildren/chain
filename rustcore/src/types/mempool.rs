use crate::types::Transaction;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct MempoolEntry {
    pub transaction: Transaction,
    pub fee: u64,
    pub timestamp: u128,
}

pub struct Mempool {
    pub entries: HashSet<MempoolEntry>,
}

impl Mempool {
    /// Get current timestamp in milliseconds since UNIX_EPOCH
    pub fn get_current_timestamp() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis()
    }
}
