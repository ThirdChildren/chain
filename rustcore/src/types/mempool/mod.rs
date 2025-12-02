use crate::types::Transaction;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of transactions the mempool can hold
const MAX_MEMPOOL_SIZE: usize = 100;

#[derive(Debug, Clone)]
pub struct MempoolEntry {
    pub transaction: Transaction,
    pub fee: u64,
    pub timestamp: u128,
}

/// Implement PartialEq based on transaction hash only
/// This allows HashSet to work correctly
impl PartialEq for MempoolEntry {
    fn eq(&self, other: &Self) -> bool {
        self.transaction.hash() == other.transaction.hash()
    }
}

impl Eq for MempoolEntry {}

/// Implement Hash based on transaction hash only
impl std::hash::Hash for MempoolEntry {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.transaction.hash().as_bytes().hash(state);
    }
}

#[derive(Debug)]
pub enum MempoolError {
    FeeTooLow {
        min_fee_required: u64,
        provided_fee: u64,
    },
    CoinbaseNotAllowed,
    InvalidTransaction(String),
    InvalidFee,
}

#[derive(Debug, Clone)]
pub struct Mempool {
    pub entries: HashSet<MempoolEntry>,
    pub max_size: usize,
}

impl Mempool {
    /// Create a new mempool with default max size
    pub fn new() -> Self {
        Mempool {
            entries: HashSet::new(),
            max_size: MAX_MEMPOOL_SIZE,
        }
    }

    /// Create a new mempool with custom max size
    pub fn with_capacity(max_size: usize) -> Self {
        Mempool {
            entries: HashSet::new(),
            max_size,
        }
    }

    /// Get current timestamp in milliseconds since UNIX_EPOCH
    pub fn get_current_timestamp() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis()
    }

    /// Add a transaction to the mempool with a pre-calculated fee
    pub fn add_entry(&mut self, transaction: Transaction, fee: u64) -> Result<(), MempoolError> {
        // Check 1: Reject coinbase transactions
        if transaction.is_coinbase() {
            return Err(MempoolError::CoinbaseNotAllowed);
        }

        // Check 2: Validate fee
        if fee == 0 {
            return Err(MempoolError::InvalidFee);
        }

        // Check 3: Basic transaction validation
        if transaction.outputs.is_empty() || transaction.inputs.is_empty() {
            return Err(MempoolError::InvalidTransaction(
                "Transaction must have inputs and outputs".to_string(),
            ));
        }

        // Check 4: Mempool size limit with fee-based replacement
        self.handle_mempool_full(fee)?;

        // Create entry and add to mempool
        let timestamp = Self::get_current_timestamp();
        let entry = MempoolEntry {
            transaction,
            fee,
            timestamp,
        };

        self.entries.insert(entry);

        Ok(())
    }

    /// Handle mempool full scenario with fee-based replacement
    fn handle_mempool_full(&mut self, new_fee: u64) -> Result<(), MempoolError> {
        if self.entries.len() >= self.max_size {
            if let Some(lowest_fee_entry) = self.entries.iter().min_by_key(|e| e.fee) {
                let min_fee = lowest_fee_entry.fee;

                if new_fee > min_fee {
                    let lowest_entry = lowest_fee_entry.clone();
                    self.entries.remove(&lowest_entry);
                } else {
                    return Err(MempoolError::FeeTooLow {
                        min_fee_required: min_fee + 1,
                        provided_fee: new_fee,
                    });
                }
            }
        }
        Ok(())
    }

    /// Remove a transaction from the mempool
    pub fn remove_entry(&mut self, transaction: &Transaction) {
        self.entries
            .retain(|entry| entry.transaction.hash() != transaction.hash());
    }

    /// Get current size of the mempool
    pub fn current_size(&self) -> usize {
        self.entries.len()
    }

    /// Check if mempool is full
    pub fn is_full(&self) -> bool {
        self.entries.len() >= self.max_size
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get all transactions sorted by fee (highest first)
    pub fn get_transactions_by_fee(&self) -> Vec<Transaction> {
        let mut entries: Vec<&MempoolEntry> = self.entries.iter().collect();
        entries.sort_by(|a, b| b.fee.cmp(&a.fee));
        entries.into_iter().map(|e| e.transaction.clone()).collect()
    }

    /// Clear all entries from the mempool
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Remove transactions that are older than the specified timestamp
    pub fn remove_old_transactions(&mut self, older_than: u128) {
        self.entries.retain(|entry| entry.timestamp > older_than);
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
