use crate::crypto::signature::backend::CryptoKey;
use crate::crypto::{Hash, PublicKey, Signature};
use crate::types::transaction::Transaction;
use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct Block {
    pub hash: Hash,
    pub index: u32,
    pub prev_block_hash: Hash,
    pub timestamp: u128,
    pub transactions: Vec<Transaction>,
    pub author: PublicKey,
    pub signature: Signature,
}

#[derive(Debug)]
pub enum BlockValidationError {
    InvalidHash,
    InvalidPreviousHash,
    InvalidAuthorSignature,
    EmptyBlock,
    InvalidCoinbasePosition,
    DuplicateTransaction,
    InvalidGenesisIndex,
    InvalidGenesisPreHash,
}

impl Block {
    /// Get current timestamp in milliseconds since UNIX_EPOCH
    pub fn get_current_timestamp() -> u128 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis()
    }

    /// Create a block with a pre-made signature
    ///
    /// **WARNING**: This method does NOT validate the signature!
    /// Use `new_signed()` for production code to ensure proper signing.
    ///
    /// This method is useful for:
    /// - Testing scenarios (creating blocks with invalid signatures)
    /// - Deserializing blocks from storage/network
    /// - Unit tests that need precise control over block fields
    #[doc(hidden)]
    pub fn new(
        index: u32,
        prev_block_hash: Hash,
        timestamp: u128,
        transactions: Vec<Transaction>,
        author: PublicKey,
        signature: Signature,
    ) -> Self {
        let mut block = Block {
            hash: Hash::zero(),
            index,
            prev_block_hash,
            timestamp,
            transactions,
            author,
            signature,
        };
        block.hash = block.calculate_hash();
        block
    }

    /// Create a new block with proper cryptographic signature
    pub fn new_signed(
        index: u32,
        prev_block_hash: Hash,
        timestamp: u128,
        transactions: Vec<Transaction>,
        author: PublicKey,
        author_private_key: &crate::crypto::PrivateKey,
    ) -> Self {
        // Step 1: Create block with temporary default signature
        let mut block = Block {
            hash: Hash::zero(),
            index,
            prev_block_hash,
            timestamp,
            transactions,
            author: author.clone(),
            signature: Signature::default(),
        };

        // Step 2: Calculate the block hash
        block.hash = block.calculate_hash();

        // Step 3: Sign the actual block hash with the author's private key
        block.signature = Signature::sign_output(&block.hash, author_private_key);

        block
    }

    pub fn hash(&self) -> Hash {
        self.hash
    }

    fn calculate_hash(&self) -> Hash {
        Hash::compute(|hasher| {
            hasher.input(self.index);
            hasher.input(self.prev_block_hash);
            hasher.input(self.timestamp);

            hasher.input(self.transactions.len() as u32);
            for tx in &self.transactions {
                hasher.input(tx.hash());
            }

            hasher.input(&self.author.to_bytes());
        })
    }

    /// Verify that the block's hash field matches its calculated hash
    pub fn verify_hash(&self) -> bool {
        self.hash == self.calculate_hash()
    }

    /// Verify that the block's prev_hash matches the expected hash
    pub fn has_correct_prev_hash(&self, expected_prev_hash: &Hash) -> bool {
        self.prev_block_hash == *expected_prev_hash
    }

    /// Verify that the author's signature is valid for this block
    pub fn verify_author_signature(&self) -> bool {
        self.signature.verify(&self.hash, &self.author)
    }

    /// Validate the structure of transactions in the block (without UTXO validation)
    /// - Block must not be empty
    /// - First transaction must be coinbase
    /// - All other transactions must NOT be coinbase
    /// - No duplicate transactions
    pub fn validate_transaction_structure(&self) -> Result<(), BlockValidationError> {
        // Block must have at least one transaction
        if self.transactions.is_empty() {
            return Err(BlockValidationError::EmptyBlock);
        }

        // First transaction MUST be coinbase
        if !self.transactions[0].is_coinbase() {
            return Err(BlockValidationError::InvalidCoinbasePosition);
        }

        // All other transactions MUST NOT be coinbase
        for tx in self.transactions.iter().skip(1) {
            if tx.is_coinbase() {
                return Err(BlockValidationError::InvalidCoinbasePosition);
            }
        }

        // Check for duplicate transactions in the block
        let mut tx_hashes = HashSet::new();
        for tx in &self.transactions {
            let tx_hash = tx.hash();
            if !tx_hashes.insert(tx_hash) {
                return Err(BlockValidationError::DuplicateTransaction);
            }
        }

        Ok(())
    }

    /// Validate a regular block structure
    /// - Hash must be correct
    /// - Previous hash must match expected
    /// - Author signature must be valid
    /// - Transaction structure must be valid
    pub fn validate_structure(
        &self,
        expected_prev_hash: &Hash,
    ) -> Result<(), BlockValidationError> {
        if !self.verify_hash() {
            return Err(BlockValidationError::InvalidHash);
        }

        if !self.has_correct_prev_hash(expected_prev_hash) {
            return Err(BlockValidationError::InvalidPreviousHash);
        }

        if !self.verify_author_signature() {
            return Err(BlockValidationError::InvalidAuthorSignature);
        }

        self.validate_transaction_structure()?;

        Ok(())
    }

    /// Validate genesis block structure
    /// - Index must be 0
    /// - Previous hash must be zero
    /// - Hash must be correct
    /// - Author signature must be valid
    /// - Transaction structure must be valid
    pub fn validate_genesis_structure(&self) -> Result<(), BlockValidationError> {
        if self.index != 0 {
            return Err(BlockValidationError::InvalidGenesisIndex);
        }

        if self.prev_block_hash != Hash::zero() {
            return Err(BlockValidationError::InvalidGenesisPreHash);
        }

        if !self.verify_hash() {
            return Err(BlockValidationError::InvalidHash);
        }

        if !self.verify_author_signature() {
            return Err(BlockValidationError::InvalidAuthorSignature);
        }

        self.validate_transaction_structure()?;

        Ok(())
    }
}

#[cfg(test)]
mod tests;
