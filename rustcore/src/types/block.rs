use crate::crypto::signature::backend::CryptoKey;
use crate::crypto::{Hash, PublicKey, Signature};
use crate::types::transaction::Transaction;
use std::collections::HashSet;

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

    /// Create a new block with proper signature over the block hash
    /// This is a convenience method that creates the block and signs it correctly
    pub fn new_signed(
        index: u32,
        prev_block_hash: Hash,
        timestamp: u128,
        transactions: Vec<Transaction>,
        author: PublicKey,
        author_private_key: &crate::crypto::PrivateKey,
    ) -> Self {
        // Create block with temporary signature
        let mut block = Block {
            hash: Hash::zero(),
            index,
            prev_block_hash,
            timestamp,
            transactions,
            author: author.clone(),
            signature: Signature::sign_output(&Hash::zero(), author_private_key),
        };
        block.hash = block.calculate_hash();

        // Sign with the actual block hash
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
mod tests {
    use super::*;
    use crate::crypto::KeyPair;
    use crate::types::{Transaction, TxInput, TxOutput};

    #[test]
    fn test_block_creation() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);

        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let prev_hash = Hash::zero();

        let block = Block::new(
            0,
            prev_hash,
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        assert_eq!(block.index, 0);
        assert_eq!(block.prev_block_hash, prev_hash);
        assert_eq!(block.transactions.len(), 1);
    }

    #[test]
    fn test_block_hash() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);

        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let prev_hash = Hash::zero();

        let block1 = Block::new(
            0,
            prev_hash,
            1000000,
            vec![coinbase_tx.clone()],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        let block2 = Block::new(
            0,
            prev_hash,
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        // Same content should produce same hash
        assert_eq!(block1.hash(), block2.hash());
    }

    #[test]
    fn test_block_hash_differs_with_different_content() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);

        let coinbase_tx1 = Transaction::new_coinbase(miner_address, 50);
        let coinbase_tx2 = Transaction::new_coinbase(miner_address, 100);
        let prev_hash = Hash::zero();

        let block1 = Block::new(
            0,
            prev_hash,
            1000000,
            vec![coinbase_tx1],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        let block2 = Block::new(
            0,
            prev_hash,
            1000000,
            vec![coinbase_tx2],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        // Different transactions should produce different hashes
        assert_ne!(block1.hash(), block2.hash());
    }

    #[test]
    fn test_verify_hash() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);
        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);

        let block = Block::new(
            0,
            Hash::zero(),
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            Signature::sign_output(&Hash::zero(), &keypair.private_key),
        );

        assert!(block.verify_hash());
    }

    #[test]
    fn test_verify_author_signature() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);
        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let prev_hash = Hash::zero();

        let block = Block::new(
            0,
            prev_hash,
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        // Should fail because signature was over prev_hash, not block hash
        assert!(!block.verify_author_signature());

        // Create block with correct signature
        let coinbase_tx2 = Transaction::new_coinbase(miner_address, 50);
        let mut temp_block = Block::new(
            0,
            prev_hash,
            1000000,
            vec![coinbase_tx2],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        // Sign with the actual block hash
        temp_block.signature = Signature::sign_output(&temp_block.hash, &keypair.private_key);

        assert!(temp_block.verify_author_signature());
    }

    #[test]
    fn test_has_correct_prev_hash() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);
        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let prev_hash = Hash::hash(b"previous_block");

        let block = Block::new(
            1,
            prev_hash,
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        assert!(block.has_correct_prev_hash(&prev_hash));
        assert!(!block.has_correct_prev_hash(&Hash::zero()));
    }

    #[test]
    fn test_validate_transaction_structure_valid() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);

        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let regular_tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: [1u8; 32],
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &keypair.private_key),
                public_key: keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 30,
                recipient: miner_address,
            }],
        );

        let block = Block::new_signed(
            1,
            Hash::zero(),
            1000000,
            vec![coinbase_tx, regular_tx],
            keypair.public_key.clone(),
            &keypair.private_key,
        );

        assert!(block.validate_transaction_structure().is_ok());
    }

    #[test]
    fn test_validate_transaction_structure_empty_block() {
        let keypair = KeyPair::generate();

        let block = Block::new(
            1,
            Hash::zero(),
            1000000,
            vec![], // Empty!
            keypair.public_key.clone(),
            Signature::sign_output(&Hash::zero(), &keypair.private_key),
        );

        assert!(matches!(
            block.validate_transaction_structure(),
            Err(BlockValidationError::EmptyBlock)
        ));
    }

    #[test]
    fn test_validate_transaction_structure_no_coinbase() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);

        let regular_tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: [1u8; 32],
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &keypair.private_key),
                public_key: keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 30,
                recipient: miner_address,
            }],
        );

        let block = Block::new(
            1,
            Hash::zero(),
            1000000,
            vec![regular_tx], // No coinbase!
            keypair.public_key.clone(),
            Signature::sign_output(&Hash::zero(), &keypair.private_key),
        );

        assert!(matches!(
            block.validate_transaction_structure(),
            Err(BlockValidationError::InvalidCoinbasePosition)
        ));
    }

    #[test]
    fn test_validate_transaction_structure_multiple_coinbase() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);

        let coinbase_tx1 = Transaction::new_coinbase(miner_address, 50);
        let coinbase_tx2 = Transaction::new_coinbase(miner_address, 50);

        let block = Block::new(
            1,
            Hash::zero(),
            1000000,
            vec![coinbase_tx1, coinbase_tx2], // Two coinbase!
            keypair.public_key.clone(),
            Signature::sign_output(&Hash::zero(), &keypair.private_key),
        );

        assert!(matches!(
            block.validate_transaction_structure(),
            Err(BlockValidationError::InvalidCoinbasePosition)
        ));
    }

    #[test]
    fn test_validate_transaction_structure_duplicate_tx() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);

        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let regular_tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: [1u8; 32],
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &keypair.private_key),
                public_key: keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 30,
                recipient: miner_address,
            }],
        );

        let block = Block::new(
            1,
            Hash::zero(),
            1000000,
            vec![coinbase_tx, regular_tx.clone(), regular_tx.clone()], // Duplicate!
            keypair.public_key.clone(),
            Signature::sign_output(&Hash::zero(), &keypair.private_key),
        );

        assert!(matches!(
            block.validate_transaction_structure(),
            Err(BlockValidationError::DuplicateTransaction)
        ));
    }

    #[test]
    fn test_validate_genesis_structure_valid() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);
        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);

        let block = Block::new_signed(
            0,
            Hash::zero(),
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            &keypair.private_key,
        );

        assert!(block.validate_genesis_structure().is_ok());
    }

    #[test]
    fn test_validate_genesis_structure_wrong_index() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);
        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);

        let block = Block::new(
            1, // Should be 0!
            Hash::zero(),
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            Signature::sign_output(&Hash::zero(), &keypair.private_key),
        );

        assert!(matches!(
            block.validate_genesis_structure(),
            Err(BlockValidationError::InvalidGenesisIndex)
        ));
    }

    #[test]
    fn test_validate_genesis_structure_non_zero_prev_hash() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);
        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);

        let block = Block::new(
            0,
            Hash::hash(b"non_zero"), // Should be zero!
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            Signature::sign_output(&Hash::zero(), &keypair.private_key),
        );

        assert!(matches!(
            block.validate_genesis_structure(),
            Err(BlockValidationError::InvalidGenesisPreHash)
        ));
    }

    #[test]
    fn test_validate_structure_valid() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);
        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let prev_hash = Hash::hash(b"previous");

        let block = Block::new_signed(
            1,
            prev_hash,
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            &keypair.private_key,
        );

        assert!(block.validate_structure(&prev_hash).is_ok());
    }

    #[test]
    fn test_validate_structure_wrong_prev_hash() {
        let keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);
        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let prev_hash = Hash::hash(b"previous");
        let wrong_hash = Hash::hash(b"wrong");

        let block = Block::new(
            1,
            prev_hash,
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        assert!(matches!(
            block.validate_structure(&wrong_hash),
            Err(BlockValidationError::InvalidPreviousHash)
        ));
    }

    #[test]
    fn test_validate_structure_invalid_author_signature() {
        let keypair = KeyPair::generate();
        let wrong_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&keypair.public_key);
        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let prev_hash = Hash::hash(b"previous");

        // Create block with wrong signature
        let mut block = Block::new(
            1,
            prev_hash,
            1000000,
            vec![coinbase_tx],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        // Replace with wrong signature
        block.signature = Signature::sign_output(&block.hash, &wrong_keypair.private_key);

        assert!(matches!(
            block.validate_structure(&prev_hash),
            Err(BlockValidationError::InvalidAuthorSignature)
        ));
    }
}
