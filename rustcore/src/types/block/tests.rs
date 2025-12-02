#[cfg(test)]
mod tests {
    use super::super::*;
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
            Block::get_current_timestamp(),
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
        let timestamp = Block::get_current_timestamp();

        let block1 = Block::new(
            0,
            prev_hash,
            timestamp,
            vec![coinbase_tx.clone()],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        let block2 = Block::new(
            0,
            prev_hash,
            timestamp,
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
            Block::get_current_timestamp(),
            vec![coinbase_tx1],
            keypair.public_key.clone(),
            Signature::sign_output(&prev_hash, &keypair.private_key),
        );

        let block2 = Block::new(
            0,
            prev_hash,
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
            Block::get_current_timestamp(),
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
