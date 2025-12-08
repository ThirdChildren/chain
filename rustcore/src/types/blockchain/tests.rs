#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::crypto::{Hash, KeyPair, Signature};
    use crate::types::{Block, Transaction, TxInput, TxOutput};

    #[test]
    fn test_create_blockchain() {
        let miner_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            Block::get_current_timestamp(),
            vec![coinbase_tx],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let blockchain_id = "test_blockchain_001".to_string();
        let blockchain = Blockchain::new_blockchain(blockchain_id.clone(), genesis_block).unwrap();

        assert!(!blockchain.is_empty());
        assert_eq!(blockchain.height(), 1);
        assert_eq!(blockchain.id, blockchain_id);
    }

    #[test]
    fn test_adding_block() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);

        let bob_keypair = KeyPair::generate();
        let bob_address = Transaction::public_key_to_address(&bob_keypair.public_key);

        let miner_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        let coinbase_tx = Transaction::new_coinbase(alice_address, 100);

        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            Block::get_current_timestamp(),
            vec![coinbase_tx.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let blockchain_id = "test_blockchain_001".to_string();
        let mut blockchain =
            Blockchain::new_blockchain(blockchain_id.clone(), genesis_block).unwrap();

        let genesis_coinbase_hash = coinbase_tx.hash();
        let mut tx1 = Transaction::new(
            vec![TxInput {
                previous_tx_id: genesis_coinbase_hash.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![
                TxOutput {
                    amount: 30,
                    recipient: bob_address,
                },
                TxOutput {
                    amount: 65,
                    recipient: alice_address,
                },
            ],
        );
        tx1.sign_input(0, &alice_keypair.private_key)
            .expect("Failed to sign transaction");

        let new_block_coinbase = Transaction::new_coinbase(miner_address, 55);

        let new_block = Block::new_signed(
            1,
            blockchain.get_block_by_index(0).unwrap().hash(),
            Block::get_current_timestamp(),
            vec![new_block_coinbase.clone(), tx1.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        blockchain.add_block(new_block).unwrap();
        assert_eq!(blockchain.height(), 2);

        assert_eq!(blockchain.get_balance(&alice_address), 65);
        assert_eq!(blockchain.get_balance(&bob_address), 30);
        assert_eq!(blockchain.get_balance(&miner_address), 55);
    }

    #[test]
    fn test_idempotent_add_block() {
        let miner_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        let coinbase_tx = Transaction::new_coinbase(miner_address, 50);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            Block::get_current_timestamp(),
            vec![coinbase_tx.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let mut blockchain =
            Blockchain::new_blockchain("test".to_string(), genesis_block.clone()).unwrap();

        let coinbase_tx2 = Transaction::new_coinbase(miner_address, 50);
        let block2 = Block::new_signed(
            1,
            genesis_block.hash(),
            Block::get_current_timestamp(),
            vec![coinbase_tx2],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        blockchain.add_block(block2.clone()).unwrap();
        assert_eq!(blockchain.height(), 2);

        blockchain.add_block(block2).unwrap();
        assert_eq!(blockchain.height(), 2);
    }

    #[test]
    fn test_double_spend_prevention() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);

        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);
        let charlie_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let miner_keypair = KeyPair::generate();

        let coinbase_tx = Transaction::new_coinbase(alice_address, 100);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            Block::get_current_timestamp(),
            vec![coinbase_tx.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let mut blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        let genesis_coinbase_hash = coinbase_tx.hash();

        let mut tx1 = Transaction::new(
            vec![TxInput {
                previous_tx_id: genesis_coinbase_hash.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 60,
                recipient: bob_address,
            }],
        );
        tx1.sign_input(0, &alice_keypair.private_key).unwrap();

        let mut tx2 = Transaction::new(
            vec![TxInput {
                previous_tx_id: genesis_coinbase_hash.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 60,
                recipient: charlie_address,
            }],
        );
        tx2.sign_input(0, &alice_keypair.private_key).unwrap();

        let coinbase_tx2 = Transaction::new_coinbase(alice_address, 50);

        let bad_block = Block::new_signed(
            1,
            blockchain.blocks[0].hash(),
            Block::get_current_timestamp(),
            vec![coinbase_tx2, tx1, tx2],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let result = blockchain.add_block(bad_block);
        assert!(matches!(result, Err(ValidationError::DoubleSpend)));
    }

    #[test]
    fn test_validate_transaction() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);
        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);
        let miner_keypair = KeyPair::generate();

        let coinbase_tx = Transaction::new_coinbase(alice_address, 100);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            Block::get_current_timestamp(),
            vec![coinbase_tx.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        let mut valid_tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: coinbase_tx.hash().as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 50,
                recipient: bob_address,
            }],
        );
        valid_tx.sign_input(0, &alice_keypair.private_key).unwrap();

        assert!(blockchain.validate_transaction(&valid_tx).is_ok());

        let mut invalid_tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: coinbase_tx.hash().as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 150,
                recipient: bob_address,
            }],
        );
        invalid_tx
            .sign_input(0, &alice_keypair.private_key)
            .unwrap();

        assert!(blockchain.validate_transaction(&invalid_tx).is_err());
    }

    #[test]
    fn test_create_block_from_mempool() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);

        let bob_keypair = KeyPair::generate();
        let bob_address = Transaction::public_key_to_address(&bob_keypair.public_key);

        let charlie_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let miner_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        // Create genesis block with funds for Alice
        let genesis_coinbase = Transaction::new_coinbase(alice_address, 200);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            Block::get_current_timestamp(),
            vec![genesis_coinbase.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let mut blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        // Create and submit three transactions with different fees
        let genesis_hash = genesis_coinbase.hash();

        // TX1: Alice -> Bob, 50 coins, fee = 10 (input 200, output 50+140)
        let mut tx1 = Transaction::new(
            vec![TxInput {
                previous_tx_id: genesis_hash.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![
                TxOutput {
                    amount: 50,
                    recipient: bob_address,
                },
                TxOutput {
                    amount: 140, // Change back to Alice
                    recipient: alice_address,
                },
            ],
        );
        tx1.sign_input(0, &alice_keypair.private_key).unwrap();
        blockchain.submit_transaction(tx1.clone()).unwrap();

        // Simulate second UTXO for Alice (this won't be in UTXO set, so we skip it)
        // Instead, we'll test with transactions that conflict

        // TX2: Alice -> Charlie, trying to spend same UTXO, fee = 20 (higher fee)
        let mut tx2 = Transaction::new(
            vec![TxInput {
                previous_tx_id: genesis_hash.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![
                TxOutput {
                    amount: 60,
                    recipient: charlie_address,
                },
                TxOutput {
                    amount: 120, // Change back to Alice
                    recipient: alice_address,
                },
            ],
        );
        tx2.sign_input(0, &alice_keypair.private_key).unwrap();
        blockchain.submit_transaction(tx2.clone()).unwrap();

        // Verify mempool has 2 transactions
        assert_eq!(blockchain.mempool.current_size(), 2);

        // Create block from mempool
        let new_block = blockchain.create_block(
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
            10, // max 10 transactions
        );

        // Verify block structure
        assert_eq!(new_block.index, 1);
        assert_eq!(new_block.prev_block_hash, blockchain.blocks[0].hash());

        // First transaction must be coinbase
        assert!(new_block.transactions[0].is_coinbase());

        // Coinbase should have reward (50) + fee from selected tx (20 from tx2)
        assert_eq!(new_block.transactions[0].outputs[0].amount, 70);
        assert_eq!(
            new_block.transactions[0].outputs[0].recipient,
            miner_address
        );

        // Should have selected only one transaction (tx2, higher fee, no conflict)
        assert_eq!(new_block.transactions.len(), 2); // coinbase + 1 tx

        // The selected transaction should be tx2 (higher fee)
        assert_eq!(new_block.transactions[1].outputs[0].amount, 60);
        assert_eq!(
            new_block.transactions[1].outputs[0].recipient,
            charlie_address
        );

        // Add block to blockchain
        blockchain.add_block(new_block).unwrap();

        // Verify mempool is cleaned up (both transactions removed as invalid)
        assert_eq!(blockchain.mempool.current_size(), 0);

        // Verify balances
        assert_eq!(blockchain.get_balance(&alice_address), 120);
        assert_eq!(blockchain.get_balance(&charlie_address), 60);
        assert_eq!(blockchain.get_balance(&miner_address), 70);
    }

    #[test]
    fn test_create_block_empty_mempool() {
        let miner_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        let genesis_coinbase = Transaction::new_coinbase(miner_address, 100);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            Block::get_current_timestamp(),
            vec![genesis_coinbase],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        // Mempool is empty
        assert!(blockchain.mempool.is_empty());

        // Create block should work with empty mempool
        let new_block = blockchain.create_block(
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
            10,
        );

        // Should only contain coinbase
        assert_eq!(new_block.transactions.len(), 1);
        assert!(new_block.transactions[0].is_coinbase());

        // Coinbase should have only block reward (no fees)
        assert_eq!(new_block.transactions[0].outputs[0].amount, 50);
    }

    #[test]
    fn test_create_block_respects_max_transactions() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);

        let miner_keypair = KeyPair::generate();
        let _miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        // Create genesis with multiple UTXOs for Alice
        let genesis_coinbase = Transaction::new_coinbase(alice_address, 1000);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            Block::get_current_timestamp(),
            vec![genesis_coinbase.clone()],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let mut blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        // We can only create one transaction from genesis UTXO
        // But we can test the max_transactions parameter with limit of 0
        let mut tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: genesis_coinbase.hash().as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 995,
                recipient: alice_address,
            }],
        );
        tx.sign_input(0, &alice_keypair.private_key).unwrap();
        blockchain.submit_transaction(tx).unwrap();

        // Create block with max_transactions = 0
        let block = blockchain.create_block(
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
            0, // No regular transactions
        );

        // Should only have coinbase
        assert_eq!(block.transactions.len(), 1);
        assert!(block.transactions[0].is_coinbase());
    }
}
