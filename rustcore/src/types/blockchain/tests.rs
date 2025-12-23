#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::crypto::{Hash, KeyPair};
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

        let blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        assert_eq!(blockchain.id, "test");
        assert_eq!(blockchain.blocks.len(), 1);
        assert_eq!(blockchain.height(), 1);
        assert!(!blockchain.is_empty());
        assert_eq!(blockchain.get_balance(&miner_address), 50);
    }

    #[test]
    fn test_adding_block() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);
        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);
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

        let mut blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        let genesis_coinbase_hash = coinbase_tx.hash();
        let mut tx1 = Transaction::new(
            vec![TxInput::unsigned(genesis_coinbase_hash.as_bytes(), 0)],
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
        tx1.sign_input(0, &alice_keypair.private_key).unwrap();

        let new_block_coinbase = Transaction::new_coinbase(miner_address, 55);

        let new_block = Block::new_signed(
            1,
            blockchain.get_block_by_index(0).unwrap().hash(),
            Block::get_current_timestamp(),
            vec![new_block_coinbase, tx1],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        blockchain.add_block(new_block).unwrap();

        assert_eq!(blockchain.blocks.len(), 2);
        assert_eq!(blockchain.height(), 2);
        assert_eq!(blockchain.get_balance(&alice_address), 65);
        assert_eq!(blockchain.get_balance(&bob_address), 30);
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

        let mut blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        let coinbase_tx2 = Transaction::new_coinbase(miner_address, 50);
        let block2 = Block::new_signed(
            1,
            blockchain.blocks[0].hash(),
            Block::get_current_timestamp(),
            vec![coinbase_tx2],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        blockchain.add_block(block2.clone()).unwrap();
        assert_eq!(blockchain.blocks.len(), 2);

        blockchain.add_block(block2).unwrap();
        assert_eq!(blockchain.blocks.len(), 2);
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
            vec![TxInput::unsigned(genesis_coinbase_hash.as_bytes(), 0)],
            vec![TxOutput {
                amount: 60,
                recipient: bob_address,
            }],
        );
        tx1.sign_input(0, &alice_keypair.private_key).unwrap();

        let mut tx2 = Transaction::new(
            vec![TxInput::unsigned(genesis_coinbase_hash.as_bytes(), 0)],
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
            vec![TxInput::unsigned(coinbase_tx.hash().as_bytes(), 0)],
            vec![TxOutput {
                amount: 50,
                recipient: bob_address,
            }],
        );
        valid_tx.sign_input(0, &alice_keypair.private_key).unwrap();

        assert!(blockchain.validate_transaction(&valid_tx).is_ok());

        let mut invalid_tx = Transaction::new(
            vec![TxInput::unsigned(coinbase_tx.hash().as_bytes(), 0)],
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
        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);
        let charlie_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let miner_keypair = KeyPair::generate();
        let _miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

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

        let genesis_hash = genesis_coinbase.hash();

        // tx1 and tx2 both spend the same UTXO - they conflict!
        let mut tx1 = Transaction::new(
            vec![TxInput::unsigned(genesis_hash.as_bytes(), 0)],
            vec![
                TxOutput {
                    amount: 50,
                    recipient: bob_address,
                },
                TxOutput {
                    amount: 140,
                    recipient: alice_address,
                },
            ],
        );
        tx1.sign_input(0, &alice_keypair.private_key).unwrap();

        blockchain.submit_transaction(tx1.clone()).unwrap();

        let mut tx2 = Transaction::new(
            vec![TxInput::unsigned(genesis_hash.as_bytes(), 0)],
            vec![
                TxOutput {
                    amount: 60,
                    recipient: charlie_address,
                },
                TxOutput {
                    amount: 120,
                    recipient: alice_address,
                },
            ],
        );
        tx2.sign_input(0, &alice_keypair.private_key).unwrap();

        blockchain.submit_transaction(tx2.clone()).unwrap();

        assert_eq!(blockchain.mempool.len(), 2);

        // create_block will select only ONE tx (highest fee)
        let block = blockchain.create_block(
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
            10,
        );

        // Block should have: coinbase + 1 selected tx (not both, due to conflict)
        assert_eq!(block.transactions.len(), 2);
        assert!(block.transactions[0].is_coinbase());

        let coinbase_amount: u64 = block.transactions[0].outputs.iter().map(|o| o.amount).sum();
        assert!(coinbase_amount > 50);

        blockchain.add_block(block).unwrap();

        assert_eq!(blockchain.mempool.len(), 0);
    }

    #[test]
    fn test_create_block_respects_max_transactions() {
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);

        let miner_keypair = KeyPair::generate();
        let _miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

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

        let mut tx = Transaction::new(
            vec![TxInput::unsigned(genesis_coinbase.hash().as_bytes(), 0)],
            vec![TxOutput {
                amount: 995,
                recipient: alice_address,
            }],
        );
        tx.sign_input(0, &alice_keypair.private_key).unwrap();

        blockchain.submit_transaction(tx).unwrap();

        assert_eq!(blockchain.mempool.len(), 1);

        let block = blockchain.create_block(
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
            0,
        );

        assert_eq!(block.transactions.len(), 1);
        assert!(block.transactions[0].is_coinbase());
    }

    #[test]
    fn test_submit_transaction_to_mempool() {
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

        let mut blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();

        let mut tx = Transaction::new(
            vec![TxInput::unsigned(coinbase_tx.hash().as_bytes(), 0)],
            vec![TxOutput {
                amount: 50,
                recipient: bob_address,
            }],
        );
        tx.sign_input(0, &alice_keypair.private_key).unwrap();

        assert_eq!(blockchain.mempool.len(), 0);
        blockchain.submit_transaction(tx).unwrap();
        assert_eq!(blockchain.mempool.len(), 1);
    }

    #[test]
    fn test_try_attach_pending_blocks() {
        let miner_keypair = KeyPair::generate();
        let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

        // Create genesis block (index 0)
        let genesis_coinbase = Transaction::new_coinbase(miner_address, 50);
        let genesis_block = Block::new_signed(
            0,
            Hash::zero(),
            Block::get_current_timestamp(),
            vec![genesis_coinbase],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        let mut blockchain = Blockchain::new_blockchain("test".to_string(), genesis_block).unwrap();
        assert_eq!(blockchain.height(), 1);

        // Create block 1
        let block1_coinbase = Transaction::new_coinbase(miner_address, 50);
        let block1 = Block::new_signed(
            1,
            blockchain.blocks[0].hash(),
            Block::get_current_timestamp() + 1,
            vec![block1_coinbase],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        // Add block 1 normally
        blockchain.add_block(block1).unwrap();
        assert_eq!(blockchain.height(), 2);

        // Create block 2 (the missing link)
        let block2_coinbase = Transaction::new_coinbase(miner_address, 50);
        let block2 = Block::new_signed(
            2,
            blockchain.blocks[1].hash(),
            Block::get_current_timestamp() + 2,
            vec![block2_coinbase],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        // Create block 3 with correct prev_hash pointing to block2
        let block3_coinbase = Transaction::new_coinbase(miner_address, 50);
        let block3 = Block::new_signed(
            3,
            block2.hash(),
            Block::get_current_timestamp() + 3,
            vec![block3_coinbase],
            miner_keypair.public_key.clone(),
            &miner_keypair.private_key,
        );

        // Add block 3 to pending blocks (it can't be added yet because block 2 is missing)
        blockchain.add_pending_block(block3.clone());
        assert_eq!(blockchain.height(), 2); // Still at height 2
        assert_eq!(blockchain.pending_blocks.len(), 1);

        // Try to attach pending blocks - should fail because block 2 is missing
        blockchain.try_attach_pending_blocks();
        assert_eq!(blockchain.height(), 2); // Still at height 2
        assert_eq!(blockchain.pending_blocks.len(), 1); // Block 3 still pending

        // Now add block 2
        blockchain.add_block(block2).unwrap();
        assert_eq!(blockchain.height(), 3);

        // Try to attach pending blocks - now block 3 should be attached
        blockchain.try_attach_pending_blocks();
        assert_eq!(blockchain.height(), 4); // Block 3 was attached!
        assert_eq!(blockchain.pending_blocks.len(), 0); // No more pending blocks

        // Verify the chain is correct
        assert_eq!(blockchain.get_block_by_index(0).unwrap().index, 0);
        assert_eq!(blockchain.get_block_by_index(1).unwrap().index, 1);
        assert_eq!(blockchain.get_block_by_index(2).unwrap().index, 2);
        assert_eq!(blockchain.get_block_by_index(3).unwrap().index, 3)
    }
}
