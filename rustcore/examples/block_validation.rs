//! Block Validation Example
//!
//! This example demonstrates:
//! - Creating and validating a genesis block
//! - Creating blocks with transactions
//! - Validating block chains
//! - Detecting invalid blocks (wrong hash, duplicates, double-spend, etc.)
//! - Progressive UTXO set updates

use rustcore::crypto::{Hash, KeyPair, Signature};
use rustcore::types::block::Block;
use rustcore::types::transaction::{Transaction, TxInput, TxOutput, UTXOSet};
use std::collections::HashMap;

fn main() {
    println!("============================================");
    println!("Block Validation Example");
    println!("============================================\n");

    // Generate keypairs for Alice, Bob, and Miner
    let alice_keypair = KeyPair::generate();
    let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);

    let bob_keypair = KeyPair::generate();
    let bob_address = Transaction::public_key_to_address(&bob_keypair.public_key);

    let miner_keypair = KeyPair::generate();

    println!("Generated addresses:");
    println!("  Alice: {:02x?}...", &alice_address[..4]);
    println!("  Bob: {:02x?}...", &bob_address[..4]);
    println!("");

    // Create initial UTXO set with coinbase transaction for Alice
    let mut utxo_set: UTXOSet = HashMap::new();
    let coinbase_tx_hash = Hash::hash(b"genesis_coinbase");
    let coinbase_output = TxOutput {
        amount: 100,
        recipient: alice_address,
    };
    utxo_set.insert((coinbase_tx_hash, 0), coinbase_output);

    println!("Initial UTXO set:");
    println!("  Alice has 100 coins from coinbase\n");

    // Create Genesis Block (empty transactions for simplicity)
    let genesis_block = Block::new(
        0,
        Hash::zero(),
        1000000,
        vec![],
        miner_keypair.public_key.clone(),
        Signature::sign_output(&Hash::zero(), &miner_keypair.private_key),
    );

    let genesis_hash = genesis_block.hash();

    println!("Genesis Block created:");
    println!("  Index: {}", genesis_block.index);
    println!("  Hash: {}", genesis_hash);
    println!("  Prev Hash: {}", genesis_block.prev_block_hash);
    println!("  Transactions: {}", genesis_block.transactions.len());
    println!("");

    // Note: Genesis block validation skipped as it has no transactions
    // In a real blockchain, genesis would have coinbase transaction
    println!("Genesis Block accepted (no transactions to validate)\n");

    // Create Transaction 1: Alice sends 50 to Bob
    let mut tx1 = Transaction::new(
        vec![TxInput {
            previous_tx_id: coinbase_tx_hash.as_bytes(),
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
                amount: 45,
                recipient: alice_address,
            },
        ],
    );

    tx1.sign_input(0, &alice_keypair.private_key)
        .expect("Failed to sign transaction");

    println!("Transaction 1 created:");
    println!("  Alice sends 50 coins to Bob");
    println!("  Alice receives 45 coins as change");
    println!("  Fee: 5 coins");
    println!("  Hash: {}", tx1.hash());
    println!("");

    // Create Block 1
    let block_1 = Block::new(
        1,
        genesis_hash,
        1000100,
        vec![tx1.clone()],
        miner_keypair.public_key.clone(),
        Signature::sign_output(&Hash::hash(b"block_1_data"), &miner_keypair.private_key),
    );

    let block_1_hash = block_1.hash();

    println!("Block 1 created:");
    println!("  Index: {}", block_1.index);
    println!("  Hash: {}", block_1_hash);
    println!("  Prev Hash: {}", block_1.prev_block_hash);
    println!("  Transactions: {}", block_1.transactions.len());
    println!("");

    // Validate Block 1
    println!("Validating Block 1:");

    print!("  Hash verification... ");
    if block_1.verify_hash(&block_1_hash) {
        println!("PASS");
    } else {
        println!("FAIL");
    }

    print!("  Prev hash check... ");
    if block_1.has_prev_hash(&genesis_hash) {
        println!("PASS");
    } else {
        println!("FAIL");
    }

    print!("  Transactions validity... ");
    if block_1.are_valid_transactions(&utxo_set) {
        println!("PASS");
    } else {
        println!("FAIL");
    }

    print!("  Complete validation... ");
    if block_1.is_valid_block(&genesis_hash, &utxo_set, &block_1_hash) {
        println!("PASS");
        println!("");
        println!("Block 1 is fully valid!");

        // Apply transactions to UTXO set
        for tx in &block_1.transactions {
            tx.apply_to_utxo_set(&mut utxo_set)
                .expect("Failed to apply transaction");
        }
        println!("UTXO set updated with Block 1 transactions");
    } else {
        println!("FAIL");
        println!("Block 1 validation failed!");
    }
    println!("");

    // Test invalid block scenarios
    println!("============================================");
    println!("Testing Invalid Block Scenarios");
    println!("============================================\n");

    // Test 1: Block with wrong prev_hash
    println!("Test 1: Block with wrong prev_hash");
    let invalid_block_1 = Block::new(
        2,
        Hash::zero(),
        1000200,
        vec![],
        miner_keypair.public_key.clone(),
        Signature::sign_output(&Hash::zero(), &miner_keypair.private_key),
    );
    let invalid_hash_1 = invalid_block_1.hash();

    print!("  Validation result... ");
    if invalid_block_1.is_valid_block(&block_1_hash, &utxo_set, &invalid_hash_1) {
        println!("PASS (unexpected)");
    } else {
        println!("FAIL (expected)");
    }
    println!("");

    // Test 2: Block with duplicate transactions
    println!("Test 2: Block with duplicate transactions");
    let invalid_block_2 = Block::new(
        2,
        block_1_hash,
        1000200,
        vec![tx1.clone(), tx1.clone()],
        miner_keypair.public_key.clone(),
        Signature::sign_output(&Hash::zero(), &miner_keypair.private_key),
    );

    print!("  Transactions validation... ");
    if invalid_block_2.are_valid_transactions(&utxo_set) {
        println!("PASS (unexpected)");
    } else {
        println!("FAIL (expected - duplicates detected)");
    }
    println!("");

    // Test 3: Block with double-spend
    println!("Test 3: Block with double-spend");
    let tx_hash = tx1.hash();
    let mut double_spend_tx1 = Transaction::new(
        vec![TxInput {
            previous_tx_id: tx_hash.as_bytes(),
            output_index: 0,
            signature: Signature::sign_output(&Hash::zero(), &bob_keypair.private_key),
            public_key: bob_keypair.public_key.clone(),
        }],
        vec![TxOutput {
            amount: 25,
            recipient: alice_address,
        }],
    );
    double_spend_tx1
        .sign_input(0, &bob_keypair.private_key)
        .expect("Failed to sign");

    let mut double_spend_tx2 = Transaction::new(
        vec![TxInput {
            previous_tx_id: tx_hash.as_bytes(),
            output_index: 0,
            signature: Signature::sign_output(&Hash::zero(), &bob_keypair.private_key),
            public_key: bob_keypair.public_key.clone(),
        }],
        vec![TxOutput {
            amount: 25,
            recipient: alice_address,
        }],
    );
    double_spend_tx2
        .sign_input(0, &bob_keypair.private_key)
        .expect("Failed to sign");

    let invalid_block_3 = Block::new(
        2,
        block_1_hash,
        1000200,
        vec![double_spend_tx1, double_spend_tx2],
        miner_keypair.public_key.clone(),
        Signature::sign_output(&Hash::zero(), &miner_keypair.private_key),
    );

    print!("  Transactions validation... ");
    if invalid_block_3.are_valid_transactions(&utxo_set) {
        println!("PASS (unexpected)");
    } else {
        println!("FAIL (expected - double-spend detected)");
    }
    println!("");

    // Test 4: Block with wrong hash verification
    println!("Test 4: Block with wrong hash claim");
    let valid_structure_block = Block::new(
        2,
        block_1_hash,
        1000200,
        vec![],
        miner_keypair.public_key.clone(),
        Signature::sign_output(&Hash::zero(), &miner_keypair.private_key),
    );
    let wrong_hash = Hash::hash(b"wrong_hash");

    print!("  Hash verification... ");
    if valid_structure_block.verify_hash(&wrong_hash) {
        println!("PASS (unexpected)");
    } else {
        println!("FAIL (expected - hash mismatch)");
    }
    println!("");

    // Test 5: Genesis block with non-zero prev_hash
    println!("Test 5: Invalid genesis block");
    let invalid_genesis = Block::new(
        0,
        Hash::hash(b"non_zero"),
        1000000,
        vec![],
        miner_keypair.public_key.clone(),
        Signature::sign_output(&Hash::zero(), &miner_keypair.private_key),
    );
    let invalid_genesis_hash = invalid_genesis.hash();

    print!("  Genesis validation... ");
    if invalid_genesis.is_valid_genesis(&utxo_set, &invalid_genesis_hash) {
        println!("PASS (unexpected)");
    } else {
        println!("FAIL (expected - non-zero prev_hash)");
    }
    println!("");

    println!("============================================");
    println!("All validation tests completed!");
    println!("============================================");
}
