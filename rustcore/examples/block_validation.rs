//! Block Validation Example
//!
//! This example demonstrates:
//! - Creating and validating a blockchain with genesis block
//! - Creating blocks with transactions
//! - Validating block chains through the Blockchain API
//! - Detecting invalid blocks (wrong hash, duplicates, double-spend, etc.)
//! - Automatic UTXO set management by the blockchain

use rustcore::crypto::{Hash, KeyPair, Signature};
use rustcore::types::{Block, Blockchain, Transaction, TxInput, TxOutput};

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
    let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

    println!("Generated addresses:");
    println!("  Alice: {:02x?}...", &alice_address[..4]);
    println!("  Bob: {:02x?}...", &bob_address[..4]);
    println!("  Miner: {:02x?}...", &miner_address[..4]);
    println!("");

    // Create Genesis Block with coinbase transaction for Alice
    let genesis_coinbase = Transaction::new_coinbase(alice_address, 100);

    let genesis_block = Block::new_signed(
        0,
        Hash::zero(),
        Block::get_current_timestamp(),
        vec![genesis_coinbase.clone()],
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    let genesis_hash = genesis_block.hash();

    println!("Genesis Block created:");
    println!("  Index: {}", genesis_block.index);
    println!("  Hash: {}", genesis_hash);
    println!("  Prev Hash: {}", genesis_block.prev_block_hash);
    println!("  Transactions: {}", genesis_block.transactions.len());
    println!("");

    // Create blockchain with genesis block
    print!("Creating blockchain with genesis block... ");
    let mut blockchain =
        match Blockchain::new_blockchain("example_chain".to_string(), genesis_block) {
            Ok(bc) => {
                println!("SUCCESS");
                println!("Genesis Block validated and added to blockchain\n");
                bc
            }
            Err(e) => {
                println!("FAILED: {:?}\n", e);
                return;
            }
        };

    println!("Blockchain state after genesis:");
    println!("  Height: {}", blockchain.height());
    println!(
        "  Alice balance: {}",
        blockchain.get_balance(&alice_address)
    );
    println!("");

    // Create Transaction 1: Alice sends 50 to Bob, keeps 45 as change
    let genesis_coinbase_hash = genesis_coinbase.hash();
    let mut tx1 = Transaction::new(
        vec![TxInput {
            previous_tx_id: genesis_coinbase_hash.as_bytes(),
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

    // Validate transaction before adding to block
    print!("Validating transaction... ");
    match blockchain.validate_transaction(&tx1) {
        Ok(_) => println!("VALID"),
        Err(e) => {
            println!("INVALID: {:?}", e);
            return;
        }
    }
    println!("");

    // Create Block 1 with coinbase + transaction
    let block1_coinbase = Transaction::new_coinbase(miner_address, 55); // 50 reward + 5 fee

    let block_1 = Block::new_signed(
        1,
        genesis_hash,
        Block::get_current_timestamp(),
        vec![block1_coinbase.clone(), tx1.clone()],
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    let block_1_hash = block_1.hash();

    println!("Block 1 created:");
    println!("  Index: {}", block_1.index);
    println!("  Hash: {}", block_1_hash);
    println!("  Prev Hash: {}", block_1.prev_block_hash);
    println!(
        "  Transactions: {} (1 coinbase + 1 regular)",
        block_1.transactions.len()
    );
    println!("  Miner reward: 55 coins (50 base + 5 fee)");
    println!("");

    // Add Block 1 to blockchain
    print!("Adding Block 1 to blockchain... ");
    match blockchain.add_block(block_1.clone()) {
        Ok(_) => {
            println!("SUCCESS");
            println!("Block 1 validated and added to blockchain\n");
        }
        Err(e) => {
            println!("FAILED: {:?}\n", e);
            return;
        }
    }

    println!("Blockchain state after Block 1:");
    println!("  Height: {}", blockchain.height());
    println!(
        "  Alice balance: {}",
        blockchain.get_balance(&alice_address)
    );
    println!("  Bob balance: {}", blockchain.get_balance(&bob_address));
    println!(
        "  Miner balance: {}",
        blockchain.get_balance(&miner_address)
    );
    println!("");

    // Test idempotent add_block
    println!("Testing idempotent add_block (adding same block again):");
    print!("  Adding Block 1 again... ");
    match blockchain.add_block(block_1.clone()) {
        Ok(_) => {
            println!("SUCCESS (idempotent)");
            println!("  Height still: {}", blockchain.height());
        }
        Err(e) => {
            println!("ERROR: {:?}", e);
        }
    }
    println!("");

    // Test invalid block scenarios
    println!("============================================");
    println!("Testing Invalid Block Scenarios");
    println!("============================================\n");

    // Test 1: Block with wrong prev_hash
    println!("Test 1: Block with wrong prev_hash");
    let test_coinbase = Transaction::new_coinbase(miner_address, 50);
    let invalid_block_1 = Block::new_signed(
        2,
        Hash::zero(), // Wrong prev_hash!
        Block::get_current_timestamp(),
        vec![test_coinbase],
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    print!("  Adding to blockchain... ");
    match blockchain.add_block(invalid_block_1) {
        Ok(_) => println!("SUCCESS (unexpected)"),
        Err(e) => println!("REJECTED (expected): {:?}", e),
    }
    println!("");

    // Test 2: Block with duplicate transactions
    println!("Test 2: Block with duplicate transactions");
    let tx_hash = tx1.hash();
    let mut bob_tx = Transaction::new(
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
    bob_tx.sign_input(0, &bob_keypair.private_key).unwrap();

    let dup_coinbase = Transaction::new_coinbase(miner_address, 50);
    let invalid_block_2 = Block::new_signed(
        2,
        block_1_hash,
        Block::get_current_timestamp(),
        vec![dup_coinbase, bob_tx.clone(), bob_tx.clone()], // Duplicate transaction!
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    print!("  Adding to blockchain... ");
    match blockchain.add_block(invalid_block_2) {
        Ok(_) => println!("SUCCESS (unexpected)"),
        Err(e) => println!("REJECTED (expected): {:?}", e),
    }
    println!("");

    // Test 3: Block with double-spend (same UTXO used twice)
    println!("Test 3: Block with double-spend");
    let mut double_spend_tx = Transaction::new(
        vec![TxInput {
            previous_tx_id: tx_hash.as_bytes(),
            output_index: 0,
            signature: Signature::sign_output(&Hash::zero(), &bob_keypair.private_key),
            public_key: bob_keypair.public_key.clone(),
        }],
        vec![TxOutput {
            amount: 30,
            recipient: alice_address,
        }],
    );
    double_spend_tx
        .sign_input(0, &bob_keypair.private_key)
        .unwrap();

    let ds_coinbase = Transaction::new_coinbase(miner_address, 50);
    let invalid_block_3 = Block::new_signed(
        2,
        block_1_hash,
        Block::get_current_timestamp(),
        vec![ds_coinbase, bob_tx, double_spend_tx], // Both spend same UTXO!
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    print!("  Adding to blockchain... ");
    match blockchain.add_block(invalid_block_3) {
        Ok(_) => println!("SUCCESS (unexpected)"),
        Err(e) => println!("REJECTED (expected): {:?}", e),
    }
    println!("");

    // Test 4: Block without coinbase
    println!("Test 4: Block without coinbase transaction");
    let charlie_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);
    let mut alice_tx2 = Transaction::new(
        vec![TxInput {
            previous_tx_id: tx1.hash().as_bytes(),
            output_index: 1,
            signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
            public_key: alice_keypair.public_key.clone(),
        }],
        vec![TxOutput {
            amount: 20,
            recipient: charlie_address,
        }],
    );
    alice_tx2.sign_input(0, &alice_keypair.private_key).unwrap();

    let no_coinbase_block = Block::new_signed(
        2,
        block_1_hash,
        Block::get_current_timestamp(),
        vec![alice_tx2], // No coinbase!
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    print!("  Adding to blockchain... ");
    match blockchain.add_block(no_coinbase_block) {
        Ok(_) => println!("SUCCESS (unexpected)"),
        Err(e) => println!("REJECTED (expected): {:?}", e),
    }
    println!("");

    // Test 5: Block with invalid signature
    println!("Test 5: Block with invalid signature (wrong keypair)");
    let wrong_keypair = KeyPair::generate();
    let mut invalid_sig_tx = Transaction::new(
        vec![TxInput {
            previous_tx_id: tx1.hash().as_bytes(),
            output_index: 1,
            signature: Signature::sign_output(&Hash::zero(), &wrong_keypair.private_key),
            public_key: wrong_keypair.public_key.clone(), // Wrong public key!
        }],
        vec![TxOutput {
            amount: 20,
            recipient: charlie_address,
        }],
    );
    invalid_sig_tx
        .sign_input(0, &wrong_keypair.private_key)
        .unwrap();

    let invalid_sig_coinbase = Transaction::new_coinbase(miner_address, 50);
    let invalid_block_5 = Block::new_signed(
        2,
        block_1_hash,
        Block::get_current_timestamp(),
        vec![invalid_sig_coinbase, invalid_sig_tx],
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    print!("  Adding to blockchain... ");
    match blockchain.add_block(invalid_block_5) {
        Ok(_) => println!("SUCCESS (unexpected)"),
        Err(e) => println!("REJECTED (expected): {:?}", e),
    }
    println!("");

    // Test 6: Valid block to finalize
    println!("Test 6: Adding another valid block");
    let mut alice_tx_final = Transaction::new(
        vec![TxInput {
            previous_tx_id: tx1.hash().as_bytes(),
            output_index: 1,
            signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
            public_key: alice_keypair.public_key.clone(),
        }],
        vec![
            TxOutput {
                amount: 20,
                recipient: bob_address,
            },
            TxOutput {
                amount: 20,
                recipient: alice_address,
            },
        ],
    );
    alice_tx_final
        .sign_input(0, &alice_keypair.private_key)
        .unwrap();

    let final_coinbase = Transaction::new_coinbase(miner_address, 55);
    let block_2 = Block::new_signed(
        2,
        block_1_hash,
        Block::get_current_timestamp(),
        vec![final_coinbase, alice_tx_final],
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    print!("  Adding to blockchain... ");
    match blockchain.add_block(block_2) {
        Ok(_) => {
            println!("SUCCESS");
        }
        Err(e) => {
            println!("FAILED: {:?}", e);
        }
    }
    println!("");

    println!("============================================");
    println!("Final Blockchain State");
    println!("============================================");
    println!("  Height: {}", blockchain.height());
    println!(
        "  Alice balance: {}",
        blockchain.get_balance(&alice_address)
    );
    println!("  Bob balance: {}", blockchain.get_balance(&bob_address));
    println!(
        "  Miner balance: {}",
        blockchain.get_balance(&miner_address)
    );
    println!("");
    println!("All validation tests completed!");
    println!("============================================");
}
