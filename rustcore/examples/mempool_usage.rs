//! Mempool Usage Example
//!
//! This example demonstrates:
//! - Creating and managing a transaction mempool
//! - Adding valid transactions to the mempool
//! - Rejecting invalid transactions (coinbase, zero fee, etc.)
//! - Managing mempool size limits
//! - Retrieving transactions sorted by fee (for mining)
//! - Removing transactions after they're included in blocks

use rustcore::crypto::{Hash, KeyPair};
use rustcore::types::{Mempool, Transaction, TxInput, TxOutput, UTXOSet, Utxo, UtxoRef};

fn main() {
    println!("============================================");
    println!("Mempool Usage Example");
    println!("============================================\n");

    // 1. Create a mempool with default capacity (100 transactions)
    let mut mempool = Mempool::new();
    println!("Mempool created with capacity: {}", mempool.max_size);
    println!("Current size: {}", mempool.len());
    println!("");

    // 2. Create UTXO set for transaction validation
    let mut utxo_set = UTXOSet::new();

    // 3. Setup test accounts
    let alice_keypair = KeyPair::generate();
    let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);

    let bob_keypair = KeyPair::generate();
    let bob_address = Transaction::public_key_to_address(&bob_keypair.public_key);

    let charlie_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

    println!("Generated addresses:");
    println!("  Alice: {:02x?}...", &alice_address[..8]);
    println!("  Bob: {:02x?}...", &bob_address[..8]);
    println!("  Charlie: {:02x?}...", &charlie_address[..8]);
    println!("");

    // 4. Add some UTXOs for Alice to spend
    let prev_tx1 = Hash::hash(b"genesis_tx_alice_1");
    let utxo_ref1 = UtxoRef::from_bytes(prev_tx1.as_bytes(), 0);
    utxo_set.add(utxo_ref1, Utxo::new(100, alice_address));

    let prev_tx2 = Hash::hash(b"genesis_tx_alice_2");
    let utxo_ref2 = UtxoRef::from_bytes(prev_tx2.as_bytes(), 0);
    utxo_set.add(utxo_ref2, Utxo::new(50, alice_address));

    println!("Added UTXOs for Alice:");
    println!("  UTXO 1: 100 coins");
    println!("  UTXO 2: 50 coins");
    println!("  Total: 150 coins\n");

    // 5. Create and add a valid transaction with fee 10
    println!("Test 1: Adding valid transaction (Alice → Bob, 90 coins, fee 10)");
    let mut tx1 = Transaction::new(
        vec![TxInput::unsigned(prev_tx1.as_bytes(), 0)],
        vec![TxOutput {
            amount: 90,
            recipient: bob_address,
        }],
    );
    tx1.sign_input(0, &alice_keypair.private_key).unwrap();

    let fee1 = tx1.calculate_fee(&utxo_set).unwrap();
    match mempool.add_entry(tx1.clone(), fee1) {
        Ok(_) => {
            println!("  ✓ Transaction added successfully");
            println!("  Transaction fee: {} coins", fee1);
        }
        Err(e) => println!("  ✗ Failed to add: {:?}", e),
    }
    println!("  Mempool size: {}\n", mempool.len());

    // 6. Try to add a coinbase transaction (should fail)
    println!("Test 2: Attempting to add coinbase transaction");
    let coinbase = Transaction::new_coinbase(bob_address, 50, 0);
    match mempool.add_entry(coinbase, 0) {
        Ok(_) => println!("  ✗ ERROR: Coinbase accepted (should be rejected)"),
        Err(e) => println!("  ✓ Correctly rejected: {:?}", e),
    }
    println!("  Mempool size: {}\n", mempool.len());

    // 7. Create transaction with higher fee
    println!("Test 3: Adding transaction with higher fee (Alice → Charlie, 30 coins, fee 20)");
    let mut tx2 = Transaction::new(
        vec![TxInput::unsigned(prev_tx2.as_bytes(), 0)],
        vec![TxOutput {
            amount: 30,
            recipient: charlie_address,
        }],
    );
    tx2.sign_input(0, &alice_keypair.private_key).unwrap();

    let fee2 = tx2.calculate_fee(&utxo_set).unwrap();
    match mempool.add_entry(tx2.clone(), fee2) {
        Ok(_) => {
            println!("  ✓ Transaction added successfully");
            println!("  Transaction fee: {} coins", fee2);
        }
        Err(e) => println!("  ✗ Failed to add: {:?}", e),
    }
    println!("  Mempool size: {}\n", mempool.len());

    // 8. Get transactions sorted by fee (for mining)
    println!("Test 4: Retrieving transactions sorted by fee (highest first)");
    let sorted_txs = mempool.get_transactions_by_fee();
    println!("  Total transactions: {}", sorted_txs.len());
    for (i, tx) in sorted_txs.iter().enumerate() {
        let fee = tx.calculate_fee(&utxo_set).unwrap();
        let total_output: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        println!(
            "  Transaction {}: {} coins sent, {} coins fee",
            i + 1,
            total_output,
            fee
        );
    }
    println!("");

    // 9. Test mempool size limit with fee-based replacement
    println!("Test 5: Testing mempool size limit with fee-based replacement");
    let mut small_mempool = Mempool::with_capacity(1);
    println!(
        "  Created mempool with capacity: {}",
        small_mempool.max_size
    );

    // Add Alice's UTXO for small mempool test
    let alice_small_tx1 = Hash::hash(b"alice_small_1");
    let alice_small_ref1 = UtxoRef::from_bytes(alice_small_tx1.as_bytes(), 0);
    utxo_set.add(alice_small_ref1, Utxo::new(100, alice_address));

    let mut small_tx1 = Transaction::new(
        vec![TxInput::unsigned(alice_small_tx1.as_bytes(), 0)],
        vec![TxOutput {
            amount: 90, // fee = 10
            recipient: bob_address,
        }],
    );
    small_tx1.sign_input(0, &alice_keypair.private_key).unwrap();
    let small_fee1 = small_tx1.calculate_fee(&utxo_set).unwrap();
    small_mempool.add_entry(small_tx1, small_fee1).ok();
    println!("  Added transaction with fee {}", small_fee1);
    println!("  Mempool is now full: {}", small_mempool.is_full());

    // Try to add transaction with lower fee (should be rejected)
    let alice_small_tx2 = Hash::hash(b"alice_small_2");
    let alice_small_ref2 = UtxoRef::from_bytes(alice_small_tx2.as_bytes(), 0);
    utxo_set.add(alice_small_ref2, Utxo::new(100, alice_address));

    let mut small_tx2 = Transaction::new(
        vec![TxInput::unsigned(alice_small_tx2.as_bytes(), 0)],
        vec![TxOutput {
            amount: 95, // fee = 5 (lower than 10)
            recipient: bob_address,
        }],
    );
    small_tx2.sign_input(0, &alice_keypair.private_key).unwrap();
    let small_fee2 = small_tx2.calculate_fee(&utxo_set).unwrap();
    match small_mempool.add_entry(small_tx2, small_fee2) {
        Ok(_) => println!("  ✗ ERROR: Low-fee transaction accepted"),
        Err(e) => println!("  ✓ Low-fee transaction rejected: {:?}", e),
    }

    // Try to add transaction with higher fee (should replace lowest)
    let alice_small_tx3 = Hash::hash(b"alice_small_3");
    let alice_small_ref3 = UtxoRef::from_bytes(alice_small_tx3.as_bytes(), 0);
    utxo_set.add(alice_small_ref3, Utxo::new(100, alice_address));

    let mut small_tx3 = Transaction::new(
        vec![TxInput::unsigned(alice_small_tx3.as_bytes(), 0)],
        vec![TxOutput {
            amount: 80, // fee = 20 (higher than 10)
            recipient: bob_address,
        }],
    );
    small_tx3.sign_input(0, &alice_keypair.private_key).unwrap();
    let small_fee3 = small_tx3.calculate_fee(&utxo_set).unwrap();
    match small_mempool.add_entry(small_tx3, small_fee3) {
        Ok(_) => println!("  ✓ High-fee transaction accepted, replaced lowest-fee transaction"),
        Err(e) => println!("  ✗ ERROR: High-fee transaction rejected: {:?}", e),
    }
    println!("  Final mempool size: {}\n", small_mempool.len());

    // 10. Remove transaction after it's mined
    println!("Test 6: Removing transaction from mempool (after mining)");
    println!("  Before removal: {} transactions", mempool.len());
    mempool.remove_entry(&tx1);
    println!("  After removal: {} transactions", mempool.len());
    println!("");

    // 11. Clear all transactions
    println!("Test 7: Clearing all transactions");
    println!("  Before clear: {} transactions", mempool.len());
    mempool.clear();
    println!("  After clear: {} transactions", mempool.len());
    println!("  Is empty: {}\n", mempool.is_empty());

    // 12. Demonstrate timestamp-based cleanup
    println!("Test 8: Timestamp-based transaction cleanup");
    let mut temp_mempool = Mempool::new();

    // Add Bob's UTXO
    let bob_prev_tx = Hash::hash(b"bob_utxo");
    let bob_utxo_ref = UtxoRef::from_bytes(bob_prev_tx.as_bytes(), 0);
    utxo_set.add(bob_utxo_ref, Utxo::new(100, bob_address));

    let mut bob_tx = Transaction::new(
        vec![TxInput::unsigned(bob_prev_tx.as_bytes(), 0)],
        vec![TxOutput {
            amount: 90,
            recipient: alice_address,
        }],
    );
    bob_tx.sign_input(0, &bob_keypair.private_key).unwrap();

    let bob_fee = bob_tx.calculate_fee(&utxo_set).unwrap();
    temp_mempool.add_entry(bob_tx, bob_fee).ok();
    println!("  Added 1 transaction");
    println!("  Current size: {}", temp_mempool.len());

    // Simulate old timestamp (1 hour ago in milliseconds)
    let one_hour_ago = Mempool::get_current_timestamp() - (60 * 60 * 1000);
    temp_mempool.remove_old_transactions(one_hour_ago);
    println!("  After removing old transactions: {}", temp_mempool.len());
    println!("");

    // Summary
    println!("============================================");
    println!("Summary");
    println!("============================================");
    println!("✓ Mempool accepts valid transactions");
    println!("✓ Mempool rejects coinbase transactions");
    println!("✓ Mempool enforces size limits with fee-based replacement");
    println!("✓ Low-fee transactions are rejected when mempool is full");
    println!("✓ High-fee transactions replace low-fee ones when full");
    println!("✓ Transactions can be sorted by fee");
    println!("✓ Transactions can be removed after mining");
    println!("✓ Old transactions can be cleaned up by timestamp");
    println!("\nMempool is ready for mining operations!");
}
