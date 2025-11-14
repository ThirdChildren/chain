//! Transaction Validation Example
//!
//! This example demonstrates:
//! - Creating transactions with inputs and outputs
//! - Signing transactions with private keys
//! - Validating transactions through the Blockchain API
//! - Calculating transaction fees
//! - Double-spend prevention at blockchain level

use rustcore::crypto::{Hash, KeyPair, Signature};
use rustcore::types::{Block, Blockchain, Transaction, TxInput, TxOutput};

fn main() {
    println!("============================================");
    println!("Transaction Validation Example");
    println!("============================================\n");

    // 1. Generate keypairs for Alice, Bob, and Miner
    let alice_keypair = KeyPair::generate();
    let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);

    let bob_keypair = KeyPair::generate();
    let bob_address = Transaction::public_key_to_address(&bob_keypair.public_key);

    let miner_keypair = KeyPair::generate();
    let miner_address = Transaction::public_key_to_address(&miner_keypair.public_key);

    println!("Generated addresses:");
    println!("  Alice: {:02x?}...", &alice_address[..8]);
    println!("  Bob: {:02x?}...", &bob_address[..8]);
    println!("  Miner: {:02x?}...", &miner_address[..8]);
    println!("");

    // 2. Create blockchain with genesis block (Alice gets 100 coins)
    let genesis_coinbase = Transaction::new_coinbase(alice_address, 100);
    let genesis_block = Block::new_signed(
        0,
        Hash::zero(),
        1000000,
        vec![genesis_coinbase.clone()],
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    let mut blockchain =
        match Blockchain::new_blockchain("example_chain".to_string(), genesis_block) {
            Ok(bc) => {
                println!("Blockchain created with genesis block");
                println!("  Alice initial balance: 100 coins\n");
                bc
            }
            Err(e) => {
                println!("Failed to create blockchain: {:?}", e);
                return;
            }
        };

    // 3. Alice creates a transaction to send 50 coins to Bob
    println!("Creating transaction: Alice sends 50 to Bob");
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
                amount: 45, // Change back to Alice
                recipient: alice_address,
            },
        ],
    );

    println!("  Input: 100 coins from Alice");
    println!("  Output 1: 50 coins to Bob");
    println!("  Output 2: 45 coins (change) to Alice");
    println!("  Fee: 5 coins");
    println!("");

    // 4. Alice signs the transaction
    print!("Signing transaction... ");
    match tx1.sign_input(0, &alice_keypair.private_key) {
        Ok(_) => println!("SUCCESS"),
        Err(e) => {
            println!("FAILED: {}", e);
            return;
        }
    }

    // 5. Calculate transaction fee
    let fee = tx1.calculate_fee(blockchain.get_utxo_set());
    println!("Calculated fee: {:?} coins", fee);
    println!("");

    // 6. Validate the transaction through blockchain
    print!("Validating transaction through blockchain... ");
    match blockchain.validate_transaction(&tx1) {
        Ok(_) => {
            println!("VALID");
            println!("  ✓ Signature verified");
            println!("  ✓ UTXO exists");
            println!("  ✓ Sufficient funds");
            println!("  ✓ Valid amounts");
        }
        Err(e) => {
            println!("INVALID: {:?}", e);
            return;
        }
    }
    println!("");

    // 7. Add transaction to a block and add block to blockchain
    println!("Creating and adding block with transaction...");
    let block_coinbase = Transaction::new_coinbase(miner_address, 55); // 50 + 5 fee

    let block_1 = Block::new_signed(
        1,
        blockchain.blocks[0].hash(),
        1000100,
        vec![block_coinbase, tx1.clone()],
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    match blockchain.add_block(block_1) {
        Ok(_) => {
            println!("  Block added successfully");
            println!("  UTXO set updated automatically by blockchain");
        }
        Err(e) => {
            println!("  Failed to add block: {:?}", e);
            return;
        }
    }
    println!("");

    // 8. Check balances
    println!("Balances after transaction:");
    println!("  Alice: {} coins", blockchain.get_balance(&alice_address));
    println!("  Bob: {} coins", blockchain.get_balance(&bob_address));
    println!("  Miner: {} coins", blockchain.get_balance(&miner_address));
    println!("");

    // 9. Test double-spend prevention
    println!("============================================");
    println!("Testing Double-Spend Prevention");
    println!("============================================\n");

    println!("Attempting to spend the same UTXO again...");

    // Try to create another transaction using the same input (already spent)
    let mut double_spend_tx = Transaction::new(
        vec![TxInput {
            previous_tx_id: genesis_coinbase_hash.as_bytes(),
            output_index: 0, // Same UTXO!
            signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
            public_key: alice_keypair.public_key.clone(),
        }],
        vec![TxOutput {
            amount: 10,
            recipient: bob_address,
        }],
    );

    double_spend_tx
        .sign_input(0, &alice_keypair.private_key)
        .unwrap();

    print!("Validating double-spend transaction... ");
    match blockchain.validate_transaction(&double_spend_tx) {
        Ok(_) => {
            println!("VALID (ERROR! Should have been rejected)");
        }
        Err(e) => {
            println!("INVALID (correct!)");
            println!("  Reason: {:?}", e);
            println!("  ✓ Double-spend correctly prevented by blockchain");
        }
    }
    println!("");

    // 10. Test valid transaction from Bob
    println!("============================================");
    println!("Testing Valid Transaction from Bob");
    println!("============================================\n");

    println!("Bob sends 20 coins back to Alice...");

    let tx1_hash = tx1.hash();
    let mut bob_tx = Transaction::new(
        vec![TxInput {
            previous_tx_id: tx1_hash.as_bytes(),
            output_index: 0, // Bob's output from tx1
            signature: Signature::sign_output(&Hash::zero(), &bob_keypair.private_key),
            public_key: bob_keypair.public_key.clone(),
        }],
        vec![
            TxOutput {
                amount: 20,
                recipient: alice_address,
            },
            TxOutput {
                amount: 28, // Change to Bob
                recipient: bob_address,
            },
        ],
    );

    bob_tx.sign_input(0, &bob_keypair.private_key).unwrap();

    print!("Validating Bob's transaction... ");
    match blockchain.validate_transaction(&bob_tx) {
        Ok(_) => {
            println!("VALID");
            println!("  ✓ Bob can spend his UTXO");
        }
        Err(e) => {
            println!("INVALID: {:?}", e);
        }
    }
    println!("");

    // Add Bob's transaction to blockchain
    let block_coinbase2 = Transaction::new_coinbase(miner_address, 52); // 50 + 2 fee
    let block_2 = Block::new_signed(
        2,
        blockchain.blocks[1].hash(),
        1000200,
        vec![block_coinbase2, bob_tx],
        miner_keypair.public_key.clone(),
        &miner_keypair.private_key,
    );

    match blockchain.add_block(block_2) {
        Ok(_) => {
            println!("Block 2 added successfully");
        }
        Err(e) => {
            println!("Failed to add block 2: {:?}", e);
        }
    }
    println!("");

    // 11. Final balances
    println!("============================================");
    println!("Final Blockchain State");
    println!("============================================");
    println!("  Blockchain height: {}", blockchain.height());
    println!(
        "  Alice balance: {} coins",
        blockchain.get_balance(&alice_address)
    );
    println!(
        "  Bob balance: {} coins",
        blockchain.get_balance(&bob_address)
    );
    println!(
        "  Miner balance: {} coins",
        blockchain.get_balance(&miner_address)
    );
    println!("  Total UTXO count: {}", blockchain.get_utxo_set().len());
    println!("");

    // 12. Test insufficient funds
    println!("============================================");
    println!("Testing Insufficient Funds");
    println!("============================================\n");

    println!("Bob tries to spend more than he has...");

    let mut invalid_tx = Transaction::new(
        vec![TxInput {
            previous_tx_id: tx1_hash.as_bytes(),
            output_index: 0,
            signature: Signature::sign_output(&Hash::zero(), &bob_keypair.private_key),
            public_key: bob_keypair.public_key.clone(),
        }],
        vec![TxOutput {
            amount: 1000, // Bob only has 28 left!
            recipient: alice_address,
        }],
    );

    invalid_tx.sign_input(0, &bob_keypair.private_key).unwrap();

    print!("Validating insufficient funds transaction... ");
    match blockchain.validate_transaction(&invalid_tx) {
        Ok(_) => {
            println!("VALID (ERROR! Should have been rejected)");
        }
        Err(e) => {
            println!("INVALID (correct!)");
            println!("  Reason: {:?}", e);
        }
    }
    println!("");

    println!("============================================");
    println!("All validation tests completed!");
    println!("============================================");
}
