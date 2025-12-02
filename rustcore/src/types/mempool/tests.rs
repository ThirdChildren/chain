#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::crypto::Hash;
    use crate::crypto::KeyPair;
    use crate::crypto::Signature;
    use crate::types::{TxInput, TxOutput};

    /// Comprehensive test for add_entry validation rules
    /// Tests: coinbase rejection, size limit, fee validation, and valid transaction acceptance
    #[test]
    fn test_add_entry_validation() {
        let mut mempool = Mempool::with_capacity(2);

        // Setup test accounts
        let alice_keypair = KeyPair::generate();
        let alice_address = Transaction::public_key_to_address(&alice_keypair.public_key);
        let bob_address = [2u8; 20];

        // Test 1: Reject coinbase transactions
        let coinbase = Transaction::new_coinbase(alice_address, 50);
        let result = mempool.add_entry(coinbase, 0);
        assert!(matches!(result, Err(MempoolError::CoinbaseNotAllowed)));
        assert_eq!(mempool.current_size(), 0);

        // Test 2: Accept valid transaction with proper fee
        let prev_tx_hash1 = Hash::hash(b"utxo1");

        let mut tx1 = Transaction::new(
            vec![TxInput {
                previous_tx_id: prev_tx_hash1.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 90,
                recipient: bob_address,
            }],
        );
        tx1.sign_input(0, &alice_keypair.private_key).unwrap();

        let fee1 = 10; // 100 - 90 = 10
        let result1 = mempool.add_entry(tx1.clone(), fee1);
        assert!(result1.is_ok());
        assert_eq!(mempool.current_size(), 1);

        // Test 3: Accept second valid transaction
        let prev_tx_hash2 = Hash::hash(b"utxo2");

        let mut tx2 = Transaction::new(
            vec![TxInput {
                previous_tx_id: prev_tx_hash2.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 80,
                recipient: bob_address,
            }],
        );
        tx2.sign_input(0, &alice_keypair.private_key).unwrap();

        let fee2 = 20; // 100 - 80 = 20
        let result2 = mempool.add_entry(tx2, fee2);
        assert!(result2.is_ok());
        assert_eq!(mempool.current_size(), 2);
        assert!(mempool.is_full());

        // Test 4: Reject when mempool is full with lower fee
        let prev_tx_hash3 = Hash::hash(b"utxo3");

        let mut tx3 = Transaction::new(
            vec![TxInput {
                previous_tx_id: prev_tx_hash3.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 95, // fee = 5 (lower than both tx1 and tx2)
                recipient: bob_address,
            }],
        );
        tx3.sign_input(0, &alice_keypair.private_key).unwrap();

        let fee3 = 5; // 100 - 95 = 5
        let result3 = mempool.add_entry(tx3, fee3);
        assert!(matches!(result3, Err(MempoolError::FeeTooLow { .. })));
        assert_eq!(mempool.current_size(), 2);

        // Test 5: Accept transaction with higher fee, replacing lowest
        let prev_tx_hash4 = Hash::hash(b"utxo4");

        let mut tx4 = Transaction::new(
            vec![TxInput {
                previous_tx_id: prev_tx_hash4.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 50, // fee = 50 (higher than both tx1 and tx2)
                recipient: bob_address,
            }],
        );
        tx4.sign_input(0, &alice_keypair.private_key).unwrap();

        let fee4 = 50; // 100 - 50 = 50
        let result4 = mempool.add_entry(tx4.clone(), fee4);
        assert!(result4.is_ok());
        assert_eq!(mempool.current_size(), 2); // Still 2, replaced lowest

        // Verify the transaction with lowest fee (tx1 with fee 10) was replaced
        let sorted = mempool.get_transactions_by_fee();
        assert_eq!(sorted[0].outputs[0].amount, 50); // tx4 with highest fee (50)
        assert_eq!(sorted[1].outputs[0].amount, 80); // tx2 with fee 20
    }

    /// Comprehensive test for mempool operations
    /// Tests: transaction removal, fee-based sorting, clearing, and state checks
    #[test]
    fn test_mempool_operations() {
        let mut mempool = Mempool::new();

        // Initial state checks
        assert!(mempool.is_empty());
        assert!(!mempool.is_full());
        assert_eq!(mempool.current_size(), 0);

        // Setup test accounts
        let alice_keypair = KeyPair::generate();
        let bob_address = [2u8; 20];

        // Add transaction with fee 10
        let prev_tx_hash1 = Hash::hash(b"tx1");

        let mut tx1 = Transaction::new(
            vec![TxInput {
                previous_tx_id: prev_tx_hash1.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 90, // fee = 10
                recipient: bob_address,
            }],
        );
        tx1.sign_input(0, &alice_keypair.private_key).unwrap();
        mempool.add_entry(tx1.clone(), 10).unwrap();

        // Add transaction with higher fee (20)
        let prev_tx_hash2 = Hash::hash(b"tx2");

        let mut tx2 = Transaction::new(
            vec![TxInput {
                previous_tx_id: prev_tx_hash2.as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 80, // fee = 20
                recipient: bob_address,
            }],
        );
        tx2.sign_input(0, &alice_keypair.private_key).unwrap();
        mempool.add_entry(tx2.clone(), 20).unwrap();

        // Test: Get transactions sorted by fee (highest first)
        let sorted_txs = mempool.get_transactions_by_fee();
        assert_eq!(sorted_txs.len(), 2);
        assert_eq!(sorted_txs[0].outputs[0].amount, 80); // Higher fee first
        assert_eq!(sorted_txs[1].outputs[0].amount, 90); // Lower fee second

        // Test: Remove specific transaction
        assert_eq!(mempool.current_size(), 2);
        mempool.remove_entry(&tx1);
        assert_eq!(mempool.current_size(), 1);
        assert!(!mempool.is_empty());

        // Test: Clear all transactions
        mempool.clear();
        assert_eq!(mempool.current_size(), 0);
        assert!(mempool.is_empty());
    }
}
