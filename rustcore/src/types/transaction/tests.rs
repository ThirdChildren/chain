#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_transaction_creation() {
        let alice_keypair = KeyPair::generate();
        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: [0u8; 32],
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 50,
                recipient: bob_address,
            }],
        );

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert!(!tx.is_coinbase());
    }

    #[test]
    fn test_coinbase_transaction() {
        let miner_address = [1u8; 20];
        let coinbase = Transaction::new_coinbase(miner_address, 50);

        assert!(coinbase.is_coinbase());
        assert_eq!(coinbase.inputs.len(), 0);
        assert_eq!(coinbase.outputs.len(), 1);
        assert_eq!(coinbase.outputs[0].amount, 50);
    }

    #[test]
    fn test_signature_hash() {
        let alice_keypair = KeyPair::generate();
        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: [1u8; 32],
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 30,
                recipient: bob_address,
            }],
        );

        let hash1 = tx.signature_hash(0);
        let hash2 = tx.signature_hash(0);

        // Same transaction should produce same signature hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_sign_input() {
        let alice_keypair = KeyPair::generate();
        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let mut tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: [1u8; 32],
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 30,
                recipient: bob_address,
            }],
        );

        let result = tx.sign_input(0, &alice_keypair.private_key);
        assert!(result.is_ok());

        // Verify signature
        let sig_hash = tx.signature_hash(0);
        assert!(
            tx.inputs[0]
                .signature
                .verify(&sig_hash, &alice_keypair.public_key)
        );
    }

    #[test]
    fn test_calculate_fee() {
        let mut utxo_set = UTXOSet::new();
        let alice_keypair = KeyPair::generate();
        let address = Transaction::public_key_to_address(&alice_keypair.public_key);

        // Add initial UTXO
        let initial_tx = Transaction::new_coinbase(address, 100);
        utxo_set.apply_transaction(&initial_tx, 0).unwrap();

        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: initial_tx.hash().as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 95,
                recipient: bob_address,
            }],
        );

        let fee = tx.calculate_fee(&utxo_set);
        assert_eq!(fee, Some(5));
    }

    #[test]
    fn test_transaction_hash() {
        let alice_keypair = KeyPair::generate();
        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let tx1 = Transaction::new(
            vec![TxInput {
                previous_tx_id: [1u8; 32],
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 50,
                recipient: bob_address,
            }],
        );

        let tx2 = Transaction::new(
            vec![TxInput {
                previous_tx_id: [1u8; 32],
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &alice_keypair.private_key),
                public_key: alice_keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 50,
                recipient: bob_address,
            }],
        );

        // Same transaction data should produce same hash
        assert_eq!(tx1.hash(), tx2.hash());
    }
}
