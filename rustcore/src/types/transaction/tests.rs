#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::crypto::KeyPair;

    #[test]
    fn test_transaction_creation() {
        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let tx = Transaction::new(
            vec![TxInput::unsigned([0u8; 32], 0)],
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
    fn test_sign_input() {
        let alice_keypair = KeyPair::generate();
        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let mut tx = Transaction::new(
            vec![TxInput::unsigned([1u8; 32], 0)],
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
        let initial_tx = Transaction::new_coinbase(address, 100, 0);
        utxo_set.apply_transaction(&initial_tx, 0).unwrap();

        let bob_address = Transaction::public_key_to_address(&KeyPair::generate().public_key);

        let tx = Transaction::new(
            vec![TxInput::unsigned(initial_tx.hash().as_bytes(), 0)],
            vec![TxOutput {
                amount: 95,
                recipient: bob_address,
            }],
        );

        let fee = tx.calculate_fee(&utxo_set);
        assert_eq!(fee, Some(5));
    }
}
