use crate::crypto::signature::backend::CryptoKey;
use crate::crypto::{Hash, PrivateKey, PublicKey, Signature};
use crate::types::utxo::UTXOSet;

#[derive(Clone, Debug)]
pub struct Transaction {
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
}

#[derive(Clone, Debug)]
pub struct TxInput {
    pub previous_tx_id: [u8; 32],
    pub output_index: u32,
    pub signature: Signature,
    pub public_key: PublicKey,
}

#[derive(Clone, Debug)]
pub struct TxOutput {
    pub amount: u64,
    pub recipient: [u8; 20],
}

impl Transaction {
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        Transaction { inputs, outputs }
    }

    /// Create a new coinbase transaction (mining reward)
    pub fn new_coinbase(recipient: [u8; 20], amount: u64) -> Self {
        let output = TxOutput { amount, recipient };
        Transaction {
            inputs: vec![],
            outputs: vec![output],
        }
    }

    /// Check if this is a coinbase transaction
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty() && !self.outputs.is_empty()
    }

    /// Serialization without external libraries
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());

        // Serialize each input
        for input in &self.inputs {
            bytes.extend_from_slice(&input.previous_tx_id);
            bytes.extend_from_slice(&input.output_index.to_le_bytes());
            bytes.extend_from_slice(&input.public_key.to_bytes());
        }

        bytes.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());

        // Serialize each output
        for output in &self.outputs {
            bytes.extend_from_slice(&output.amount.to_le_bytes());
            bytes.extend_from_slice(&output.recipient);
        }

        bytes
    }

    /// Transaction hash
    pub fn hash(&self) -> Hash {
        Hash::compute(|hasher| {
            hasher.input(self.inputs.len() as u32);

            for input in &self.inputs {
                hasher.input(&input.previous_tx_id);
                hasher.input(input.output_index);
                hasher.input(&input.public_key.to_bytes());
            }

            hasher.input(self.outputs.len() as u32);

            for output in &self.outputs {
                hasher.input(output.amount);
                hasher.input(&output.recipient);
            }
        })
    }

    /// Create a hash for signing a specific input
    pub fn signature_hash(&self, input_index: usize) -> Hash {
        Hash::compute(|hasher| {
            hasher.input(self.inputs.len() as u32);

            for (i, input) in self.inputs.iter().enumerate() {
                hasher.input(&input.previous_tx_id);
                hasher.input(input.output_index);

                if i == input_index {
                    hasher.input(&input.public_key.to_bytes());
                }
            }

            hasher.input(self.outputs.len() as u32);
            for output in &self.outputs {
                hasher.input(output.amount);
                hasher.input(&output.recipient);
            }
        })
    }

    /// Sign a specific input
    pub fn sign_input(
        &mut self,
        input_index: usize,
        private_key: &PrivateKey,
    ) -> Result<(), &'static str> {
        if input_index >= self.inputs.len() {
            return Err("Input index out of bounds");
        }

        let sig_hash = self.signature_hash(input_index);
        let signature = Signature::sign_output(&sig_hash, private_key);

        self.inputs[input_index].signature = signature;
        self.inputs[input_index].public_key = private_key.public_key();

        Ok(())
    }

    /// Utility: convert public key to address (hash of public key)
    pub fn public_key_to_address(public_key: &PublicKey) -> [u8; 20] {
        let hash = Hash::compute(|hasher| {
            hasher.input(&public_key.to_bytes());
        });
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash.as_bytes()[0..20]);
        address
    }

    /// Calculate transaction fee
    /// Returns None if the transaction is coinbase or if UTXO is not found
    pub fn calculate_fee(&self, utxo_set: &UTXOSet) -> Option<u64> {
        utxo_set.calculate_transaction_fee(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        utxo_set.apply_transaction(&initial_tx).unwrap();

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
