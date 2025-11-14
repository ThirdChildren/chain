use crate::crypto::Hash;
use crate::types::Transaction;
use std::collections::HashMap;

/// Reference to a specific UTXO (transaction hash + output index)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UtxoRef {
    pub tx_hash: Hash,
    pub output_index: u32,
}

impl UtxoRef {
    pub fn new(tx_hash: Hash, output_index: u32) -> Self {
        UtxoRef {
            tx_hash,
            output_index,
        }
    }

    pub fn from_bytes(tx_hash_bytes: [u8; 32], output_index: u32) -> Self {
        UtxoRef {
            tx_hash: Hash::from_bytes_array(tx_hash_bytes),
            output_index,
        }
    }
}

/// Unspent Transaction Output
#[derive(Debug, Clone, PartialEq)]
pub struct Utxo {
    pub amount: u64,
    pub recipient: [u8; 20],
}

impl Utxo {
    pub fn new(amount: u64, recipient: [u8; 20]) -> Self {
        Utxo { amount, recipient }
    }
}

/// Set of Unspent Transaction Outputs
#[derive(Debug, Clone)]
pub struct UTXOSet {
    utxos: HashMap<UtxoRef, Utxo>,
}

impl UTXOSet {
    /// Create a new empty UTXO set
    pub fn new() -> Self {
        UTXOSet {
            utxos: HashMap::new(),
        }
    }

    /// Get a UTXO by reference
    pub fn get(&self, utxo_ref: &UtxoRef) -> Option<&Utxo> {
        self.utxos.get(utxo_ref)
    }

    /// Check if a UTXO exists
    pub fn has(&self, utxo_ref: &UtxoRef) -> bool {
        self.utxos.contains_key(utxo_ref)
    }

    /// Add a UTXO to the set
    pub fn add(&mut self, utxo_ref: UtxoRef, utxo: Utxo) {
        self.utxos.insert(utxo_ref, utxo);
    }

    /// Remove a UTXO from the set, returning the removed UTXO if it existed
    pub fn remove(&mut self, utxo_ref: &UtxoRef) -> Option<Utxo> {
        self.utxos.remove(utxo_ref)
    }

    /// Get the number of UTXOs in the set
    pub fn len(&self) -> usize {
        self.utxos.len()
    }

    /// Check if the set is empty
    pub fn is_empty(&self) -> bool {
        self.utxos.is_empty()
    }

    /// Get all UTXOs for a specific address
    pub fn get_utxos_for_address(&self, address: &[u8; 20]) -> Vec<(UtxoRef, &Utxo)> {
        self.utxos
            .iter()
            .filter(|(_, utxo)| utxo.recipient == *address)
            .map(|(utxo_ref, utxo)| (*utxo_ref, utxo))
            .collect()
    }

    /// Calculate balance for an address
    pub fn get_balance(&self, address: &[u8; 20]) -> u64 {
        self.utxos
            .values()
            .filter(|utxo| utxo.recipient == *address)
            .map(|utxo| utxo.amount)
            .sum()
    }

    /// Apply a transaction to the UTXO set
    /// Removes spent inputs and adds new outputs
    /// Returns error if an input doesn't exist (double spend)
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), &'static str> {
        let tx_hash = tx.hash();

        // For regular transactions, remove spent inputs
        if !tx.is_coinbase() {
            for input in &tx.inputs {
                let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
                if self.remove(&utxo_ref).is_none() {
                    return Err("Input UTXO not found (double spend)");
                }
            }
        }

        // Add new outputs to UTXO set
        for (index, output) in tx.outputs.iter().enumerate() {
            let utxo_ref = UtxoRef::new(tx_hash, index as u32);
            let utxo = Utxo::new(output.amount, output.recipient);
            self.add(utxo_ref, utxo);
        }

        Ok(())
    }

    /// Check if a transaction can be applied without actually applying it
    /// This is useful for validating transactions before adding them to a block
    pub fn can_apply_transaction(&self, tx: &Transaction) -> Result<(), &'static str> {
        // Coinbase transactions can always be applied
        if tx.is_coinbase() {
            return Ok(());
        }

        // Check that all inputs exist
        for input in &tx.inputs {
            let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
            if !self.has(&utxo_ref) {
                return Err("Input UTXO not found");
            }
        }

        Ok(())
    }

    /// Get total value of inputs for a transaction
    /// Returns None if any input is not found
    pub fn get_transaction_input_value(&self, tx: &Transaction) -> Option<u64> {
        if tx.is_coinbase() {
            return Some(0);
        }

        let mut total = 0u64;
        for input in &tx.inputs {
            let utxo_ref = UtxoRef::from_bytes(input.previous_tx_id, input.output_index);
            let utxo = self.get(&utxo_ref)?;
            total = total.checked_add(utxo.amount)?;
        }
        Some(total)
    }

    /// Get total value of outputs for a transaction
    pub fn get_transaction_output_value(tx: &Transaction) -> Option<u64> {
        let mut total = 0u64;
        for output in &tx.outputs {
            total = total.checked_add(output.amount)?;
        }
        Some(total)
    }

    /// Calculate fee for a transaction
    /// Returns None if transaction is invalid or coinbase
    pub fn calculate_transaction_fee(&self, tx: &Transaction) -> Option<u64> {
        if tx.is_coinbase() {
            return Some(0);
        }

        let input_value = self.get_transaction_input_value(tx)?;
        let output_value = Self::get_transaction_output_value(tx)?;
        input_value.checked_sub(output_value)
    }

    /// Iterator over all UTXOs
    pub fn iter(&self) -> impl Iterator<Item = (&UtxoRef, &Utxo)> {
        self.utxos.iter()
    }
}

impl Default for UTXOSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{KeyPair, Signature};
    use crate::types::{TxInput, TxOutput};

    #[test]
    fn test_utxo_ref_creation() {
        let hash = Hash::hash(b"test");
        let utxo_ref = UtxoRef::new(hash, 0);
        assert_eq!(utxo_ref.tx_hash, hash);
        assert_eq!(utxo_ref.output_index, 0);
    }

    #[test]
    fn test_utxo_creation() {
        let utxo = Utxo::new(100, [1u8; 20]);
        assert_eq!(utxo.amount, 100);
        assert_eq!(utxo.recipient, [1u8; 20]);
    }

    #[test]
    fn test_utxo_set_new() {
        let set = UTXOSet::new();
        assert!(set.is_empty());
        assert_eq!(set.len(), 0);
    }

    #[test]
    fn test_utxo_set_add_get() {
        let mut set = UTXOSet::new();
        let hash = Hash::hash(b"test");
        let utxo_ref = UtxoRef::new(hash, 0);
        let utxo = Utxo::new(100, [1u8; 20]);

        set.add(utxo_ref, utxo.clone());

        assert_eq!(set.len(), 1);
        assert!(set.has(&utxo_ref));
        assert_eq!(set.get(&utxo_ref), Some(&utxo));
    }

    #[test]
    fn test_utxo_set_remove() {
        let mut set = UTXOSet::new();
        let hash = Hash::hash(b"test");
        let utxo_ref = UtxoRef::new(hash, 0);
        let utxo = Utxo::new(100, [1u8; 20]);

        set.add(utxo_ref, utxo.clone());
        assert_eq!(set.len(), 1);

        let removed = set.remove(&utxo_ref);
        assert_eq!(removed, Some(utxo));
        assert_eq!(set.len(), 0);
        assert!(!set.has(&utxo_ref));
    }

    #[test]
    fn test_get_balance() {
        let mut set = UTXOSet::new();
        let address = [1u8; 20];

        let hash1 = Hash::hash(b"tx1");
        set.add(UtxoRef::new(hash1, 0), Utxo::new(100, address));

        let hash2 = Hash::hash(b"tx2");
        set.add(UtxoRef::new(hash2, 0), Utxo::new(50, address));

        let hash3 = Hash::hash(b"tx3");
        set.add(UtxoRef::new(hash3, 0), Utxo::new(25, [2u8; 20]));

        assert_eq!(set.get_balance(&address), 150);
        assert_eq!(set.get_balance(&[2u8; 20]), 25);
        assert_eq!(set.get_balance(&[3u8; 20]), 0);
    }

    #[test]
    fn test_apply_coinbase_transaction() {
        let mut set = UTXOSet::new();
        let address = [1u8; 20];

        let coinbase = Transaction::new_coinbase(address, 50);
        assert!(set.apply_transaction(&coinbase).is_ok());

        assert_eq!(set.len(), 1);
        assert_eq!(set.get_balance(&address), 50);
    }

    #[test]
    fn test_apply_regular_transaction() {
        let mut set = UTXOSet::new();
        let keypair = KeyPair::generate();
        let address = Transaction::public_key_to_address(&keypair.public_key);

        // Add initial UTXO
        let initial_tx = Transaction::new_coinbase(address, 100);
        set.apply_transaction(&initial_tx).unwrap();

        // Create spending transaction
        let recipient = [2u8; 20];
        let mut tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: initial_tx.hash().as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &keypair.private_key),
                public_key: keypair.public_key.clone(),
            }],
            vec![
                TxOutput {
                    amount: 60,
                    recipient,
                },
                TxOutput {
                    amount: 35,
                    recipient: address,
                },
            ],
        );
        tx.sign_input(0, &keypair.private_key).unwrap();

        assert!(set.apply_transaction(&tx).is_ok());

        // Original UTXO should be removed
        assert_eq!(set.len(), 2);
        assert_eq!(set.get_balance(&address), 35);
        assert_eq!(set.get_balance(&recipient), 60);
    }

    #[test]
    fn test_apply_transaction_double_spend() {
        let mut set = UTXOSet::new();
        let address = [1u8; 20];

        let initial_tx = Transaction::new_coinbase(address, 100);
        set.apply_transaction(&initial_tx).unwrap();

        let keypair = KeyPair::generate();
        let tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: initial_tx.hash().as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &keypair.private_key),
                public_key: keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 50,
                recipient: [2u8; 20],
            }],
        );

        // First application should succeed
        assert!(set.apply_transaction(&tx).is_ok());

        // Second application should fail (double spend)
        assert!(set.apply_transaction(&tx).is_err());
    }

    #[test]
    fn test_can_apply_transaction() {
        let mut set = UTXOSet::new();
        let address = [1u8; 20];

        let initial_tx = Transaction::new_coinbase(address, 100);
        set.apply_transaction(&initial_tx).unwrap();

        let keypair = KeyPair::generate();
        let tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: initial_tx.hash().as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &keypair.private_key),
                public_key: keypair.public_key.clone(),
            }],
            vec![TxOutput {
                amount: 50,
                recipient: [2u8; 20],
            }],
        );

        assert!(set.can_apply_transaction(&tx).is_ok());

        // Apply it
        set.apply_transaction(&tx).unwrap();

        // Now it can't be applied again
        assert!(set.can_apply_transaction(&tx).is_err());
    }

    #[test]
    fn test_get_transaction_values() {
        let mut set = UTXOSet::new();
        let address = [1u8; 20];

        let initial_tx = Transaction::new_coinbase(address, 100);
        set.apply_transaction(&initial_tx).unwrap();

        let keypair = KeyPair::generate();
        let tx = Transaction::new(
            vec![TxInput {
                previous_tx_id: initial_tx.hash().as_bytes(),
                output_index: 0,
                signature: Signature::sign_output(&Hash::zero(), &keypair.private_key),
                public_key: keypair.public_key.clone(),
            }],
            vec![
                TxOutput {
                    amount: 60,
                    recipient: [2u8; 20],
                },
                TxOutput {
                    amount: 35,
                    recipient: address,
                },
            ],
        );

        assert_eq!(set.get_transaction_input_value(&tx), Some(100));
        assert_eq!(UTXOSet::get_transaction_output_value(&tx), Some(95));
        assert_eq!(set.calculate_transaction_fee(&tx), Some(5));
    }

    #[test]
    fn test_get_utxos_for_address() {
        let mut set = UTXOSet::new();
        let address1 = [1u8; 20];
        let address2 = [2u8; 20];

        let hash1 = Hash::hash(b"tx1");
        set.add(UtxoRef::new(hash1, 0), Utxo::new(100, address1));
        set.add(UtxoRef::new(hash1, 1), Utxo::new(50, address2));

        let hash2 = Hash::hash(b"tx2");
        set.add(UtxoRef::new(hash2, 0), Utxo::new(25, address1));

        let utxos_addr1 = set.get_utxos_for_address(&address1);
        assert_eq!(utxos_addr1.len(), 2);

        let utxos_addr2 = set.get_utxos_for_address(&address2);
        assert_eq!(utxos_addr2.len(), 1);
    }
}
