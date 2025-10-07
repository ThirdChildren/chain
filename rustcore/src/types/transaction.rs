use crate::crypto::{PublicKey, Signature, Hash, PrivateKey};
use crate::crypto::backend::CryptoKey;
use std::collections::HashMap;

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

// UTXO Set per prevenire doppia spesa
pub type UTXOSet = HashMap<(Hash, u32), TxOutput>;

#[derive(Debug)]
pub enum ValidationError {
    InputNotFound,
    InvalidSignature,
    InsufficientFunds,
    DoubleSpend,
    InvalidAmount,
    EmptyTransaction,
}

impl Transaction {
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        Transaction { inputs, outputs }
    }

    /// Serializzazione semplice senza librerie esterne
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Numero di inputs
        bytes.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        
        // Serializza ogni input
        for input in &self.inputs {
            bytes.extend_from_slice(&input.previous_tx_id);
            bytes.extend_from_slice(&input.output_index.to_le_bytes());
            bytes.extend_from_slice(&input.public_key.to_bytes());
        }
        
        // Numero di outputs
        bytes.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        
        // Serializza ogni output
        for output in &self.outputs {
            bytes.extend_from_slice(&output.amount.to_le_bytes());
            bytes.extend_from_slice(&output.recipient);
        }
        
        bytes
    }
    
    /// Hash della transazione usando Hasher incrementale (più efficiente)
    pub fn hash_with_hasher(&self) -> Hash {
        Hash::hash_with_hasher(|hasher| {
            // Numero di inputs
            hasher.update_u32_le(self.inputs.len() as u32);
            
            // Serializza ogni input
            for input in &self.inputs {
                hasher.update(&input.previous_tx_id);
                hasher.update_u32_le(input.output_index);
                hasher.update(&input.public_key.to_bytes());
            }
            
            // Numero di outputs
            hasher.update_u32_le(self.outputs.len() as u32);
            
            // Serializza ogni output
            for output in &self.outputs {
                hasher.update_u64_le(output.amount);
                hasher.update(&output.recipient);
            }
        })
    }
    
    /// Hash della transazione 
    pub fn hash(&self) -> Hash {
        self.hash_with_hasher()
    }
    
    /// Crea hash per la firma di un input specifico usando Hasher incrementale
    pub fn signature_hash(&self, input_index: usize) -> Hash {
        Hash::hash_with_hasher(|hasher| {
            // Include tutti i dati tranne le firme
            hasher.update_u32_le(self.inputs.len() as u32);
            
            for (i, input) in self.inputs.iter().enumerate() {
                hasher.update(&input.previous_tx_id);
                hasher.update_u32_le(input.output_index);
                
                // Include la chiave pubblica solo per l'input che stiamo firmando
                if i == input_index {
                    hasher.update(&input.public_key.to_bytes());
                }
            }
            
            // Include tutti gli outputs
            hasher.update_u32_le(self.outputs.len() as u32);
            for output in &self.outputs {
                hasher.update_u64_le(output.amount);
                hasher.update(&output.recipient);
            }
        })
    }
    
    /// Firma un input specifico
    pub fn sign_input(&mut self, input_index: usize, private_key: &PrivateKey) -> Result<(), ValidationError> {
        if input_index >= self.inputs.len() {
            return Err(ValidationError::InputNotFound);
        }
        
        let sig_hash = self.signature_hash(input_index);
        let signature = Signature::sign_output(&sig_hash, private_key);
        
        self.inputs[input_index].signature = signature;
        self.inputs[input_index].public_key = private_key.public_key();
        
        Ok(())
    }
    
    /// Valida una singola transazione
    pub fn validate(&self, utxo_set: &UTXOSet) -> Result<(), ValidationError> {
        // Controlli di base
        if self.inputs.is_empty() || self.outputs.is_empty() {
            return Err(ValidationError::EmptyTransaction);
        }
        
        let mut total_input_amount = 0u64;
        let mut total_output_amount = 0u64;
        
        // Valida ogni input
        for (i, input) in self.inputs.iter().enumerate() {
            // Controlla se l'UTXO esiste
            let utxo_key = (Hash::from_bytes_array(input.previous_tx_id), input.output_index);
            let referenced_output = utxo_set.get(&utxo_key)
                .ok_or(ValidationError::InputNotFound)?;
            
            // Verifica che il recipient dell'output precedente corrisponda alla chiave pubblica
            let public_key_hash = Self::public_key_to_address(&input.public_key);
            if public_key_hash != referenced_output.recipient {
                return Err(ValidationError::InvalidSignature);
            }
            
            // Verifica la firma
            let sig_hash = self.signature_hash(i);
            if !input.signature.verify(&sig_hash, &input.public_key) {
                return Err(ValidationError::InvalidSignature);
            }
            
            total_input_amount = total_input_amount.checked_add(referenced_output.amount)
                .ok_or(ValidationError::InvalidAmount)?;
        }
        
        // Calcola il totale degli output
        for output in &self.outputs {
            if output.amount == 0 {
                return Err(ValidationError::InvalidAmount);
            }
            total_output_amount = total_output_amount.checked_add(output.amount)
                .ok_or(ValidationError::InvalidAmount)?;
        }
        
        // Verifica che input >= output (le fee vanno al miner)
        if total_input_amount < total_output_amount {
            return Err(ValidationError::InsufficientFunds);
        }
        
        Ok(())
    }
    
    /// Applica la transazione all'UTXO set (rimuove input, aggiunge output)
    pub fn apply_to_utxo_set(&self, utxo_set: &mut UTXOSet) -> Result<(), ValidationError> {
        // Prima valida la transazione
        self.validate(utxo_set)?;
        
        let tx_hash = self.hash();
        
        // Rimuovi gli UTXO spesi
        for input in &self.inputs {
            let utxo_key = (Hash::from_bytes_array(input.previous_tx_id), input.output_index);
            if utxo_set.remove(&utxo_key).is_none() {
                return Err(ValidationError::DoubleSpend);
            }
        }
        
        // Aggiungi i nuovi UTXO
        for (index, output) in self.outputs.iter().enumerate() {
            let utxo_key = (tx_hash, index as u32);
            utxo_set.insert(utxo_key, output.clone());
        }
        
        Ok(())
    }
    
    /// Converte una chiave pubblica in un address (20 bytes) usando Hasher
    pub fn public_key_to_address(public_key: &PublicKey) -> [u8; 20] {
        let hash = Hash::hash(&public_key.to_bytes());
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash.as_bytes()[0..20]);
        address
    }
    
    /// Versione alternativa con Hasher per compatibilità
    pub fn public_key_to_address_with_hasher(public_key: &PublicKey) -> [u8; 20] {
        let hash = Hash::hash_with_hasher(|hasher| {
            hasher.update(&public_key.to_bytes());
        });
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash.as_bytes()[0..20]);
        address
    }
    
    /// Calcola le fee della transazione
    pub fn calculate_fee(&self, utxo_set: &UTXOSet) -> Result<u64, ValidationError> {
        let mut total_input = 0u64;
        let mut total_output = 0u64;
        
        for input in &self.inputs {
            let utxo_key = (Hash::from_bytes_array(input.previous_tx_id), input.output_index);
            let output = utxo_set.get(&utxo_key)
                .ok_or(ValidationError::InputNotFound)?;
            total_input += output.amount;
        }
        
        for output in &self.outputs {
            total_output += output.amount;
        }
        
        Ok(total_input - total_output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{PrivateKey, Hash};
    
    fn create_dummy_utxo_set() -> (UTXOSet, Hash, [u8; 20]) {
        let mut utxo_set = UTXOSet::new();
        let alice_private = PrivateKey::new_key();
        let alice_public = alice_private.public_key();
        let alice_address = Transaction::public_key_to_address(&alice_public);
        
        let genesis_hash = Hash::hash(b"genesis");
        let output = TxOutput {
            amount: 100,
            recipient: alice_address,
        };
        utxo_set.insert((genesis_hash, 0), output);
        
        (utxo_set, genesis_hash, alice_address)
    }
    
    #[test]
    fn test_transaction_creation() {
        let inputs = vec![];
        let outputs = vec![];
        let tx = Transaction::new(inputs, outputs);
        
        assert_eq!(tx.inputs.len(), 0);
        assert_eq!(tx.outputs.len(), 0);
    }
    
    #[test]
    fn test_public_key_to_address() {
        let private_key = PrivateKey::new_key();
        let public_key = private_key.public_key();
        let address = Transaction::public_key_to_address(&public_key);
        
        assert_eq!(address.len(), 20);
    }
    
    #[test]
    fn test_transaction_hash() {
        let alice_private = PrivateKey::new_key();
        let alice_public = alice_private.public_key();
        
        let dummy_hash = Hash::hash(b"dummy");
        let dummy_signature = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        
        let input = TxInput {
            previous_tx_id: [1u8; 32],
            output_index: 0,
            signature: dummy_signature,
            public_key: alice_public.clone(),
        };
        
        let output = TxOutput {
            amount: 50,
            recipient: [2u8; 20],
        };
        
        let tx = Transaction::new(vec![input], vec![output]);
        let hash1 = tx.hash();
        let hash2 = tx.hash();
        
        // L'hash dovrebbe essere deterministico
        assert_eq!(hash1.as_bytes(), hash2.as_bytes());
    }
    
    #[test]
    fn test_signature_hash() {
        let alice_private = PrivateKey::new_key();
        let alice_public = alice_private.public_key();
        
        let dummy_hash = Hash::hash(b"dummy");
        let dummy_signature1 = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        let dummy_signature2 = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        
        let input1 = TxInput {
            previous_tx_id: [1u8; 32],
            output_index: 0,
            signature: dummy_signature1,
            public_key: alice_public.clone(),
        };
        
        let input2 = TxInput {
            previous_tx_id: [2u8; 32],
            output_index: 1,
            signature: dummy_signature2,
            public_key: alice_public.clone(),
        };
        
        let output = TxOutput {
            amount: 50,
            recipient: [2u8; 20],
        };
        
        let tx = Transaction::new(vec![input1.clone()], vec![output.clone()]);
        
        // Verifichiamo che signature_hash generi un hash
        let sig_hash = tx.signature_hash(0);
        assert_eq!(sig_hash.as_bytes().len(), 32);
        
        // Verifichiamo che signature_hash per indici diversi sia diverso
        let tx_multi = Transaction::new(vec![input1, input2], vec![output]);
        let sig_hash_0 = tx_multi.signature_hash(0);
        let sig_hash_1 = tx_multi.signature_hash(1);
        
        // Gli hash per input diversi dovrebbero essere diversi
        assert_ne!(sig_hash_0.as_bytes(), sig_hash_1.as_bytes());
    }
    
    #[test]
    fn test_valid_transaction() {
        let (mut utxo_set, genesis_hash, _alice_address) = create_dummy_utxo_set();
        
        let alice_private = PrivateKey::new_key();
        let alice_public = alice_private.public_key();
        let bob_address = [3u8; 20];
        
        // Aggiorniamo l'address di Alice nell'UTXO set
        let alice_real_address = Transaction::public_key_to_address(&alice_public);
        let output = TxOutput {
            amount: 100,
            recipient: alice_real_address,
        };
        utxo_set.insert((genesis_hash, 0), output);
        
        let dummy_hash = Hash::hash(b"dummy");
        let dummy_signature = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        
        let input = TxInput {
            previous_tx_id: genesis_hash.as_bytes(),
            output_index: 0,
            signature: dummy_signature,
            public_key: alice_public.clone(),
        };
        
        let output_to_bob = TxOutput {
            amount: 60,
            recipient: bob_address,
        };
        
        let change_to_alice = TxOutput {
            amount: 35,
            recipient: alice_real_address,
        };
        
        let mut tx = Transaction::new(vec![input], vec![output_to_bob, change_to_alice]);
        
        // Firmiamo la transazione
        tx.sign_input(0, &alice_private).unwrap();
        
        // La transazione dovrebbe essere valida
        assert!(tx.validate(&utxo_set).is_ok());
    }
    
    #[test]
    fn test_empty_transaction_validation() {
        let utxo_set = UTXOSet::new();
        
        // Transazione senza input
        let tx_no_inputs = Transaction::new(vec![], vec![TxOutput { amount: 10, recipient: [1u8; 20] }]);
        assert!(matches!(tx_no_inputs.validate(&utxo_set), Err(ValidationError::EmptyTransaction)));
        
        let alice_private = PrivateKey::new_key();
        let alice_public = alice_private.public_key();
        let dummy_hash = Hash::hash(b"dummy");
        let dummy_signature = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        
        // Transazione senza output
        let tx_no_outputs = Transaction::new(
            vec![TxInput {
                previous_tx_id: [1u8; 32],
                output_index: 0,
                signature: dummy_signature,
                public_key: alice_public,
            }], 
            vec![]
        );
        assert!(matches!(tx_no_outputs.validate(&utxo_set), Err(ValidationError::EmptyTransaction)));
    }
    
    #[test]
    fn test_input_not_found() {
        let utxo_set = UTXOSet::new();
        
        let alice_private = PrivateKey::new_key();
        let alice_public = alice_private.public_key();
        let dummy_hash = Hash::hash(b"dummy");
        let dummy_signature = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        
        let input = TxInput {
            previous_tx_id: [1u8; 32], // UTXO inesistente
            output_index: 0,
            signature: dummy_signature,
            public_key: alice_public,
        };
        
        let output = TxOutput {
            amount: 10,
            recipient: [2u8; 20],
        };
        
        let tx = Transaction::new(vec![input], vec![output]);
        
        assert!(matches!(tx.validate(&utxo_set), Err(ValidationError::InputNotFound)));
    }
    
    #[test]
    fn test_insufficient_funds() {
        let (mut utxo_set, genesis_hash, _) = create_dummy_utxo_set();
        
        let alice_private = PrivateKey::new_key();
        let alice_public = alice_private.public_key();
        let alice_real_address = Transaction::public_key_to_address(&alice_public);
        
        // Aggiorniamo l'UTXO con l'address corretto
        let output = TxOutput {
            amount: 50, // Solo 50 monete disponibili
            recipient: alice_real_address,
        };
        utxo_set.insert((genesis_hash, 0), output);
        
        let dummy_hash = Hash::hash(b"dummy");
        let dummy_signature = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        
        let input = TxInput {
            previous_tx_id: genesis_hash.as_bytes(),
            output_index: 0,
            signature: dummy_signature,
            public_key: alice_public.clone(),
        };
        
        let output = TxOutput {
            amount: 100, // Cerca di spendere più di quello che ha
            recipient: [2u8; 20],
        };
        
        let mut tx = Transaction::new(vec![input], vec![output]);
        tx.sign_input(0, &alice_private).unwrap();
        
        assert!(matches!(tx.validate(&utxo_set), Err(ValidationError::InsufficientFunds)));
    }
    
    #[test]
    fn test_zero_amount_output() {
        let (mut utxo_set, genesis_hash, _) = create_dummy_utxo_set();
        
        let alice_private = PrivateKey::new_key();
        let alice_public = alice_private.public_key();
        let alice_real_address = Transaction::public_key_to_address(&alice_public);
        
        // Aggiorniamo l'UTXO con l'address corretto
        let output = TxOutput {
            amount: 100,
            recipient: alice_real_address,
        };
        utxo_set.insert((genesis_hash, 0), output);
        
        let dummy_hash = Hash::hash(b"dummy");
        let dummy_signature = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        
        let input = TxInput {
            previous_tx_id: genesis_hash.as_bytes(),
            output_index: 0,
            signature: dummy_signature,
            public_key: alice_public.clone(),
        };
        
        let output = TxOutput {
            amount: 0, // Amount zero non valido
            recipient: [2u8; 20],
        };
        
        let mut tx = Transaction::new(vec![input], vec![output]);
        tx.sign_input(0, &alice_private).unwrap();
        
        assert!(matches!(tx.validate(&utxo_set), Err(ValidationError::InvalidAmount)));
    }
    
    #[test]
    fn test_calculate_fee() {
        let (mut utxo_set, genesis_hash, _) = create_dummy_utxo_set();
        
        let alice_private = PrivateKey::new_key();
        let alice_public = alice_private.public_key();
        let alice_real_address = Transaction::public_key_to_address(&alice_public);
        
        // UTXO con 100 monete
        let output = TxOutput {
            amount: 100,
            recipient: alice_real_address,
        };
        utxo_set.insert((genesis_hash, 0), output);
        
        let dummy_hash = Hash::hash(b"dummy");
        let dummy_signature = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        
        let input = TxInput {
            previous_tx_id: genesis_hash.as_bytes(),
            output_index: 0,
            signature: dummy_signature,
            public_key: alice_public,
        };
        
        let output = TxOutput {
            amount: 95, // Spende 95, fee = 5
            recipient: [2u8; 20],
        };
        
        let tx = Transaction::new(vec![input], vec![output]);
        let fee = tx.calculate_fee(&utxo_set).unwrap();
        
        assert_eq!(fee, 5);
    }
    
    #[test]
    fn test_double_spend_prevention() {
        let (mut utxo_set, genesis_hash, _) = create_dummy_utxo_set();
        
        let alice_private = PrivateKey::new_key();
        let alice_public = alice_private.public_key();
        let alice_real_address = Transaction::public_key_to_address(&alice_public);
        
        let output = TxOutput {
            amount: 100,
            recipient: alice_real_address,
        };
        utxo_set.insert((genesis_hash, 0), output);
        
        let dummy_hash = Hash::hash(b"dummy");
        let dummy_signature1 = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        let dummy_signature2 = crate::crypto::Signature::sign_output(&dummy_hash, &alice_private);
        
        let input1 = TxInput {
            previous_tx_id: genesis_hash.as_bytes(),
            output_index: 0,
            signature: dummy_signature1,
            public_key: alice_public.clone(),
        };
        
        let input2 = TxInput {
            previous_tx_id: genesis_hash.as_bytes(),
            output_index: 0,
            signature: dummy_signature2,
            public_key: alice_public.clone(),
        };
        
        let output_tx = TxOutput {
            amount: 50,
            recipient: [2u8; 20],
        };
        
        let mut first_tx = Transaction::new(vec![input1], vec![output_tx.clone()]);
        first_tx.sign_input(0, &alice_private).unwrap();
        
        // Prima transazione dovrebbe essere applicata con successo
        assert!(first_tx.apply_to_utxo_set(&mut utxo_set).is_ok());
        
        // Seconda transazione che usa lo stesso input dovrebbe fallire
        let mut second_tx = Transaction::new(vec![input2], vec![output_tx]);
        second_tx.sign_input(0, &alice_private).unwrap();
        
        // Ora l'UTXO è già stato speso, quindi dovrebbe fallire con InputNotFound
        assert!(matches!(second_tx.validate(&utxo_set), Err(ValidationError::InputNotFound)));
    }
}

