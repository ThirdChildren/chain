use rustcore::crypto::{PrivateKey, Hash, Signature};
use rustcore::types::transaction::{Transaction, TxInput, TxOutput, UTXOSet, ValidationError};

fn main() -> Result<(), ValidationError> {
    println!("🔒 Demo di Validazione Transazioni Blockchain");
    println!("============================================\n");
    
    // 1. Generiamo due coppie di chiavi (Alice e Bob)
    let alice_private = PrivateKey::new_key();
    let alice_public = alice_private.public_key();
    let alice_address = Transaction::public_key_to_address(&alice_public);
    
    let bob_private = PrivateKey::new_key();
    let bob_public = bob_private.public_key();
    let bob_address = Transaction::public_key_to_address(&bob_public);
    
    println!("Alice address: {:02x?}", &alice_address[..8]);
    println!("Bob address: {:02x?}", &bob_address[..8]);

    // 2. Creiamo un UTXO set iniziale (Alice ha 100 monete)
    let mut utxo_set = UTXOSet::new();
    
    // Simuliamo una transazione precedente (genesis o coinbase)
    let genesis_tx_hash = Hash::hash(b"genesis_transaction");
    let initial_output = TxOutput {
        amount: 100,
        recipient: alice_address,
    };
    utxo_set.insert((genesis_tx_hash, 0), initial_output);
    
    println!("\nUTXO iniziale: Alice ha 100 monete");
    println!("UTXO Set size: {}", utxo_set.len());
    
    // 3. Alice crea una transazione per inviare 50 monete a Bob
    // Creiamo una firma dummy temporanea
    let dummy_hash = Hash::hash(b"dummy");
    let dummy_signature = Signature::sign_output(&dummy_hash, &alice_private);
    
    let input = TxInput {
        previous_tx_id: genesis_tx_hash.as_bytes(),
        output_index: 0,
        signature: dummy_signature, // Verrà sostituito quando firmiamo
        public_key: alice_public.clone(),
    };
    
    let output_to_bob = TxOutput {
        amount: 50,
        recipient: bob_address,
    };
    
    let change_to_alice = TxOutput {
        amount: 45, // Alice si tiene 45, 5 di fee
        recipient: alice_address,
    };
    
    let mut transaction = Transaction::new(
        vec![input],
        vec![output_to_bob, change_to_alice],
    );

    println!("\nTransazione creata:");
    println!("   Input: {} monete da Alice", 100);
    println!("   Output 1: {} monete a Bob", 50);
    println!("   Output 2: {} monete (change) ad Alice", 45);
    println!("   Fee: {} monete", 5);
    
    // 4. Alice firma la transazione
    println!("\nAlice firma la transazione...");
    transaction.sign_input(0, &alice_private)?;
    println!("Transazione firmata!");
    
    // 5. Calcoliamo le fee
    let fee = transaction.calculate_fee(&utxo_set)?;
    println!("Fee calcolata: {} monete", fee);
    
    // 6. Validazione della transazione
    println!("\nValidazione della transazione...");
    
    match transaction.validate(&utxo_set) {
        Ok(()) => {
            println!("Transazione valida!");

            // 7. Applichiamo la transazione all'UTXO set
            println!("\nApplicazione al UTXO set...");
            transaction.apply_to_utxo_set(&mut utxo_set)?;

            println!("Transazione applicata con successo!");
            println!("Nuovo UTXO Set size: {}", utxo_set.len());

            // Mostriamo i nuovi UTXO
            let tx_hash = transaction.hash();
            println!("\nNuovi UTXO creati:");
            println!("   TX Hash: {}", tx_hash);
            println!("   Output 0: {} monete per Bob", 50);
            println!("   Output 1: {} monete per Alice", 45);

        }
        Err(e) => {
            println!("Transazione non valida: {:?}", e);
        }
    }
    
    // 8. Test di validazione con errori
    println!("\nTest di prevenzione doppia spesa...");
    
    // Proviamo a riutilizzare lo stesso input (doppia spesa)
    let dummy_signature2 = Signature::sign_output(&dummy_hash, &alice_private);
    let double_spend_tx = Transaction::new(
        vec![TxInput {
            previous_tx_id: genesis_tx_hash.as_bytes(),
            output_index: 0,
            signature: dummy_signature2,
            public_key: alice_public.clone(),
        }],
        vec![TxOutput {
            amount: 10,
            recipient: bob_address,
        }],
    );
    
    match double_spend_tx.validate(&utxo_set) {
        Ok(()) => println!("ERRORE: Doppia spesa non rilevata!"),
        Err(ValidationError::InputNotFound) => println!("Doppia spesa correttamente prevenuta!"),
        Err(e) => println!("Errore inaspettato: {:?}", e),
    }

    Ok(())
}