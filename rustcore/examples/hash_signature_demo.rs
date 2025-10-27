use rustcore::crypto::{Hash, PrivateKey, Signature};
use rustcore::crypto::backend::{CryptoKey, CryptoSignature};

fn main() {
    println!("=== Demo: Hash e Firma Digitale ===\n");

    // 1. Genera una coppia di chiavi
    println!("1. Generazione chiavi:");
    let alice_private = PrivateKey::new_key();
    let alice_public = alice_private.public_key();
    println!("   Chiave privata generata: {} bytes", alice_private.to_bytes().len());
    println!("   Chiave pubblica derivata: {} bytes\n", alice_public.to_bytes().len());

    // 2. Crea un messaggio da firmare
    println!("2. Messaggio da firmare:");
    let message = b"Alice paga a Bob 50 BTC";
    println!("   Messaggio: {:?}\n", std::str::from_utf8(message).unwrap());

    // 3. Hash del messaggio
    println!("3. Hash del messaggio:");
    let message_hash = Hash::hash(message);
    println!("   Hash: {}\n", message_hash);

    // 4. Firma del hash
    println!("4. Firma digitale:");
    let signature = Signature::sign_output(&message_hash, &alice_private);
    println!("   Firma creata: {} bytes", signature.to_bytes().len());
    println!("   (La firma viene generata con la chiave privata)\n");

    // 5. Verifica della firma
    println!("5. Verifica della firma:");
    let is_valid = signature.verify(&message_hash, &alice_public);
    println!("   Firma valida: {}", if is_valid { "✓ SI" } else { "✗ NO" });
    println!("   (La verifica usa solo la chiave pubblica)\n");

    // 6. Test con messaggio modificato (attacco!)
    println!("6. Test di sicurezza - messaggio modificato:");
    let tampered_message = b"Alice paga a Bob 500 BTC"; // Modificato!
    let tampered_hash = Hash::hash(tampered_message);
    println!("   Messaggio alterato: {:?}", std::str::from_utf8(tampered_message).unwrap());
    println!("   Nuovo hash: {}", tampered_hash);
    
    let is_valid_tampered = signature.verify(&tampered_hash, &alice_public);
    println!("   Firma valida: {}", if is_valid_tampered { "✓ SI" } else { "✗ NO" });
    println!("   Risultato: {} ← La firma NON è valida!\n", 
             if !is_valid_tampered { "ATTACCO RILEVATO" } else { "PROBLEMA!" });

    // 7. Hash complesso con più dati
    println!("7. Hash di transazione complessa:");
    let tx_hash = Hash::compute(|hasher| {
        hasher.input(b"sender: alice");
        hasher.input(b"receiver: bob");
        hasher.input(50u64); // amount
        hasher.input(1u32);  // nonce
        hasher.input(1698765432u64); // timestamp
    });
    println!("   Hash transazione: {}", tx_hash);
    
    let tx_signature = Signature::sign_output(&tx_hash, &alice_private);
    println!("   Firma transazione: {} bytes", tx_signature.to_bytes().len());
    
    let tx_valid = tx_signature.verify(&tx_hash, &alice_public);
    println!("   Verifica: {}\n", if tx_valid { "✓ VALIDA" } else { "✗ NON VALIDA" });

    // 8. Multiple firme (scenario multi-party)
    println!("8. Scenario multi-party (Alice e Bob firmano):");
    
    let bob_private = PrivateKey::new_key();
    let bob_public = bob_private.public_key();
    
    let contract = b"Smart contract: Alice e Bob accettano i termini";
    let contract_hash = Hash::hash(contract);
    
    println!("   Contratto: {:?}", std::str::from_utf8(contract).unwrap());
    println!("   Hash contratto: {}", contract_hash);
    
    let alice_sig = Signature::sign_output(&contract_hash, &alice_private);
    let bob_sig = Signature::sign_output(&contract_hash, &bob_private);
    
    let alice_valid = alice_sig.verify(&contract_hash, &alice_public);
    let bob_valid = bob_sig.verify(&contract_hash, &bob_public);
    
    println!("   Firma Alice valida: {}", if alice_valid { "✓" } else { "✗" });
    println!("   Firma Bob valida: {}", if bob_valid { "✓" } else { "✗" });
    println!("   Contratto validato: {}\n", if alice_valid && bob_valid { "✓ SI" } else { "✗ NO" });

    // 9. Serializzazione e deserializzazione
    println!("9. Serializzazione firma:");
    let sig_bytes = signature.to_bytes();
    println!("   Firma serializzata: {} bytes", sig_bytes.len());
    println!("   Primi 8 bytes: {:02x?}", &sig_bytes[..8.min(sig_bytes.len())]);
    
    match Signature::from_bytes(&sig_bytes) {
        Ok(recovered_sig) => {
            let still_valid = recovered_sig.verify(&message_hash, &alice_public);
            println!("   Firma deserializzata e verificata: {}\n", 
                     if still_valid { "✓ OK" } else { "✗ ERRORE" });
        }
        Err(e) => println!("   Errore deserializzazione: {:?}\n", e),
    }

    // 10. Riepilogo del processo
    println!("=== Riepilogo del Processo ===");
    println!("1. Messaggio → Hash (Blake3, 32 bytes)");
    println!("2. Hash + Chiave Privata → Firma");
    println!("3. Firma + Hash + Chiave Pubblica → Verifica");
    println!("\n✓ La firma garantisce:");
    println!("  - Autenticità (chi ha firmato)");
    println!("  - Integrità (il messaggio non è stato modificato)");
    println!("  - Non ripudio (il firmatario non può negare)");
    
    #[cfg(feature = "secp256k1")]
    println!("\n📌 Backend attivo: secp256k1 (ECDSA)");
    
    #[cfg(feature = "mldsa")]
    println!("\n📌 Backend attivo: ML-DSA/Dilithium5 (Post-Quantum)");
}
