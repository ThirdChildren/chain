use rustcore::crypto::{Hash, Hasher, PrivateKey};
use rustcore::types::transaction::{Transaction, TxInput, TxOutput};

fn main() {
    println!("🚀 Demo Blake3 Hasher Incrementale");
    println!("==================================\n");
    
    // 1. Demo Hasher di base
    println!("📝 1. Hash incrementale di base:");
    
    let mut hasher = Hasher::new();
    hasher.update(b"Hello, ");
    hasher.update(b"World!");
    let hash1 = hasher.finalize();
    
    let hash2 = Hash::hash(b"Hello, World!");
    
    println!("   Hash incrementale: {}", hash1);
    println!("   Hash diretto:      {}", hash2);
    println!("   Sono uguali: {}\n", hash1 == hash2);
    
    // 2. Demo hash con builder
    println!("🔧 2. Hash con builder pattern:");
    
    let hash3 = Hash::hash_with_hasher(|hasher| {
        hasher.update(b"Part 1");
        hasher.update_u32_le(42);
        hasher.update(b"Part 2");
        hasher.update_u64_le(1234567890);
    });
    
    println!("   Hash con builder: {}\n", hash3);
    
    // 3. Demo hash multipli
    println!("📦 3. Hash di dati multipli:");
    
    let data_parts: &[&[u8]] = &[b"first", b"second", b"third"];
    let hash4 = Hash::hash_multiple(data_parts);
    
    let hash5 = Hash::hash_with_hasher(|hasher| {
        for part in data_parts {
            hasher.update(part);
        }
    });
    
    println!("   Hash multipli:     {}", hash4);
    println!("   Hash equivalente:  {}", hash5);
    println!("   Sono uguali: {}\n", hash4 == hash5);
    
    // 4. Demo con chiavi personalizzate
    println!("🔑 4. Hash con chiave personalizzata:");
    
    let key = [42u8; 32];
    let mut keyed_hasher = Hasher::new_keyed(&key);
    keyed_hasher.update(b"Authenticated data");
    let authenticated_hash = keyed_hasher.finalize();
    
    println!("   Hash autenticato: {}\n", authenticated_hash);
    
    // 5. Demo key derivation
    println!("🔐 5. Key derivation:");
    
    let mut derive_hasher = Hasher::new_derive_key("MyApp v1.0 session key");
    derive_hasher.update(b"user_id_123");
    derive_hasher.update_u64_le(1696627200); // timestamp
    let session_key = derive_hasher.finalize();
    
    println!("   Session key derivata: {}\n", session_key);
    
    // 6. Demo con transazioni - confronto efficienza
    println!("⚡ 6. Efficienza con transazioni:");
    
    // Creiamo una transazione di esempio
    let alice_private = PrivateKey::new_key();
    let alice_public = alice_private.public_key();
    let dummy_hash = Hash::hash(b"dummy");
    let dummy_signature = rustcore::crypto::Signature::sign_output(&dummy_hash, &alice_private);
    
    let input = TxInput {
        previous_tx_id: [1u8; 32],
        output_index: 0,
        signature: dummy_signature,
        public_key: alice_public,
    };
    
    let output = TxOutput {
        amount: 1000,
        recipient: [2u8; 20],
    };
    
    let tx = Transaction::new(vec![input], vec![output]);
    
    // Metodo tradizionale (serializzazione completa + hash)
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let _hash = Hash::hash(&tx.to_bytes());
    }
    let traditional_time = start.elapsed();
    
    // Metodo con Hasher incrementale
    let start = std::time::Instant::now();
    for _ in 0..1000 {
        let _hash = tx.hash_with_hasher();
    }
    let hasher_time = start.elapsed();
    
    println!("   Metodo tradizionale: {:?}", traditional_time);
    println!("   Metodo con Hasher:   {:?}", hasher_time);
    
    if hasher_time < traditional_time {
        let speedup = traditional_time.as_nanos() as f64 / hasher_time.as_nanos() as f64;
        println!("   🚀 Speedup: {:.2}x più veloce", speedup);
    } else {
        println!("   📊 Performance simile");
    }
    
    // Verifichiamo che producano lo stesso risultato
    let hash_traditional = Hash::hash(&tx.to_bytes());
    let hash_incremental = tx.hash_with_hasher();
    println!("   Risultati identici: {}", hash_traditional == hash_incremental);
    
    // 7. Demo riutilizzo hasher
    println!("\n♻️  7. Riutilizzo hasher:");
    
    let mut reusable_hasher = Hasher::new();
    
    // Primo hash
    reusable_hasher.update(b"First message");
    let first_hash = reusable_hasher.finalize();
    println!("   Primo hash: {}", first_hash);
    
    // Reset e secondo hash
    let mut reusable_hasher = Hasher::new(); // Il finalize consuma l'hasher, quindi ne creiamo uno nuovo
    reusable_hasher.update(b"Second message");
    let second_hash = reusable_hasher.finalize();
    println!("   Secondo hash: {}", second_hash);
    
    println!("\n✅ Demo completata!");
    
    // 8. Vantaggi dell'hasher incrementale
    println!("\n💡 Vantaggi dell'hasher incrementale:");
    println!("   • Nessuna allocazione intermedia di Vec<u8>");
    println!("   • Streaming dei dati direttamente nell'hasher");
    println!("   • Memory footprint ridotto per transazioni grandi");
    println!("   • Possibilità di hash autenticati con chiavi");
    println!("   • Key derivation per scopi crittografici");
    println!("   • Reset e riutilizzo dell'hasher");
}