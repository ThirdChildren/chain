/// Example demonstrating the crypto backend system
/// This example works with any enabled backend (secp256k1 or mldsa)
/// 
/// Run with:
/// - Default (secp256k1): `cargo run --example crypto_backend_demo`
/// - ML-DSA: `cargo run --no-default-features --features mldsa --example crypto_backend_demo`

use rustcore::crypto::{PrivateKey, PublicKey, Signature, Hash, CryptoKey, CryptoSignature};

fn main() {
    println!("=== Crypto Backend Demo ===\n");
    
    // Display which backend is active
    #[cfg(feature = "secp256k1")]
    println!("Active backend: secp256k1 (ECDSA)");
    
    #[cfg(feature = "mldsa")]
    println!("Active backend: ML-DSA (CRYSTALS-Dilithium)\n");
    
    // Generate a new keypair
    println!("1. Generating keypair...");
    let private_key = PrivateKey::new_key();
    let public_key = private_key.public_key();
    
    println!("   Private key size: {} bytes", private_key.to_bytes().len());
    println!("   Public key size: {} bytes", public_key.to_bytes().len());
    
    // Create some data to sign
    println!("\n2. Creating data to sign...");
    let data = b"Hello, blockchain world!";
    let hash = Hash::hash(data);
    println!("   Data: {:?}", String::from_utf8_lossy(data));
    println!("   Hash: {}", hex::encode(hash.as_bytes()));
    
    // Sign the hash
    println!("\n3. Signing the hash...");
    let signature = Signature::sign_output(&hash, &private_key);
    println!("   Signature size: {} bytes", signature.to_bytes().len());
    println!("   Signature (first 32 bytes): {}", 
             hex::encode(&signature.to_bytes()[..32.min(signature.to_bytes().len())]));
    
    // Verify the signature
    println!("\n4. Verifying the signature...");
    let is_valid = signature.verify(&hash, &public_key);
    println!("   Signature valid: {}", is_valid);
    assert!(is_valid, "Signature should be valid!");
    
    // Try to verify with wrong data
    println!("\n5. Testing with wrong data...");
    let wrong_data = b"This is different data";
    let wrong_hash = Hash::hash(wrong_data);
    let is_valid_wrong = signature.verify(&wrong_hash, &public_key);
    println!("   Signature valid with wrong data: {}", is_valid_wrong);
    assert!(!is_valid_wrong, "Signature should be invalid with wrong data!");
    
    // Test key serialization
    println!("\n6. Testing key serialization...");
    let pub_bytes = public_key.to_bytes();
    let pub_restored = PublicKey::from_bytes(&pub_bytes)
        .expect("Failed to deserialize public key");
    println!("   Public key serialization: OK");
    
    let priv_bytes = private_key.to_bytes();
    let _priv_restored = PrivateKey::from_bytes(&priv_bytes)
        .expect("Failed to deserialize private key");
    println!("   Private key serialization: OK");
    
    // Verify with restored keys
    println!("\n7. Verifying with restored keys...");
    let is_valid_restored = signature.verify(&hash, &pub_restored);
    println!("   Signature valid with restored public key: {}", is_valid_restored);
    assert!(is_valid_restored, "Signature should be valid with restored key!");
    
    // Test signature serialization
    println!("\n8. Testing signature serialization...");
    let sig_bytes = signature.to_bytes();
    let sig_restored = Signature::from_bytes(&sig_bytes)
        .expect("Failed to deserialize signature");
    let is_valid_sig_restored = sig_restored.verify(&hash, &public_key);
    println!("   Restored signature valid: {}", is_valid_sig_restored);
    assert!(is_valid_sig_restored, "Restored signature should be valid!");
    
    println!("\n=== All tests passed! ===");
    
    // Display key size comparison
    println!("\n--- Key Size Information ---");
    #[cfg(feature = "secp256k1")]
    {
        println!("Backend: secp256k1");
        println!("  - Public key: ~65 bytes");
        println!("  - Private key: 32 bytes");
        println!("  - Signature: ~72 bytes");
    }
    
    #[cfg(feature = "mldsa")]
    {
        println!("Backend: ML-DSA (Dilithium5)");
        println!("  - Public key: 2592 bytes");
        println!("  - Private key: 4864 bytes");
        println!("  - Signature: 4595 bytes");
        println!("  - Security: Post-quantum (NIST Level 5)");
    }
}
