use rustcore::crypto::{
    DefaultBackend, DefaultKeyPair, CryptoBackend, CryptoKey, CryptoSignature, Hash,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Rustcore Crypto System Demo");
    
    // Generate a new key pair using the default backend (secp256k1)
    println!("\n📝 Generating new key pair...");
    let keypair: DefaultKeyPair = DefaultBackend::generate_keypair();
    println!("✅ Key pair generated successfully!");
    
    // Create some test data to sign
    let test_data = "Hello, blockchain!";
    let data_hash = Hash::hash(test_data.as_bytes());
    println!("\n📊 Test data: {}", test_data);
    println!("📋 Data hash: {}", data_hash);
    
    // Sign the data
    println!("\n✍️  Signing data...");
    let signature = DefaultBackend::sign(&data_hash, &keypair.private_key);
    println!("✅ Data signed successfully!");
    
    // Verify the signature
    println!("\n🔍 Verifying signature...");
    let is_valid = DefaultBackend::verify(&signature, &data_hash, &keypair.public_key);
    println!("✅ Signature valid: {}", is_valid);
    
    // Demonstrate simple byte operations
    println!("\n💾 Testing basic operations...");
    
    // Convert keys to bytes (simplified)
    let private_key_bytes = keypair.private_key.to_bytes();
    let public_key_bytes = keypair.public_key.to_bytes();
    println!("✅ Private key serialized to {} bytes", private_key_bytes.len());
    
    // Show key bytes representation
    println!("\n🔑 Key information:");
    println!("Public key bytes: {} bytes", public_key_bytes.len());
    println!("Private key bytes: {} bytes", private_key_bytes.len());
    println!("Signature bytes: {} bytes", signature.to_bytes().len());
    
    Ok(())
}