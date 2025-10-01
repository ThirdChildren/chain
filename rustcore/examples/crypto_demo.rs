use rustcore::crypto::{
    DefaultBackend, DefaultKeyPair, CryptoBackend, CryptoKey, CryptoSignature, Hash,
    CborFormat, SaveableKey,
};
use rustcore::util::Saveable;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔐 Rustcore Crypto System Demo");
    
    // Generate a new key pair using the default backend (secp256k1)
    println!("\n📝 Generating new key pair...");
    let keypair: DefaultKeyPair = DefaultBackend::generate_keypair();
    println!("✅ Key pair generated successfully!");
    
    // Create some test data to sign
    let test_data = "Hello, blockchain!";
    let data_hash = Hash::hash(&test_data);
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
    
    // Demonstrate serialization
    println!("\n💾 Testing serialization...");
    
    // Save private key to CBOR format
    let saveable_private = SaveableKey::<_, CborFormat>::new(keypair.private_key.clone());
    let mut private_key_data = Vec::new();
    saveable_private.save(&mut private_key_data)?;
    println!("✅ Private key serialized to {} bytes", private_key_data.len());
    
    // Load private key back from CBOR
    let loaded_private: SaveableKey<_, CborFormat> = SaveableKey::load(private_key_data.as_slice())?;
    println!("✅ Private key deserialized successfully");
    
    // Verify the loaded key works
    let signature2 = DefaultBackend::sign(&data_hash, loaded_private.key());
    let is_valid2 = DefaultBackend::verify(&signature2, &data_hash, &keypair.public_key);
    println!("✅ Loaded key signature valid: {}", is_valid2);
    
    // Show key bytes representation
    println!("\n🔑 Key information:");
    println!("Public key bytes: {} bytes", keypair.public_key.to_bytes().len());
    println!("Private key bytes: {} bytes", keypair.private_key.to_bytes().len());
    println!("Signature bytes: {} bytes", signature.to_bytes().len());
    
    Ok(())
}