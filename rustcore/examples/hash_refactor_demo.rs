use rustcore::crypto::Hash;

#[derive(Debug)]
struct TestData {
    message: String,
    value: u64,
}

impl TestData {
    fn new(message: &str, value: u64) -> Self {
        Self {
            message: message.to_string(),
            value,
        }
    }
    
    fn to_bytes(&self) -> Vec<u8> {
        format!("{:?}", self).into_bytes()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔗 Simplified Hash System Demo");
    
    // Create test data
    let data = TestData::new("Hello, simplified hash!", 42);
    println!("\n📊 Test data: {:?}", data);
    
    // Simple hash method: convert to bytes and hash
    println!("\n🔄 Simple hashing method");
    let hash1 = Hash::hash(&data.to_bytes());
    println!("✅ Hash created: {}", hash1);
    
    // Hash raw data directly
    println!("\n🔄 Hash raw bytes directly");
    let raw_data = b"Hello, raw bytes!";
    let hash2 = Hash::hash(raw_data);
    println!("✅ Hash created: {}", hash2);
    
    // Show hash properties
    println!("\n📏 Hash properties:");
    println!("Hash as bytes: {:?}", &hash1.as_bytes()[..8]); // Show first 8 bytes
    println!("Hash as U256: {}", hash1.as_u256());
    println!("Hash Display: {}", hash1);
    
    // Show core functionality
    println!("\n🎯 Hash core functionality:");
    let zero_hash = Hash::zero();
    println!("Zero hash: {}", zero_hash);
    
    let target = hash1.as_u256();
    println!("Hash matches target: {}", hash1.matches_target(target));
    
    println!("\n✨ Hash system simplified!");
    println!("   - Hash focuses on core functionality");
    println!("   - Simple to_bytes() + Hash::hash() pattern");
    println!("   - No complex serialization");
    println!("   - Direct byte operations");
    
    Ok(())
}