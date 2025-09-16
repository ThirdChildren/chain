use blake3::Hasher;

pub struct Hash {
    value: Vec<u8>,
}

impl Hash {
    pub fn new(data: &[u8]) -> Self {
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();
        Hash {
            value: hash.as_bytes().to_vec(),
        }
    }

    pub fn to_hex(&self) -> String {
        hex::encode(&self.value)
    }

    pub fn from_hex(hex_str: &str) -> Option<Self> {
        match hex::decode(hex_str) {
            Ok(bytes) => Some(Hash { value: bytes }),
            Err(_) => None,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
}