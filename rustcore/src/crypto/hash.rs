//use blake3::Hasher;
use crate::U256;
use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct Hash (U256);
impl Hash {
    pub fn hash<T: serde::Serialize>(data: &T) -> Self {
         let mut serialized: Vec<u8> = vec![];
         if let Err(e) = ciborium::into_writer(data, &mut serialized) {
            panic!(
                "Failed to serialize data: {:?}. \
                 This should not happen",
                e
            );
        }
        let hash = blake3::hash(&serialized);
        let hash_bytes = hash.as_bytes();
        let hash_array: [u8; 32] = hash_bytes.as_slice().try_into().unwrap();
        Hash(U256::from_little_endian(&hash_array))
    }

    //check if a hash matches a target
    pub fn matches_target(&self, target: U256) -> bool {
        self.0 <= target
    }

    //zero hash
    pub fn zero() -> Self {
        Hash(U256::zero())
    }

     pub fn as_bytes(&self) -> [u8; 32] {
        let mut bytes: Vec<u8> = vec![0; 32];
        self.0.write_as_little_endian(&mut bytes);
        bytes.as_slice().try_into().unwrap()
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}