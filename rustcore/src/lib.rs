use uint::construct_uint;
construct_uint! {
    pub struct U256(4);
}

const BLOCK_REWARD: u64 = 50;

pub mod crypto;
pub mod types;
pub mod util;
