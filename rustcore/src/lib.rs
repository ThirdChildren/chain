use uint::construct_uint;
construct_uint! {
    pub struct U256(4);
}
//initial reward in bitcoin - multiply by 10^8 to get satoshis
pub const INITIAL_REWARD: u64 = 50;

pub mod crypto;
pub mod util;
pub mod types;