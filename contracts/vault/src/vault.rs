use prost::Message;

include!(concat!(env!("OUT_DIR"), "/vault.rs"));

pub fn deserialize_withdraw(buf: &[u8]) -> Result<Withdraw, prost::DecodeError> {
    Withdraw::decode(buf)
}
