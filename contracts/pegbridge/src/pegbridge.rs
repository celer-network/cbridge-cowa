use prost::Message;

include!(concat!(env!("OUT_DIR"), "/pegbridge.rs"));

pub fn deserialize_mint(buf: &[u8]) -> Result<Mint, prost::DecodeError> {
    Mint::decode(buf)
}
