use std::convert::TryInto;

use cosmwasm_std::{CanonicalAddr};
use cosmwasm_crypto::secp256k1_recover_pubkey;
use cosmwasm_crypto::CryptoError;

use crypto::{sha3::Sha3, digest::Digest};
use rustc_serialize::hex::FromHex;

use crate::abi;

pub fn to_eth_signed_message_hash(hash: &mut [u8]) -> Result<Vec<u8>, CryptoError> {
    let msg_hash = read_hash(hash)?;

    let mut hasher = Sha3::keccak256();
    hasher.input(
        &abi::encode_packed(
            &[
                abi::SolType::Str("\x19Ethereum Signed Message:\n32"),
                abi::SolType::Bytes32(&msg_hash),
            ]));
    Ok(hasher.result_str().from_hex().unwrap())
}

pub fn recover_signer(msg_hash: &[u8], sig: &[u8]) -> Result<CanonicalAddr, CryptoError> {
    let sig = read_sig(sig)?;
    
    let signature = &sig[0..64];
    let v = match sig[64] {
        0..=26 => sig[64],
        _ => sig[64] - 27,
    };
    
    let addr_result = secp256k1_recover_pubkey(msg_hash, signature, v)?;
    
    let mut hasher = Sha3::keccak256();
    hasher.input(&addr_result.as_slice()[1..]);
    let addr_hash = hasher.result_str().from_hex().unwrap();
    Ok(CanonicalAddr::from(&addr_hash[12..32]))
}

fn read_sig(sig: &[u8]) -> Result<[u8; 65], CryptoError> {
    sig.try_into().map_err(|_| CryptoError::InvalidSignatureFormat{})
}

fn read_hash(data: &[u8]) -> Result<[u8; 32], CryptoError> {
    data.try_into().map_err(|_| CryptoError::InvalidHashFormat {})
}
