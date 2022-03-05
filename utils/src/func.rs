use std::convert::TryInto;

use cosmwasm_std::{CanonicalAddr};
use cosmwasm_crypto::secp256k1_recover_pubkey;
use cosmwasm_crypto::CryptoError;

use crypto::{sha3::Sha3, digest::Digest};
use rustc_serialize::hex::FromHex;

use crate::abi;

pub fn to_eth_signed_message_hash(hash: &mut [u8]) -> Result<Vec<u8>, CryptoError> {
    let msg_hash = read_hash(hash)?;

    let result = keccak256(&abi::encode_packed(
        &[
            abi::SolType::Str("\x19Ethereum Signed Message:\n32"),
            abi::SolType::Bytes32(&msg_hash),
        ]));
    Ok(result)
}

pub fn recover_signer(msg_hash: &[u8], sig: &[u8]) -> Result<CanonicalAddr, CryptoError> {
    let sig = read_sig(sig)?;
    
    let signature = &sig[0..64];
    let v = match sig[64] {
        0..=26 => sig[64],
        _ => sig[64] - 27,
    };
    
    let addr_result = secp256k1_recover_pubkey(msg_hash, signature, v)?;
    let addr_hash = keccak256(&addr_result.as_slice()[1..]);
    Ok(CanonicalAddr::from(&addr_hash[12..32]))
}

fn read_sig(sig: &[u8]) -> Result<[u8; 65], CryptoError> {
    sig.try_into().map_err(|_| CryptoError::InvalidSignatureFormat{})
}

fn read_hash(data: &[u8]) -> Result<[u8; 32], CryptoError> {
    data.try_into().map_err(|_| CryptoError::InvalidHashFormat {})
}

pub fn get_domain(contract_addr: CanonicalAddr, method: &str) -> Vec<u8> {
    keccak256(&abi::encode_packed(
        &[
            abi::SolType::Uint256(&cosmwasm_std::Uint256::from(abi::CHAIN_ID).to_be_bytes()), 
            abi::SolType::Addr(contract_addr.as_slice()[0..20].try_into().unwrap()),
            abi::SolType::Str(method)
        ]))
}

pub fn keccak256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha3::keccak256();
    hasher.input(data);
    hasher.result_str().from_hex().unwrap()
}
