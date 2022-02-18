use std::convert::TryInto;

use cosmwasm_std::{CanonicalAddr};
use cosmwasm_crypto::secp256k1_recover_pubkey;
use cosmwasm_crypto::CryptoError;

use crypto::{sha3::Sha3, digest::Digest};

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
    let domain: &mut [u8] = &mut [];
    hasher.result(domain);
    Ok(CanonicalAddr::from(&domain[12..32]))
}

fn read_sig(sig: &[u8]) -> Result<[u8;65], CryptoError> {
    sig.try_into().map_err(|_| CryptoError::InvalidSignatureFormat{})
}