/*
use sha3::Keccak256;
use cosmwasm_std::CanonicalAddr;
use cosmwasm_crypto::secp256k1_recover_pubkey;

fn keccak(input: &[u8]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    keccak256(&input, &mut hash);
    hash
}

pub fn recover_signer(self, block_hash: &Vec<u8>) -> CanonicalAddr {
        let mut hasher = Sha256::new();
        hasher.update([self.signed_data_prefix.as_slice(), block_hash.as_slice(), self.signed_data_suffix.as_slice()].concat());
        let hash_result = Vec::from(&hasher.finalize()[..]);
        let signature = [self.r, self.s].concat();
        let addr_result = secp256k1_recover_pubkey(hash_result.as_slice(), signature.as_slice(), self.v-27u8).unwrap();
        let mut hasher = Keccak256::new();
        hasher.update(&addr_result.as_slice()[1..]);
        let result = &hasher.finalize()[12..32];
        return CanonicalAddr::from(result);
    }
*/