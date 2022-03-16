use core::panic;

/// types and helper funcs, mostly to be compatible with solidity/evm stuff
// define SolType to wrap so we can match type then return correct Vec<u8>
pub enum SolType<'a> {
    // variable length type in solidity, note for encodepacked, no length info, just concat
    Str(&'a str),
    Bytes(&'a [u8]),
    // fixed solidity length, but not in other language
    Bytes32(&'a [u8; 32]), // len should be 32
    Addr(&'a [u8; 20]), // len should be 20, use addr to avoid confusion w/ cosmwasm Address
    Uint256(&'a [u8; 32]), // will left pad to 32 bytes, [u8] is big.Int.Bytes()
    // array type, we have to treat it differently due to encode packed pad array element
    AddrList(&'a Vec<[u8; 20]>),
    Uint256List(&'a Vec<[u8; 32]>),
}

pub type Word = [u8; 32];

pub const CHAIN_ID: u64 = 999999999;

pub fn encode_packed(items: &[SolType]) -> Vec<u8> {
    let raw = items.iter().fold(Vec::new(), |mut acc, i| {
        let pack = pack(i);
        acc.push(pack);
        acc
    });
    let raw = raw.join(&[][..]);
    raw
}

pub fn pack<'a>(data: &'a SolType) -> Vec<u8> {
    let mut raw = Vec::new();
    match data {
        SolType::Str(s) => {
            raw.extend(s.as_bytes());
        }
        SolType::Bytes(b) => {
            raw.extend(*b);
        }
        SolType::Bytes32(b) => {
            raw.extend(*b);
        }
        SolType::Addr(a) => {
            raw.extend(*a);
        }
        SolType::Uint256(n) => {
            raw.extend(*n);
        }
        SolType::AddrList(a) => {
            let encoded = a.iter().fold(Vec::new(), |mut acc, i| {
                let padded = pad_addr(i).to_vec();
                acc.push(padded);
                acc            
            });
            let encoded = encoded.join(&[][..]);
            raw.extend(encoded);
        }
        SolType::Uint256List(a) => {
            for i in a.iter() {
                raw.extend(i);
            }
        }
    };
    return raw;
}

fn pad_addr(addr: &[u8; 20]) -> Word {
    let mut padded = [0u8; 32];
    padded[12..].copy_from_slice(addr);
    padded
}

pub fn pad_to_16_bytes(ori: &[u8]) -> [u8;16] {
    if ori.len() > 16 {
        panic!("unreachable: len bigger than 16")
    }
    let mut padded = [0u8; 16];
    let from = 16 - ori.len();
    padded[from..].copy_from_slice(ori);
    padded
}

pub fn pad_to_32_bytes(ori: &[u8]) -> [u8;32] {
    if ori.len() > 32 {
        panic!("unreachable: len bigger than 32")
    }
    let mut padded = [0u8; 32];
    let from = 32 - ori.len();
    padded[from..].copy_from_slice(ori);
    padded
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use super::*;

    #[test]
	fn encode_addr_list() {
		let addresses = vec![hex!("1111111111111111111111111111111111111111"), hex!("1111111111111111111111111111111111111112")];
        let addr_list = SolType::AddrList(&addresses);
		let encoded = encode_packed(&[addr_list]);
		let expected = hex!("00000000000000000000000011111111111111111111111111111111111111110000000000000000000000001111111111111111111111111111111111111112").to_vec();
		assert_eq!(encoded, expected);
	}
}


