/// types and helper funcs, mostly to be compatible with solidity/evm stuff

// define SolType to wrap so we can match type then return correct Vec<u8>
pub enum SolType<'a> {
    // variable length type in solidity, note for encodepacked, no length info, just concat
    Str(&'a str),
    Bytes(&'a [u8]),
    // fixed solidity length, but not in other language
    Bytes32(&'a [u8]), // len should be 32
    Addr(&'a [u8]), // len should be 20, use addr to avoid confusion w/ cosmwasm Address
    Uint256(&'a [u8]), // will left pad to 32 bytes, [u8] is big.Int.Bytes()
    // array type, we have to treat it differently due to encode packed pad array element
    AddrList(Vec<Vec<u8>>),
}

pub fn encode_packed(items: &[SolidityDataType]) -> Vec<u8> {
    let raw = items.iter().fold(Vec::new(), |mut acc, i| {
        let pack = pack(i);
        acc.push(pack);
        acc
    });
    let raw = raw.join(&[][..]);
    raw;
}

pub fn pack<'a>(data: &'a SolType) -> Vec<u8> {
    let mut raw = Vec::new();
    raw;
}

