use prost::Message;

/// withdraw locked original tokens
/// triggered by burn at the pegged token bridge
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Withdraw {
    #[prost(bytes="vec", tag="1")]
    pub token: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="2")]
    pub receiver: ::prost::alloc::vec::Vec<u8>,
    #[prost(bytes="vec", tag="3")]
    pub amount: ::prost::alloc::vec::Vec<u8>,
    /// burn_account defines the account that burned the pegged token.
    /// Not applicable to fee claims and governance-triggered withdrawals.
    #[prost(bytes="vec", tag="4")]
    pub burn_account: ::prost::alloc::vec::Vec<u8>,
    /// ref_chain_id defines the reference chain ID, taking values of:
    /// 1. The common case of burn-withdraw: the chain ID on which the corresponding burn happened;
    /// 2. Pegbridge fee claim: zero / Not applicable;
    /// 3. Other governance-triggered withdrawals: the chain ID on which the withdrawal will happen.
    #[prost(uint64, tag="5")]
    pub ref_chain_id: u64,
    /// ref_id defines a unique reference ID, taking values of:
    /// 1. The common case of burn-withdraw: the burn ID;
    /// 2. Pegbridge fee claim: a per-account nonce;
    /// 3. Refund for wrong deposit: the deposit ID;
    /// 4. Governance-triggered withdrawal: ID as needed.
    #[prost(bytes="vec", tag="6")]
    pub ref_id: ::prost::alloc::vec::Vec<u8>,
}

pub fn deserialize_withdraw(buf: &[u8]) -> Result<Withdraw, prost::DecodeError> {
    Withdraw::decode(buf)
}
