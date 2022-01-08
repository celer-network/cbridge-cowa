/// signers keep a map of CanonicalAddr(eth 20 bytes) to U256 sign power
/// and can verify if a msg has enough sigs
/// we don't save a hash like evm because it tradeoff more calldata to save storage cost
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use thiserror::Error;

use cosmwasm_std::{CanonicalAddr, Deps, DepsMut, Response, StdError, StdResult, Uint128};
use cw_storage_plus::{Item, Map};

/// Errors returned from Signers
#[derive(Error, Debug, PartialEq)]
pub enum SignersError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Caller is not owner")]
    NotOwner {},

    #[error("signing power not enough")]
    NotEnoughPower {},

    #[error("triggerTime is not valid")]
    BadTriggerTime {},
}

/// save triggerTime, resetTime and noticePeriod
/// all numbers are native u64 as u256 is overkill just cheaper on solidity
/// we don't save owner internally, and just depend on calling contracts
/// have proper owner check. this is due to cosmwasm has no contract inherit
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct SignersState {
    pub trigger_time: u64,
    pub reset_time: u64,
    pub notice_period: u64,
}

/// Signers has 0 as state and 1 a map of CanoAddr to signing power
/// note we use Uint128 as it's a wrap of native u128 and cheaper and should be enough
/// also here we MUST use CanonicalAddr as key because recovered signers are ETH addr 20 bytes
pub struct Signers<'a>(
    Item<'a, SignersState>,
    Map<'a, &'a CanonicalAddr, Uint128>
);

// this is the core business logic we expose
impl<'a> Signers<'a> {
    pub const fn new() -> Self {
        // I don't know how to concat &str and literal in const fn so just hardcode within this fn
        Signers(Item::new("signers_state"), Map::new("signers_map"))
    }

    /// only allow set once. if already set, fail
    pub fn init_set(&self, deps: DepsMut) -> StdResult<()> {
        // storage has way to check if a key exists but it's hidden by Item.
        match self.0.may_load(deps.storage)? {
            // not found, ok to set
            None => self.0.save(deps.storage, &SignersState{
                notice_period: 0,
                reset_time: 0,
                trigger_time: 0,
            }),
            // found SignersState, return error
            Some(_) => Err(StdError::generic_err("init_set called after state already set")),
        }
    }

    /// only should be called by contract owner, calling contract MUST check!!!
    /// this func has NO sender check and will update internal map directly
    /// block_time is env.block.time.seconds();
    pub fn reset_signers(&self, block_time: u64) -> StdResult<()> {
        // todo: impl
        Ok(())
    }

    /// only should be called by contract owner, calling contract MUST check!!!
    /// this func has NO sender check and will update internal map directly
    pub fn notify_reset_signers(&self, block_time: u64) -> Result<Response, SignersError> {
        // todo: impl
        Ok(Response::new())
    }
    /// only should be called by contract owner, calling contract MUST check!!!
    /// this func has NO sender check and will update internal map directly
    pub fn incr_notice_period(&self, new_period: u64) -> Result<Response, SignersError> {
        // todo: impl
        Ok(Response::new())
    }

    /// we have to be consistent with how data is signed in sgn and verified in solidity
    pub fn update_signers(&self, _trigger_time: u64, new_signers:&[&CanonicalAddr], new_powers: &[&Uint128], sigs: &[&[u8]], ) -> Result<Response, SignersError> {
        // calculate msg, then verify_sigs, then update
        Ok(Response::new())
    }

    /// verify msg is signed with enough power, msg will be keccak256(_msg).toEthSignedMessageHash() internally
    pub fn verify_sigs(&self, deps: Deps, msg: &[u8], sigs: &[&[u8]]) -> Result<Response, SignersError> {
        Ok(Response::new())
    }

    /// return signerstate. if not set, error
    pub fn get_state(&self, deps: Deps) -> StdResult<SignersState> {
        self.0.load(deps.storage)
    }
}