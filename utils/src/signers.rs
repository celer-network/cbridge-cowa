/// signers keep a map of CanonicalAddr(eth 20 bytes) to U256 sign power
/// and can verify if a msg has enough sigs
/// we don't save a hash like evm because it tradeoff more calldata to save storage cost
use std::{collections::HashMap, convert::TryInto};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crypto::{sha3::Sha3, digest::Digest};
use crate::abi;

use cosmwasm_std::{Addr, CanonicalAddr, Deps, Storage, Response, StdError, StdResult, Uint128, DepsMut};
use cw_storage_plus::{Item};

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
    Item<'a, HashMap<CanonicalAddr, Uint128>>
);

// this is the core business logic we expose
impl<'a> Signers<'a> {
    pub const fn new() -> Self {
        // I don't know how to concat &str and literal in const fn so just hardcode within this fn
        Signers(Item::new("signers_state"), Item::new("signers"))
    }

    /// only allow set once. if already set, fail
    pub fn init_set(&self, store: &mut dyn Storage) -> StdResult<()> {
        // storage has way to check if a key exists but it's hidden by Item.
        match self.0.may_load(store)? {
            // not found, ok to set
            None => self.0.save(store, &SignersState{
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
    pub fn reset_signers(&self, store: &mut dyn Storage, block_time: u64, signers:&[&CanonicalAddr], powers: &[&Uint128]) -> Result<Response, SignersError> {
        let signer_state = &mut self.0.load(store)?;
        if signer_state.reset_time >= block_time {
            return Err(SignersError::Std(StdError::generic_err("not reach reset time")));
        }
        signer_state.reset_time = u64::MAX;
        self.0.save(store, signer_state)?;

        self._update_signers(store, signers, powers)
    }

    fn _update_signers(&self, store: &mut dyn Storage, signers:&[&CanonicalAddr], powers: &[&Uint128]) -> Result<Response, SignersError> {
        if signers.len() != powers.len() {
            return Err(SignersError::Std(StdError::generic_err("signers and powers length not match")));
        }
        let mut signer_powers: HashMap<CanonicalAddr, Uint128> = HashMap::new();
        for i in 0..signers.len() {
            signer_powers.insert(signers[i].clone(), *powers[i]);
        }
        self.1.save(store, &signer_powers)?;

        Ok(Response::new())
    }

    /// only should be called by contract owner, calling contract MUST check!!!
    /// this func has NO sender check and will update internal map directly
    pub fn notify_reset_signers(&self, store: &mut dyn Storage, block_time: u64) -> Result<Response, SignersError> {
        let signer_state = &mut self.0.load(store)?;
        signer_state.reset_time = block_time + signer_state.notice_period;
        self.0.save(store, signer_state)?;

        Ok(Response::new()
            .add_attribute("action", "notify_reset_signers")
            .add_attribute("reset_time", signer_state.reset_time.to_string()))
    }
    /// only should be called by contract owner, calling contract MUST check!!!
    /// this func has NO sender check and will update internal map directly
    pub fn incr_notice_period(&self, store: &mut dyn Storage, new_period: u64) -> Result<Response, SignersError> {
        let signer_state = &mut self.0.load(store)?;
        if signer_state.notice_period >= new_period {
            return Err(SignersError::Std(StdError::generic_err("notice period can only be increased")));
        }
        signer_state.notice_period = new_period;
        self.0.save(store, signer_state)?;
        Ok(Response::new())
    }

    /// we have to be consistent with how data is signed in sgn and verified in solidity
    pub fn update_signers(&self, deps: DepsMut, trigger_time: u64, contract_addr: Addr, new_signers:&[&CanonicalAddr], new_powers: &[&Uint128], sigs: &[&[u8]]) -> Result<Response, SignersError> {
        let signer_state = &mut self.0.load(deps.storage)?;
        if signer_state.trigger_time >= trigger_time {
            return Err(SignersError::Std(StdError::generic_err("Trigger time is not increasing")));
        }
        
        // calculate msg, then verify_sigs, then update
        let mut hasher = Sha3::keccak256();
        hasher.input(
            &abi::encode_packed(
                &[
                    abi::SolType::Bytes(&abi::CHAIN_ID.to_be_bytes()), 
                    abi::SolType::Bytes(contract_addr.as_bytes()),
                    abi::SolType::Str("update_signers")
                ]));
        let domain: &mut [u8] = &mut [];
        hasher.result(domain);
        hasher.input(
            &abi::encode_packed(
                &[
                    abi::SolType::Bytes(domain), 
                    abi::SolType::Bytes(&trigger_time.to_be_bytes()),
                    abi::SolType::AddrList(&new_signers.iter().map(
                        |i| -> [u8;20] {
                            let a: Result<[u8;20], _> = i.as_slice().try_into();
                            a.unwrap()
                        }).collect()),
                    abi::SolType::Uint128List(&new_powers.iter().map(
                        |i| -> [u8;16] {
                            let a: Result<[u8;16], _> = i.u128().to_be_bytes().try_into();
                            a.unwrap()
                        }).collect()), 
                ]));
        let msg: &mut [u8] = &mut [];
        hasher.result(msg);

        self.verify_sigs(deps.as_ref(), msg, sigs)?;

        self._update_signers(deps.storage, new_signers, new_powers)?;

        signer_state.trigger_time = trigger_time;
        self.0.save(deps.storage, signer_state)?;
        Ok(Response::new())
    }

    /// verify msg is signed with enough power, msg will be keccak256(_msg).toEthSignedMessageHash() internally
    pub fn verify_sigs(&self, deps: Deps, msg: &[u8], sigs: &[&[u8]]) -> Result<Response, SignersError> {
        //bytes32 h = keccak256(abi.encodePacked(_signers, _powers));
        //require(ssHash == h, "Mismatch current signers");
        // require(_signers.length == _powers.length, "signers and powers length not match");
        // uint256 totalPower; // sum of all signer.power
        // for (uint256 i = 0; i < _signers.length; i++) {
        //     totalPower += _powers[i];
        // }
        // uint256 quorum = (totalPower * 2) / 3 + 1;

        // uint256 signedPower; // sum of signer powers who are in sigs
        // address prev = address(0);
        // uint256 index = 0;
        // for (uint256 i = 0; i < _sigs.length; i++) {
        //     address signer = _hash.recover(_sigs[i]);
        //     require(signer > prev, "signers not in ascending order");
        //     prev = signer;
        //     // now find match signer add its power
        //     while (signer > _signers[index]) {
        //         index += 1;
        //         require(index < _signers.length, "signer not found");
        //     }
        //     if (signer == _signers[index]) {
        //         signedPower += _powers[index];
        //     }
        //     if (signedPower >= quorum) {
        //         // return early to save gas
        //         return;
        //     }
        // }
        // revert("quorum not reached");
        Ok(Response::new())
    }

    /// return signerstate. if not set, error
    pub fn get_state(&self, deps: Deps) -> StdResult<SignersState> {
        self.0.load(deps.storage)
    }
}