/// signers keep a map of CanonicalAddr(eth 20 bytes) to U256 sign power
/// and can verify if a msg has enough sigs
/// we don't save a hash like evm because it tradeoff more calldata to save storage cost
use std::{collections::HashMap, convert::TryInto, ops::{Add, Mul, Div}};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::{abi, func};

use cosmwasm_std::{Addr, CanonicalAddr, Deps, Storage, Response, StdError, StdResult, Uint128, DepsMut};
use cw_storage_plus::{Item};
use cosmwasm_crypto::CryptoError;

/// Errors returned from Signers
#[derive(Error, Debug)]
pub enum SignersError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Caller is not owner")]
    NotOwner {},

    #[error("signing power not enough")]
    NotEnoughPower {},

    #[error("triggerTime is not valid")]
    BadTriggerTime {},

    #[error("{0}")]
    CryptoError(#[from] CryptoError),
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

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct SignerPowers {
    signers: Vec<CanonicalAddr>, 
    powers: Vec<Uint128>,
}

/// Signers has 0 as state and 1 a map of CanoAddr to signing power
/// note we use Uint128 as it's a wrap of native u128 and cheaper and should be enough
/// also here we MUST use CanonicalAddr as key because recovered signers are ETH addr 20 bytes
pub struct Signers<'a>(
    Item<'a, SignersState>,
    Item<'a, SignerPowers>
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
    pub fn reset_signers(&self, store: &mut dyn Storage, block_time: u64, signers:&[CanonicalAddr], powers: &[Uint128]) -> Result<Response, SignersError> {
        let signer_state = &mut self.0.load(store)?;
        if signer_state.reset_time >= block_time {
            return Err(SignersError::Std(StdError::generic_err("not reach reset time")));
        }
        signer_state.reset_time = u64::MAX;
        self.0.save(store, signer_state)?;

        self._update_signers(store, signers, powers)
    }

    fn _update_signers(&self, store: &mut dyn Storage, signers:&[CanonicalAddr], powers: &[Uint128]) -> Result<Response, SignersError> {
        if signers.len() != powers.len() {
            return Err(SignersError::Std(StdError::generic_err("signers and powers length not match")));
        }
        self.1.save(store, &SignerPowers {
            signers: signers.to_vec(), 
            powers: powers.to_vec()}
        )?;

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
    /// contract_addr will be 12..32 of the hash of the addr
    pub fn update_signers(&self, deps: DepsMut, trigger_time: u64, contract_addr: Addr, new_signers:&[CanonicalAddr], new_powers: &[Uint128], sigs: &[&[u8]]) -> Result<Response, SignersError> {
        let signer_state = &mut self.0.load(deps.storage)?;
        if signer_state.trigger_time >= trigger_time {
            return Err(SignersError::Std(StdError::generic_err("Trigger time is not increasing")));
        }

        let domain = func::get_domain(contract_addr, "UpdateSigners");
        let msg = abi::encode_packed(
                &[
                    abi::SolType::Bytes(&domain), 
                    abi::SolType::Uint256(&cosmwasm_std::Uint256::from(trigger_time).to_be_bytes()), 
                    abi::SolType::AddrList(&new_signers.iter().map(
                        |i| -> [u8;20] {
                            let a: Result<[u8;20], _> = i.as_slice().try_into();
                            a.unwrap()
                        }).collect()),
                    abi::SolType::Uint256List(&new_powers.iter().map(
                        |i| -> [u8;32] {
                            cosmwasm_std::Uint256::from(i.u128()).to_be_bytes()
                        }).collect()), 
                ]);

        self.verify_sigs(deps.as_ref(), msg.as_slice(), sigs)?;

        self._update_signers(deps.storage, new_signers, new_powers)?;

        signer_state.trigger_time = trigger_time;
        self.0.save(deps.storage, signer_state)?;
        Ok(Response::new())
    }

    /// verify msg is signed with enough power, msg will be keccak256(_msg).toEthSignedMessageHash() internally
    pub fn verify_sigs(&self, deps: Deps, msg: &[u8], sigs: &[&[u8]]) -> Result<Response, SignersError> {
        let hash = func::keccak256(msg);
        let hash: &mut [u8] = &mut hash.clone();

        let eth_msg = func::to_eth_signed_message_hash(hash)?;

        let signers = &self.1.load(deps.storage)?;
        let mut total_power = Uint128::from(0u128);
        let mut signer_powers: HashMap<CanonicalAddr, Uint128> = HashMap::new();
        for i in 0..signers.signers.len() {
            total_power = total_power.add(signers.powers[i]);
            signer_powers.insert(signers.signers[i].clone(), signers.powers[i]);
        }

        let quorum = total_power.mul(Uint128::from(2u128)).div(Uint128::from(3u128)).add(Uint128::from(1u128));

        let mut signed_power = Uint128::from(0u128);
        for sig in sigs {
            let signer = func::recover_signer(&eth_msg, sig)?;
            if let Some(power) = signer_powers.get(&signer) {
                signed_power = signed_power.add(power);
                if signed_power >= quorum {
                    return Ok(Response::new());
                }
            } else {
                return Err(SignersError::Std(StdError::generic_err("signer not found")));
            }
        }
        Err(SignersError::NotEnoughPower {})
    }

    /// return signerstate. if not set, error
    pub fn get_state(&self, deps: Deps) -> StdResult<SignersState> {
        self.0.load(deps.storage)
    }
}