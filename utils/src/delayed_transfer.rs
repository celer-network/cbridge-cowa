use std::ops::Deref;
use thiserror::Error;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Addr, Deps, DepsMut, MessageInfo, Response, StdError, StdResult, Storage, Uint256};
use cw_storage_plus::{Item, Map};
use crate::governor::{Governor, GovernorError};

/// Errors returned from DelayedTransfer
#[derive(Error, Debug, PartialEq)]
pub enum DelayedTransferError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    GovernorError(#[from] GovernorError),

    #[error("Delayed transfer already exists")]
    Existed {},

    #[error("Delayed transfer not exists")]
    NotExist {},

    #[error("Invalid inputs")]
    InvalidInputs {},

    #[error("Delayed transfer still locked")]
    TimeNotYet {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct DelayedXfer {
    pub receiver: Addr,
    pub token: Addr,
    pub amount: Uint256,
    timestamp: u64,
}

pub struct DelayedTransfer<'a>{
    governor: &'a Governor<'a>,
    delay_period: Item<'a, u64>,
    delay_thresholds: Map<'a, &'a Addr, Uint256>,
    delayed_transfers: Map<'a, Vec<u8>, DelayedXfer>,
}

const DEFAULT_DELAY_PERIOD_NAMESPACE: &str = "delay_period";
const DEFAULT_DELAY_THRESHOLDS_NAMESPACE: &str = "delay_threshold";
const DEFAULT_DELAYED_TRANSFERS_NAMESPACE: &str = "delay_transfers";

impl<'a> DelayedTransfer<'a> {
    pub const fn new(governor: &'a Governor) -> Self {
        DelayedTransfer{
            governor,
            delay_period: Item::new(DEFAULT_DELAY_PERIOD_NAMESPACE),
            delay_thresholds: Map::new(DEFAULT_DELAY_THRESHOLDS_NAMESPACE),
            delayed_transfers: Map::new(DEFAULT_DELAYED_TRANSFERS_NAMESPACE),
        }
    }

    //internal functions

    //utils
    /// get delay period
    pub fn get_delay_period(&self, store: &dyn Storage) -> StdResult<u64> {
        self.delay_period.load(store)
    }

    /// get delay threshold
    pub fn get_delay_threshold(&self, store: &dyn Storage, token: &Addr) -> StdResult<Uint256> {
        self.delay_thresholds.load(store, token)
    }

    /// get delay transfer
    pub fn get_delayed_transfer(&self, store: &dyn Storage, id: &Vec<u8>) -> StdResult<DelayedXfer> {
        self.delayed_transfers.load(store, id.to_vec())
    }

    /// add delayed transrer
    pub fn add_delayed_transfer(&self, store: &mut dyn Storage, block_time: u64, id: &Vec<u8>, receiver: &Addr, token: &Addr, amount: &Uint256) -> Result<(), DelayedTransferError> {
        if self.delayed_transfers.has(store, id.to_vec()) {
            return Err(DelayedTransferError::Existed {});
        }
        let dt = DelayedXfer{
            receiver: receiver.clone(),
            token: token.clone(),
            amount: amount.clone(),
            timestamp: block_time
        };
        self.delayed_transfers.save(store, id.to_vec(), &dt)?;
        Ok(())
    }

    /// execute delayed transfer by its id, and return the delayed transfer as well
    pub fn execute_delayed_transfer(&self, store: &mut dyn Storage, block_time: u64, id: &Vec<u8>) -> Result<DelayedXfer, DelayedTransferError> {
        if !self.delayed_transfers.has(store, id.to_vec()) {
            return Err(DelayedTransferError::NotExist {});
        }
        let dt = self.delayed_transfers.load(store, id.to_vec())?;
        if block_time <= dt.timestamp + self.delay_period.load(store)? {
            return Err(DelayedTransferError::TimeNotYet {});
        }
        self.delayed_transfers.remove(store, id.to_vec());
        Ok(dt)
    }

    // emit an event of adding a delayed transfer
    pub fn emit_delayed_transfer_added(&self, store: &dyn Storage, id: &Vec<u8>) -> Result<Response, DelayedTransferError> {
        if !self.delayed_transfers.has(store, id.to_vec()) {
            Err(DelayedTransferError::NotExist {})
        } else {
            Ok(Response::new().add_attribute("delayed_transfer_action", "add_delayed_transfer")
                .add_attribute("delayed_transfer_id", hex::encode(id)))
        }
    }

    // emit an event of executing a delayed transfer
    pub fn emit_delayed_transfer_executed(&self, store: &dyn Storage, id: &Vec<u8>) -> Result<Response, DelayedTransferError> {
        if self.delayed_transfers.has(store, id.to_vec()) {
            Err(DelayedTransferError::Existed {})
        } else {
            Ok(Response::new().add_attribute("delayed_transfer_action", "execute_delayed_transfer")
                .add_attribute("delayed_transfer_id", hex::encode(id)))
        }
    }

    //external functions
    //query
    /// return the delay period
    pub fn query_delay_period(&self, deps: Deps) -> StdResult<u64> {
        self.get_delay_period(deps.storage)
    }

    /// return the delay threshold
    pub fn query_delay_threshold(&self, deps: Deps, token: String) -> StdResult<Uint256> {
        let token = deps.api.addr_validate(&token)?;
        self.get_delay_threshold(deps.storage, &token)
    }

    /// return the delayed transfer
    pub fn query_delayed_transfer(&self, deps: Deps, id: Vec<u8>) -> StdResult<DelayedXfer> {
        self.get_delayed_transfer(deps.storage, &id)
    }

    //execute
    /// set delay thresholds
    pub fn execute_set_delay_thresholds(&self, deps: DepsMut, info: MessageInfo, tokens: Vec<String>, thresholds: Vec<Uint256>) -> Result<Response, DelayedTransferError> {
        self.governor.only_governor(deps.storage.deref(), &info.sender)?;
        if tokens.len() != thresholds.len() {
            return Err(DelayedTransferError::InvalidInputs {})
        }
        let mut resp = Response::new().add_attribute("action", "set_delay_thresholds");
        for i in 0..tokens.len() {
            let token_addr = deps.api.addr_validate(&tokens[i])?;
            if thresholds[i].clone() == Uint256::zero() {
                return Err(DelayedTransferError::InvalidInputs {})
            }
            self.delay_thresholds.save(deps.storage, &token_addr, &thresholds[i])?;
            resp = resp.add_attribute(token_addr,thresholds[i]);
        }
        Ok(resp)
    }

    /// set delay period
    pub fn execute_set_delay_period(&self, deps: DepsMut, info: MessageInfo, period: u64) -> Result<Response, DelayedTransferError> {
        self.governor.only_governor(deps.storage.deref(), &info.sender)?;
        if period == 0 {
            return Err(DelayedTransferError::InvalidInputs {})
        }
        self.delay_period.save(deps.storage, &period)?;
        Ok(Response::new().add_attribute("action", "set_delay_period")
            .add_attribute("delay_period", period.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use cosmwasm_std::{Api, Attribute};
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_info};
    use crate::owner::Owner;
    use crate::governor::GovernorError;

    #[test]
    fn instantiate() {
        let mut deps = mock_dependencies(&[]);
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let owner = Owner::new("owner");
        let governor = Governor::new("governor", &owner);
        owner.init_set(deps.as_mut().storage, &owner_addr).unwrap();
        governor.instantiate(deps.as_mut().storage, &owner_addr).unwrap();
        DelayedTransfer::new(&governor);
    }

    #[test]
    fn set_query() {
        let mut deps = mock_dependencies(&[]);
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let anyone_addr = Addr::unchecked("0x7F4A47e039328F95deC1919aA557E998774eD8dA");
        let owner = Owner::new("owner");
        owner.init_set(deps.as_mut().storage, &owner_addr).unwrap();
        let governor = Governor::new("governor", &owner);
        governor.instantiate(deps.as_mut().storage, &owner_addr).unwrap();
        let obj = DelayedTransfer::new(&governor);

        let info = mock_info(anyone_addr.as_ref(), &[]);
        let err = obj.execute_set_delay_period(deps.as_mut(), info, 100).unwrap_err();
        assert_eq!(err, DelayedTransferError::GovernorError(GovernorError::NotGovernor {}));

        let info = mock_info(owner_addr.as_ref(), &[]);
        let resp = obj.execute_set_delay_period(deps.as_mut(), info.clone(), 1000).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("delay_period", 1000.to_string())), true);
        assert_eq!(resp.attributes.len(), 2);
        let period = obj.query_delay_period(deps.as_ref()).unwrap();
        assert_eq!(period, 1000 as u64);

        let resp = obj.execute_set_delay_thresholds(deps.as_mut(), info.clone(), vec![String::from("1234")], vec![Uint256::from(666 as u64)]).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("1234", "666")), true);
        assert_eq!(resp.attributes.len(), 2);
        let threshold = obj.query_delay_threshold(deps.as_ref(), String::from("1234")).unwrap();
        assert_eq!(threshold, Uint256::from(666 as u64));
    }

    #[test]
    fn add_execute() {
        let mut deps = mock_dependencies(&[]);
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        //let anyone_addr = Addr::unchecked("0x7F4A47e039328F95deC1919aA557E998774eD8dA");
        let owner = Owner::new("owner");
        owner.init_set(deps.as_mut().storage, &owner_addr).unwrap();
        let governor = Governor::new("governor", &owner);
        governor.instantiate(deps.as_mut().storage, &owner_addr).unwrap();
        let obj = DelayedTransfer::new(&governor);

        let info = mock_info(owner_addr.as_ref(), &[]);
        obj.execute_set_delay_period(deps.as_mut(), info.clone(), 1000).unwrap();

        let token = deps.api.addr_validate("1234").unwrap();
        obj.add_delayed_transfer(
            deps.as_mut().storage,
            1000,
            vec![10 as u8, 11 as u8, 12 as u8].as_ref(),
            &owner_addr,
            &token,
            &Uint256::from(666 as u64),
        ).unwrap();
        let resp = obj.emit_delayed_transfer_added(deps.as_ref().storage, vec![10 as u8, 11 as u8, 12 as u8].as_ref()).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("delayed_transfer_id", hex::encode(vec![10 as u8, 11 as u8, 12 as u8]))), true);
        assert_eq!(resp.attributes.len(), 2);

        let dt = obj.execute_delayed_transfer(deps.as_mut().storage, 3000, vec![10 as u8, 11 as u8, 12 as u8].as_ref()).unwrap();
        let resp = obj.emit_delayed_transfer_executed(deps.as_ref().storage, vec![10 as u8, 11 as u8, 12 as u8].as_ref()).unwrap();
        assert_eq!(resp.attributes.len(), 2);
        let expected_dt = DelayedXfer{
            receiver: owner_addr.clone(),
            token: token.clone(),
            amount: Uint256::from(666 as u64),
            timestamp: 1000 as u64,
        };
        assert_eq!(dt, expected_dt);
    }
}