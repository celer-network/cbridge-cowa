use std::ops::{Deref, Div, Mul};
use thiserror::Error;

use cosmwasm_std::{Addr, Deps, DepsMut, MessageInfo, Response, StdError, StdResult, Storage, Uint256};
use cw_storage_plus::{Item, Map};
use crate::governor::{Governor, GovernorError};

/// Errors returned from VolumeControl
#[derive(Error, Debug, PartialEq)]
pub enum VolumeControlError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    GovernorError(#[from] GovernorError),

    #[error("Volume exceeds cap")]
    ExceedCap {},

    #[error("Invalid inputs")]
    InvalidInputs {},
}

pub struct VolumeControl<'a>{
    governor: &'a Governor<'a>,
    epoch_length: Item<'a, u64>,
    epoch_volumes: Map<'a, &'a Addr, Uint256>,
    epoch_volume_caps: Map<'a, &'a Addr, Uint256>,
    last_op_timestamps: Map<'a, &'a Addr, u64>,
}

const DEFAULT_EPOCH_LENGTH_NAMESPACE: &str = "epoch_length";
const DEFAULT_EPOCH_VOLUMES_NAMESPACE: &str = "epoch_volumes";
const DEFAULT_EPOCH_VOLUME_CAPS_NAMESPACE: &str = "epoch_volume_caps";
const DEFAULT_LAST_OP_TIMESTAMPS_NAMESPACE: &str = "last_op_timestamps";

impl<'a> VolumeControl<'a> {
    pub const fn new(governor: &'a Governor) -> Self {
        VolumeControl {
            governor,
            epoch_length: Item::new(DEFAULT_EPOCH_LENGTH_NAMESPACE),
            epoch_volumes: Map::new(DEFAULT_EPOCH_VOLUMES_NAMESPACE),
            epoch_volume_caps: Map::new(DEFAULT_EPOCH_VOLUME_CAPS_NAMESPACE),
            last_op_timestamps: Map::new(DEFAULT_LAST_OP_TIMESTAMPS_NAMESPACE),
        }
    }

    //internal functions

    //utils
    /// get epoch length
    pub fn get_epoch_length(&self, store: &dyn Storage) -> StdResult<u64> {
        self.epoch_length.load(store)
    }

    /// get epoch volumes
    pub fn get_epoch_volume(&self, store: &dyn Storage, token: &Addr) -> StdResult<Uint256> {
        if let Ok(volume) = self.epoch_volumes.load(store, token) {
            Ok(volume)
        } else {
            Ok(Uint256::zero())
        }
    }

    /// get epoch volume cap
    pub fn get_epoch_volume_cap(&self, store: &dyn Storage, token: &Addr) -> StdResult<Uint256> {
        self.epoch_volume_caps.load(store, token)
    }

    /// get last op timestamp
    pub fn get_last_op_timestamp(&self, store: &dyn Storage, token: &Addr) -> StdResult<u64> {
        if let Ok(timestamp) = self.last_op_timestamps.load(store, token) {
            Ok(timestamp)
        } else {
            Ok(0)
        }
    }

    /// update volume
    pub fn update_volume(&self, store: &mut dyn Storage, block_time: u64, token: &Addr, amount: &Uint256) -> Result<Response, VolumeControlError> {
        let epoch_length = self.get_epoch_length(store)?;
        let volume_cap = self.get_epoch_volume_cap(store, token)?;
        let mut volume = self.get_epoch_volume(store, token)?;
        let epoch_start_time = block_time.clone().div(epoch_length).mul(epoch_length);
        let last_op_timestamp = self.get_last_op_timestamp(store, token)?;
        if last_op_timestamp < epoch_start_time {
            volume = amount.clone();
        } else {
            volume += amount.clone();
        }
        if volume > volume_cap {
            return Err(VolumeControlError::ExceedCap {});
        }
        self.epoch_volumes.save(store, token, &volume)?;
        self.last_op_timestamps.save(store, token, &block_time)?;
        Ok(Response::new().add_attribute("action", "update_volume"))
    }

    //external functions
    //query
    /// return the epoch length
    pub fn query_epoch_length(&self, deps: Deps) -> StdResult<u64> {
        self.get_epoch_length(deps.storage)
    }

    /// return the epoch volume
    pub fn query_epoch_volume(&self, deps: Deps, token: String) -> StdResult<Uint256> {
        let token = deps.api.addr_validate(&token)?;
        self.get_epoch_volume(deps.storage, &token)
    }

    /// return the epoch volume cap
    pub fn query_epoch_volume_cap(&self, deps: Deps, token: String) -> StdResult<Uint256> {
        let token = deps.api.addr_validate(&token)?;
        self.get_epoch_volume_cap(deps.storage, &token)
    }

    /// return the last op timestamp
    pub fn query_last_op_timestamp(&self, deps: Deps, token: String) -> StdResult<u64> {
        let token = deps.api.addr_validate(&token)?;
        self.get_last_op_timestamp(deps.storage, &token)
    }

    //execute
    /// set epoch volume caps
    pub fn execute_set_epoch_volume_caps(&self, deps: DepsMut, info: MessageInfo, tokens: Vec<String>, caps: Vec<Uint256>) -> Result<Response, VolumeControlError> {
        self.governor.only_governor(deps.storage.deref(), &info.sender)?;
        if tokens.len() != caps.len() {
            return Err(VolumeControlError::InvalidInputs {})
        }
        let mut resp = Response::new().add_attribute("action", "set_epoch_volume_caps");
        for i in 0..tokens.len() {
            let token_addr = deps.api.addr_validate(&tokens[i])?;
            if caps[i].clone() == Uint256::zero() {
                return Err(VolumeControlError::InvalidInputs {})
            }
            self.epoch_volume_caps.save(deps.storage, &token_addr, &caps[i])?;
            resp = resp.add_attribute(token_addr, caps[i]);
        }
        Ok(resp)
    }

    /// set epoch length
    pub fn execute_set_epoch_length(&self, deps: DepsMut, info: MessageInfo, length: u64) -> Result<Response, VolumeControlError> {
        self.governor.only_governor(deps.storage.deref(), &info.sender)?;
        if length == 0 {
            return Err(VolumeControlError::InvalidInputs {})
        }
        self.epoch_length.save(deps.storage, &length)?;
        Ok(Response::new().add_attribute("action", "set_epoch_length")
            .add_attribute("epoch_length", length.to_string()))
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
        VolumeControl::new(&governor);
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
        let obj = VolumeControl::new(&governor);

        let info = mock_info(anyone_addr.as_ref(), &[]);
        let err = obj.execute_set_epoch_length(deps.as_mut(), info, 100).unwrap_err();
        assert_eq!(err, VolumeControlError::GovernorError(GovernorError::NotGovernor {}));

        let info = mock_info(owner_addr.as_ref(), &[]);
        let resp = obj.execute_set_epoch_length(deps.as_mut(), info.clone(), 100).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("epoch_length", 100.to_string())), true);
        assert_eq!(resp.attributes.len(), 2);
        let length = obj.query_epoch_length(deps.as_ref()).unwrap();
        assert_eq!(length, 100);

        let resp = obj.execute_set_epoch_volume_caps(deps.as_mut(), info.clone(), vec![String::from("1234")], vec![Uint256::from(666 as u64)]).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("1234", "666")), true);
        assert_eq!(resp.attributes.len(), 2);
        let cap = obj.query_epoch_volume_cap(deps.as_ref(), String::from("1234")).unwrap();
        assert_eq!(cap, Uint256::from(666 as u64));
    }

    #[test]
    fn update_volume() {
        let mut deps = mock_dependencies(&[]);
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        //let anyone_addr = Addr::unchecked("0x7F4A47e039328F95deC1919aA557E998774eD8dA");
        let owner = Owner::new("owner");
        owner.init_set(deps.as_mut().storage, &owner_addr).unwrap();
        let governor = Governor::new("governor", &owner);
        governor.instantiate(deps.as_mut().storage, &owner_addr).unwrap();
        let obj = VolumeControl::new(&governor);

        let info = mock_info(owner_addr.as_ref(), &[]);
        obj.execute_set_epoch_length(deps.as_mut(), info.clone(), 100).unwrap();
        obj.execute_set_epoch_volume_caps(deps.as_mut(), info.clone(), vec![String::from("1234")], vec![Uint256::from(666 as u64)]).unwrap();

        let token = deps.api.addr_validate("1234").unwrap();
        let volume = obj.get_epoch_volume(deps.as_ref().storage, &token).unwrap();
        assert_eq!(volume, Uint256::zero());
        let resp = obj.update_volume(
            deps.as_mut().storage,
            110,
            &token,
            &Uint256::from(222 as u64),
        ).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("action", "update_volume")), true);
        assert_eq!(resp.attributes.len(), 1);
        let volume = obj.get_epoch_volume(deps.as_ref().storage, &token).unwrap();
        assert_eq!(volume, Uint256::from(222 as u64));
        obj.update_volume(
            deps.as_mut().storage,
            120,
            &token,
            &Uint256::from(333 as u64),
        ).unwrap();
        let volume = obj.get_epoch_volume(deps.as_ref().storage, &token).unwrap();
        assert_eq!(volume, Uint256::from(555 as u64));
        let err = obj.update_volume(
            deps.as_mut().storage,
            130,
            &token,
            &Uint256::from(333 as u64),
        ).unwrap_err();
        assert_eq!(err, VolumeControlError::ExceedCap {});
        obj.update_volume(
            deps.as_mut().storage,
            210,
            &token,
            &Uint256::from(444 as u64),
        ).unwrap();
        let volume = obj.get_epoch_volume(deps.as_ref().storage, &token).unwrap();
        assert_eq!(volume, Uint256::from(444 as u64));
    }
}