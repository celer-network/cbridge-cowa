use std::ops::Deref;
use sei_cosmwasm::SeiMsg;
use thiserror::Error;

use cosmwasm_std::{Addr, Deps, DepsMut, MessageInfo, Response, StdError, StdResult, Storage};
use cw_storage_plus::Map;
use crate::owner::{Owner, OwnerError};

/// Errors returned from Governor
#[derive(Error, Debug, PartialEq)]
pub enum GovernorError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    OwnerError(#[from] OwnerError),

    #[error("Not governor")]
    NotGovernor {},

    #[error("Already governor")]
    AlreadyGovernor {},
}

pub struct Governor<'a>{
    owner: &'a Owner<'a>,
    governors: Map<'a, &'a Addr, bool>,
}

impl<'a> Governor<'a> {
    pub const fn new(governors_namespace: &'a str, owner: &'a Owner) -> Self {
        Governor {
            owner,
            governors: Map::new(governors_namespace),
        }
    }

    /// as constructor in solidity, can only be called once
    pub fn instantiate(&self, store: &mut dyn Storage, caller: &Addr) -> Result<Response<SeiMsg>, GovernorError> {
        // make sure Owner has already been set.
        self.owner.only_owner(store.deref(),caller)?;
        self.add_governor(store, caller)
    }

    //internal functions
    fn is_governor(&self, store: &dyn Storage, candidat: &Addr) -> bool {
        self.governors.has(store, candidat)
    }

    fn add_governor(&self, store: &mut dyn Storage, new_governor: &Addr) -> Result<Response<SeiMsg>, GovernorError> {
        if self.is_governor(store.deref(), new_governor) {
            return Err(GovernorError::AlreadyGovernor {});
        }
        self.governors.save(store, &new_governor, &true)?;
        Ok(Response::new().add_attribute("new_governor", new_governor))
    }

    fn remove_governor(&self, store: &mut dyn Storage, removed_governor: &Addr) -> Result<Response<SeiMsg>, GovernorError> {
        if !self.is_governor(store.deref(), removed_governor) {
            return Err(GovernorError::NotGovernor {});
        }
        self.governors.remove(store, removed_governor);
        Ok(Response::new().add_attribute("removed_governor", removed_governor))
    }

    // modifier
    /// modifier onlyGovernor
    pub fn only_governor(&self, store: &dyn Storage, candidat: &Addr) -> Result<(), GovernorError> {
        if self.is_governor(store, candidat) {
            Ok(())
        } else {
            Err(GovernorError::NotGovernor {})
        }
    }

    //query
    /// return if given address is a governor
    pub fn query_governor(&self, deps: Deps, address: String) -> StdResult<bool> {
        let governor = deps.api.addr_validate(&address)?;
        Ok(self.is_governor(deps.storage, &governor))
    }

    //execute
    /// add a governor, can only be called by owner
    pub fn execute_add_governor(&self, deps: DepsMut, info: MessageInfo, address: String) -> Result<Response<SeiMsg>, GovernorError> {
        let governor = deps.api.addr_validate(&address)?;
        self.owner.only_owner(deps.storage.deref(), &info.sender)?;
        self.add_governor(deps.storage, &governor)
    }

    /// remove a governor, can only be called by owner
    pub fn execute_remove_governor(&self, deps: DepsMut, info: MessageInfo, address: String) -> Result<Response<SeiMsg>, GovernorError> {
        let governor = deps.api.addr_validate(&address)?;
        self.owner.only_owner(deps.storage.deref(), &info.sender)?;
        self.remove_governor(deps.storage, &governor)
    }

    /// renounce governor, can be called by any governor
    pub fn execute_renounce_governor(&self, deps: DepsMut, info: MessageInfo) -> Result<Response<SeiMsg>, GovernorError> {
        self.remove_governor(deps.storage, &info.sender)
    }

}

#[cfg(test)]
mod tests {
    use cosmwasm_std::Attribute;
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    #[test]
    fn instantiate() {
        let mut deps = mock_dependencies();
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let anyone_addr = Addr::unchecked("0x7F4A47e039328F95deC1919aA557E998774eD8dA");
        let owner = Owner::new("owner");
        owner.init_set(deps.as_mut().storage, &owner_addr).unwrap();
        let obj = Governor::new("governors", &owner);
        obj.instantiate(deps.as_mut().storage, &owner_addr).expect("failed to instantiate");

        let got = obj.owner.get(deps.as_ref()).unwrap();
        assert_eq!(got, "0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let is_governor = obj.query_governor(deps.as_ref(), owner_addr.as_ref().to_string()).unwrap();
        assert_eq!(is_governor, true);
        let is_governor = obj.query_governor(deps.as_ref(), anyone_addr.as_ref().to_string()).unwrap();
        assert_eq!(is_governor, false);
        obj.only_governor(deps.as_ref().storage, &owner_addr).unwrap();

        // try to call init_set again will cause err
        let err = obj.instantiate(deps.as_mut().storage, &owner_addr).unwrap_err();
        assert_eq!(err, GovernorError::AlreadyGovernor {});
    }

    #[test]
    fn governors() {
        let mut deps = mock_dependencies();
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let anyone_addr = Addr::unchecked("0x7F4A47e039328F95deC1919aA557E998774eD8dA");
        let owner = Owner::new("owner");
        owner.init_set(deps.as_mut().storage, &owner_addr).unwrap();
        let obj = Governor::new("governors", &owner);
        obj.instantiate(deps.as_mut().storage, &owner_addr).expect("failed to instantiate");

        let info = mock_info(anyone_addr.as_ref(), &[]);
        let err = obj.execute_add_governor(deps.as_mut(), info, anyone_addr.as_ref().to_string()).unwrap_err();
        assert_eq!(err, GovernorError::OwnerError(OwnerError::NotOwner {}));

        let info = mock_info(owner_addr.as_ref(), &[]);
        let resp = obj.execute_add_governor(deps.as_mut(), info, anyone_addr.as_ref().to_string()).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("new_governor", &anyone_addr)), true);
        assert_eq!(resp.attributes.len(), 1);
        obj.only_governor(deps.as_ref().storage, &anyone_addr).unwrap();

        let info = mock_info(owner_addr.as_ref(), &[]);
        let err = obj.execute_add_governor(deps.as_mut(), info, anyone_addr.as_ref().to_string()).unwrap_err();
        assert_eq!(err, GovernorError::AlreadyGovernor {});

        let info = mock_info(anyone_addr.as_ref(), &[]);
        let resp = obj.execute_renounce_governor(deps.as_mut(), info).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("removed_governor", &anyone_addr)), true);
        assert_eq!(resp.attributes.len(), 1);
        let err = obj.only_governor(deps.as_ref().storage, &anyone_addr).unwrap_err();
        assert_eq!(err, GovernorError::NotGovernor {});

        let info = mock_info(owner_addr.as_ref(), &[]);
        let err = obj.execute_remove_governor(deps.as_mut(), info, anyone_addr.as_ref().to_string()).unwrap_err();
        assert_eq!(err, GovernorError::NotGovernor {})
    }
}