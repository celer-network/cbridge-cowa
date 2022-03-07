use std::ops::Deref;
use thiserror::Error;

use cosmwasm_std::{Addr, Deps, DepsMut, MessageInfo, Response, StdError, StdResult, Storage};
use cw_storage_plus::{Item, Map};
use crate::owner::{Owner, OwnerError};

/// Errors returned from Pauser
#[derive(Error, Debug, PartialEq)]
pub enum PauserError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    OwnerError(#[from] OwnerError),

    #[error("Not pauser")]
    NotPauser {},

    #[error("Already pauser")]
    AlreadyPauser {},

    #[error("Paused")]
    Paused {},

    #[error("Not paused")]
    NotPaused {},
}

pub struct Pauser<'a>{
    owner: &'a Owner<'a>,
    paused: Item<'a, bool>,
    pausers: Map<'a, &'a Addr, bool>,
}

impl<'a> Pauser<'a> {
    pub const fn new(paused_namespace: &'a str, pausers_namespace: &'a str, owner: &'a Owner) -> Self {
        Pauser{
            owner,
            paused: Item::new(paused_namespace),
            pausers: Map::new(pausers_namespace),
        }
    }

    /// as constructor in solidity, can only be called once
    pub fn instantiate(&self, store: &mut dyn Storage, caller: &Addr) -> Result<Response, PauserError> {
        // make sure Owner has already been set.
        self.owner.only_owner(store.deref(),caller)?;
        self.paused.save(store, &false)?;
        self.add_pauser(store, caller)
    }

    //internal functions
    fn is_paused(&self, store: &dyn Storage) -> StdResult<bool> {
        self.paused.load(store)
    }

    fn add_pauser(&self, store: &mut dyn Storage, new_pauser: &Addr) -> Result<Response, PauserError> {
        if self.is_pauser(store.deref(), new_pauser) {
            return Err(PauserError::AlreadyPauser {});
        }
        self.pausers.save(store, &new_pauser, &true)?;
        Ok(Response::new().add_attribute("new_pauser", new_pauser))
    }

    fn remove_pauser(&self, store: &mut dyn Storage, removed_pauser: &Addr) -> Result<Response, PauserError> {
        if !self.is_pauser(store.deref(), removed_pauser) {
            return Err(PauserError::NotPauser {});
        }
        self.pausers.remove(store, removed_pauser);
        Ok(Response::new().add_attribute("removed_pauser", removed_pauser))
    }

    // modifier
    /// modifier onlyPauser
    pub fn only_pauser(&self, store: &dyn Storage, candidat: &Addr) -> Result<(), PauserError> {
        if self.is_pauser(store, candidat) {
            Ok(())
        } else {
            Err(PauserError::NotPauser {})
        }
    }

    /// modifier whenNotPaused
    pub fn when_not_paused(&self, store: &dyn Storage) -> Result<(), PauserError> {
        if !self.paused.load(store)? {
            Ok(())
        } else {
            Err(PauserError::Paused {})
        }
    }

    /// modifier whenPaused
    pub fn when_paused(&self, store: &dyn Storage) -> Result<(), PauserError> {
        if self.paused.load(store)? {
            Ok(())
        } else {
            Err(PauserError::NotPaused {})
        }
    }

    //utils
    pub fn is_pauser(&self, store: &dyn Storage, candidat: &Addr) -> bool {
        self.pausers.has(store, candidat)
    }

    //query
    /// return if given address is a pauser
    pub fn query_pauser(&self, deps: Deps, address: String) -> StdResult<bool> {
        let pauser = deps.api.addr_validate(&address)?;
        Ok(self.is_pauser(deps.storage, &pauser))
    }

    /// return if this contract is paused
    pub fn query_paused(&self, deps: Deps) -> StdResult<bool> {
        self.is_paused(deps.storage)
    }

    //execute
    /// pause this contract
    pub fn execute_pause(&self, deps: DepsMut, info: MessageInfo) -> Result<Response, PauserError> {
        let store= deps.storage;
        self.when_not_paused(store.deref())?;
        self.only_pauser(store.deref(), &info.sender)?;
        self.paused.save(store, &true)?;
        Ok(Response::new().add_attribute("paused_by", info.sender))
    }

    /// unpause this contract
    pub fn execute_unpause(&self, deps: DepsMut, info: MessageInfo) -> Result<Response, PauserError> {
        let store = deps.storage;
        self.when_paused(store.deref())?;
        self.only_pauser(store.deref(), &info.sender)?;
        self.paused.save(store, &false)?;
        Ok(Response::new().add_attribute("unpaused_by", info.sender))
    }

    /// add a pauser, can only be called by owner
    pub fn execute_add_pauser(&self, deps: DepsMut, info: MessageInfo, address: String) -> Result<Response, PauserError> {
        let pauser = deps.api.addr_validate(&address)?;
        self.owner.only_owner(deps.storage.deref(), &info.sender)?;
        self.add_pauser(deps.storage, &pauser)
    }

    /// remove a pauser, can only be called by owner
    pub fn execute_remove_pauser(&self, deps: DepsMut, info: MessageInfo, address: String) -> Result<Response, PauserError> {
        let pauser = deps.api.addr_validate(&address)?;
        self.owner.only_owner(deps.storage.deref(), &info.sender)?;
        self.remove_pauser(deps.storage, &pauser)
    }

    /// renounce pauser, can be called by any pauser
    pub fn execute_renounce_pauser(&self, deps: DepsMut, info: MessageInfo) -> Result<Response, PauserError> {
        self.remove_pauser(deps.storage, &info.sender)
    }

}

#[cfg(test)]
mod tests {
    use cosmwasm_std::Attribute;
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    #[test]
    fn instantiate() {
        let mut deps = mock_dependencies(&[]);
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let anyone_addr = Addr::unchecked("0x7F4A47e039328F95deC1919aA557E998774eD8dA");
        let owner = Owner::new("owner");
        owner.init_set(deps.as_mut().storage, &owner_addr).unwrap();
        let obj = Pauser::new("paused", "pausers", &owner);
        obj.instantiate(deps.as_mut().storage, &owner_addr).expect("failed to instantiate");

        let got = obj.owner.get(deps.as_ref()).unwrap();
        assert_eq!(got, "0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let paused = obj.query_paused(deps.as_ref()).unwrap();
        assert_eq!(paused, false);
        let is_pauser = obj.query_pauser(deps.as_ref(), owner_addr.as_ref().to_string()).unwrap();
        assert_eq!(is_pauser, true);
        let is_pauser = obj.query_pauser(deps.as_ref(), anyone_addr.as_ref().to_string()).unwrap();
        assert_eq!(is_pauser, false);
        obj.only_pauser(deps.as_ref().storage, &owner_addr).unwrap();
        obj.when_not_paused(deps.as_ref().storage).unwrap();
        let err = obj.when_paused(deps.as_ref().storage).unwrap_err();
        assert_eq!(err, PauserError::NotPaused {});
        // try to call init_set again will cause err
        let err = obj.instantiate(deps.as_mut().storage, &owner_addr).unwrap_err();
        assert_eq!(err, PauserError::AlreadyPauser {});
    }

    #[test]
    fn pause_unpause() {
        let mut deps = mock_dependencies(&[]);
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let anyone_addr = Addr::unchecked("0x7F4A47e039328F95deC1919aA557E998774eD8dA");
        let owner = Owner::new("owner");
        owner.init_set(deps.as_mut().storage, &owner_addr).unwrap();
        let obj = Pauser::new("paused", "pausers", &owner);
        obj.instantiate(deps.as_mut().storage, &owner_addr).expect("failed to instantiate");

        let info = mock_info(anyone_addr.as_ref(), &[]);
        let err = obj.execute_pause(deps.as_mut(), info).unwrap_err();
        assert_eq!(err, PauserError::NotPauser {});

        let info = mock_info(owner_addr.as_ref(), &[]);
        let resp = obj.execute_pause(deps.as_mut(), info).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("paused_by", &owner_addr)), true);
        assert_eq!(resp.attributes.len(), 1);
        obj.when_paused(deps.as_ref().storage).unwrap();
        let err = obj.when_not_paused(deps.as_ref().storage).unwrap_err();
        assert_eq!(err, PauserError::Paused {});

        let info = mock_info(owner_addr.as_ref(), &[]);
        let resp = obj.execute_unpause(deps.as_mut(), info).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("unpaused_by", &owner_addr)), true);
        assert_eq!(resp.attributes.len(), 1);
        obj.when_not_paused(deps.as_ref().storage).unwrap();
    }

    #[test]
    fn pausers() {
        let mut deps = mock_dependencies(&[]);
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let anyone_addr = Addr::unchecked("0x7F4A47e039328F95deC1919aA557E998774eD8dA");
        let owner = Owner::new("owner");
        owner.init_set(deps.as_mut().storage, &owner_addr).unwrap();
        let obj = Pauser::new("paused", "pausers", &owner);
        obj.instantiate(deps.as_mut().storage, &owner_addr).expect("failed to instantiate");

        let info = mock_info(anyone_addr.as_ref(), &[]);
        let err = obj.execute_add_pauser(deps.as_mut(), info, anyone_addr.as_ref().to_string()).unwrap_err();
        assert_eq!(err, PauserError::OwnerError(OwnerError::NotOwner {}));

        let info = mock_info(owner_addr.as_ref(), &[]);
        let resp = obj.execute_add_pauser(deps.as_mut(), info, anyone_addr.as_ref().to_string()).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("new_pauser", &anyone_addr)), true);
        assert_eq!(resp.attributes.len(), 1);
        obj.only_pauser(deps.as_ref().storage, &anyone_addr).unwrap();

        let info = mock_info(owner_addr.as_ref(), &[]);
        let err = obj.execute_add_pauser(deps.as_mut(), info, anyone_addr.as_ref().to_string()).unwrap_err();
        assert_eq!(err, PauserError::AlreadyPauser {});

        let info = mock_info(anyone_addr.as_ref(), &[]);
        let resp = obj.execute_renounce_pauser(deps.as_mut(), info).unwrap();
        assert_eq!(resp.attributes.contains(&Attribute::new("removed_pauser", &anyone_addr)), true);
        assert_eq!(resp.attributes.len(), 1);
        let err = obj.only_pauser(deps.as_ref().storage, &anyone_addr).unwrap_err();
        assert_eq!(err, PauserError::NotPauser {});

        let info = mock_info(owner_addr.as_ref(), &[]);
        let err = obj.execute_remove_pauser(deps.as_mut(), info, anyone_addr.as_ref().to_string()).unwrap_err();
        assert_eq!(err, PauserError::NotPauser {})
    }
}