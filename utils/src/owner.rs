use thiserror::Error;

use cosmwasm_std::{Addr, Deps, DepsMut, MessageInfo, Response, StdError, StdResult, Storage};
use cw_storage_plus::Item;

/// Errors returned from Owner
#[derive(Error, Debug, PartialEq)]
pub enum OwnerError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Caller is not owner")]
    NotOwner {},
}

// state/logic
pub struct Owner<'a>(Item<'a, String>);

// this is the core business logic we expose
impl<'a> Owner<'a> {
    pub const fn new(namespace: &'a str) -> Self {
        Owner(Item::new(namespace))
    }

    /// only allow set once. if already has owner, fail. owner should be info.sender
    pub fn init_set(&self, store: &mut dyn Storage, owner: &Addr) -> StdResult<()> {
        // storage has way to check if a key exists but it's hidden by Item.
        match self.0.may_load(store)? {
            // not found, ok to set
            None => self.0.save(store, &owner.clone().into_string()),
            // found string, return error
            Some(_) => Err(StdError::generic_err("init_set called after owner already set")),
        }
    }

    /// return owner string. if not set, error
    pub fn get(&self, deps: Deps) -> StdResult<String> {
        self.0.load(deps.storage)
    }

    /// returns OwnerError::NotOwner if info.sender is not owner. we take info to avoid anyone
    /// pass in wrong Addr eg. from user msg
    pub fn assert_owner(&self, deps: Deps, info: &MessageInfo) -> Result<(), OwnerError> {
        if !self.is_owner(deps, &info.sender)? {
            Err(OwnerError::NotOwner {})
        } else {
            Ok(())
        }
    }

    /// Returns Ok(true) if this is an owner, Ok(false) if not and an Error if
    /// we hit an error with Api or Storage usage. you should use assert_owner
    pub fn is_owner(&self, deps: Deps, caller: &Addr) -> StdResult<bool> {
        Ok(self.0.load(deps.storage)? == caller.clone().into_string())
    }

    /// set a new owner, must be called by current owner, we check new_owner is valid Addr
    /// to avoid any mistake eg. set to an ETH address
    pub fn update_owner(
        &self,
        deps: DepsMut,
        info: MessageInfo,
        new_owner: &str,
    ) -> Result<Response, OwnerError> {
        // make sure caller is current owner
        self.assert_owner(deps.as_ref(), &info)?;

        // check if new_owner is valid Addr
        let valid_addr = deps.api.addr_validate(new_owner)?;

        // write to storage
        self.0.save(deps.storage, &valid_addr.to_string())?;

        // return and emit event
        let res = Response::new()
            .add_attribute("action", "update_owner")
            .add_attribute("owner", new_owner)
            .add_attribute("sender", info.sender);
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    #[test]
    fn init_set() {
        let mut deps = mock_dependencies(&[]);
        let obj = Owner::new("owner");
        
        let owner_addr = Addr::unchecked("owner_addr");
        obj.init_set(deps.as_mut().storage, &owner_addr).unwrap();

        let got = obj.get(deps.as_ref()).unwrap();
        assert_eq!(got, "owner_addr");
        // try to call init_set again will cause err
        let err = obj.init_set(deps.as_mut().storage, &owner_addr).unwrap_err();
        assert_eq!(err, StdError::generic_err("init_set called after owner already set"));
    }

    #[test]
    fn assert_owner() {
        let mut deps = mock_dependencies(&[]);
        let obj = Owner::new("owner");
        
        let owner_addr = Addr::unchecked("owner_addr");
        obj.init_set(deps.as_mut().storage, &owner_addr).unwrap();

        let info = mock_info(owner_addr.as_ref(), &[]);
        // must Ok
        obj.assert_owner(deps.as_ref(), &info).unwrap();
        let info = mock_info("not_owner_addr", &[]);
        // must err
        let err = obj.assert_owner(deps.as_ref(), &info).unwrap_err();
        assert_eq!(err, OwnerError::NotOwner {}); 
    }

    #[test]
    fn update_owner() {
        let mut deps = mock_dependencies(&[]);
        let obj = Owner::new("owner");
        
        let owner_addr = Addr::unchecked("owner_addr");
        obj.init_set(deps.as_mut().storage, &owner_addr).unwrap();

        let info = mock_info(owner_addr.as_ref(), &[]);
        // must Ok
        obj.update_owner(deps.as_mut(), info, "new_owner_addr").unwrap();
        let got = obj.get(deps.as_ref()).unwrap();
        assert_eq!(got, "new_owner_addr");

        let info = mock_info("new_owner_addr", &[]);
        // must Ok for new owner
        obj.assert_owner(deps.as_ref(), &info).unwrap();

        let info = mock_info("owner_addr", &[]);
        // must err for previous
        let err = obj.assert_owner(deps.as_ref(), &info).unwrap_err();
        assert_eq!(err, OwnerError::NotOwner {}); 
    }
}