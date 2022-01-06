use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use cosmwasm_std::{attr, Addr, Deps, DepsMut, MessageInfo, Response, StdError, StdResult};
use cw_storage_plus::Item;

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct OwnerResponse {
    pub owner: Option<String>,
}

/// Errors returned from Owner
#[derive(Error, Debug, PartialEq)]
pub enum OwnerError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Caller is not owner")]
    NotOwner {},
}

// state/logic
pub struct Owner<'a>(Item<'a, Option<Addr>>);

// this is the core business logic we expose
impl<'a> Owner<'a> {
    pub const fn new(namespace: &'a str) -> Self {
        Owner(Item::new(namespace))
    }

    pub fn set(&self, deps: DepsMut, owner: Option<Addr>) -> StdResult<()> {
        self.0.save(deps.storage, &owner)
    }

    pub fn get(&self, deps: Deps) -> StdResult<Option<Addr>> {
        self.0.load(deps.storage)
    }

    /// Returns Ok(true) if this is an owner, Ok(false) if not and an Error if
    /// we hit an error with Api or Storage usage
    pub fn is_owner(&self, deps: Deps, caller: &Addr) -> StdResult<bool> {
        match self.0.load(deps.storage)? {
            Some(owner) => Ok(caller == &owner),
            None => Ok(false),
        }
    }

    /// Like is_owner but returns OwnerError::NotOwner if not owner.
    /// Helper for a nice one-line auth check.
    pub fn assert_owner(&self, deps: Deps, caller: &Addr) -> Result<(), OwnerError> {
        if !self.is_owner(deps, caller)? {
            Err(OwnerError::NotOwner {})
        } else {
            Ok(())
        }
    }

    pub fn execute_update_owner(
        &self,
        deps: DepsMut,
        info: MessageInfo,
        new_owner: Option<Addr>,
    ) -> Result<Response, OwnerError> {
        self.assert_owner(deps.as_ref(), &info.sender)?;

        let owner_str = match new_owner.as_ref() {
            Some(owner) => owner.to_string(),
            None => "None".to_string(),
        };
        let attributes = vec![
            attr("action", "update_owner"),
            attr("owner", owner_str),
            attr("sender", info.sender),
        ];

        self.set(deps, new_owner)?;

        Ok(Response::new().add_attributes(attributes))
    }

    pub fn query_owner(&self, deps: Deps) -> StdResult<OwnerResponse> {
        let owner = self.get(deps)?.map(String::from);
        Ok(OwnerResponse { owner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_info};

    #[test]
    fn set_and_get_owner() {
        let mut deps = mock_dependencies(&[]);
        let control = Owner::new("foo");

        // initialize and check
        let owner = Some(Addr::unchecked("owner"));
        control.set(deps.as_mut(), owner.clone()).unwrap();
        let got = control.get(deps.as_ref()).unwrap();
        assert_eq!(owner, got);

        // clear it and check
        control.set(deps.as_mut(), None).unwrap();
        let got = control.get(deps.as_ref()).unwrap();
        assert_eq!(None, got);
    }

    #[test]
    fn owner_checks() {
        let mut deps = mock_dependencies(&[]);

        let control = Owner::new("foo");
        let owner = Addr::unchecked("big boss");
        let imposter = Addr::unchecked("imposter");

        // ensure checks proper with owner set
        control.set(deps.as_mut(), Some(owner.clone())).unwrap();
        assert!(control.is_owner(deps.as_ref(), &owner).unwrap());
        assert!(!(control.is_owner(deps.as_ref(), &imposter).unwrap()));
        control.assert_owner(deps.as_ref(), &owner).unwrap();
        let err = control.assert_owner(deps.as_ref(), &imposter).unwrap_err();
        assert_eq!(OwnerError::NotOwner {}, err);

        // ensure checks proper with owner None
        control.set(deps.as_mut(), None).unwrap();
        assert!(!(control.is_owner(deps.as_ref(), &owner).unwrap()));
        assert!(!(control.is_owner(deps.as_ref(), &imposter).unwrap()));
        let err = control.assert_owner(deps.as_ref(), &owner).unwrap_err();
        assert_eq!(OwnerError::NotOwner {}, err);
        let err = control.assert_owner(deps.as_ref(), &imposter).unwrap_err();
        assert_eq!(OwnerError::NotOwner {}, err);
    }

    #[test]
    fn test_execute_query() {
        let mut deps = mock_dependencies(&[]);

        // initial setup
        let control = Owner::new("foo");
        let owner = Addr::unchecked("big boss");
        let imposter = Addr::unchecked("imposter");
        let friend = Addr::unchecked("buddy");
        control.set(deps.as_mut(), Some(owner.clone())).unwrap();

        // query shows results
        let res = control.query_owner(deps.as_ref()).unwrap();
        assert_eq!(Some(owner.to_string()), res.owner);

        // imposter cannot update
        let info = mock_info(imposter.as_ref(), &[]);
        let new_owner = Some(friend.clone());
        let err = control
            .execute_update_owner(deps.as_mut(), info, new_owner.clone())
            .unwrap_err();
        assert_eq!(OwnerError::NotOwner {}, err);

        // owner can update
        let info = mock_info(owner.as_ref(), &[]);
        let res = control
            .execute_update_owner(deps.as_mut(), info, new_owner)
            .unwrap();
        assert_eq!(0, res.messages.len());

        // query shows results
        let res = control.query_owner(deps.as_ref()).unwrap();
        assert_eq!(Some(friend.to_string()), res.owner);
    }
}