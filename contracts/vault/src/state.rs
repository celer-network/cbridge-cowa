use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// this will save the bech32 string addr
// owner is included in pauser
// use utils::owner::Owner;
// pub const OWNER: Owner = Owner::new("owner"); // save Item under key: owner

use cosmwasm_std::Addr;
use cw_storage_plus::Item;
use utils::pauser::Pauser;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub sig_checker: Addr, // contract address that validates sigs
}

pub const STATE: Item<State> = Item::new("state");
/*
    Pauser {
        Owner,   // default storage_key is "owner"
        Paused,  // default storage_key is "paused"
        Pausers, // default storage_key is "pausers"
    }
 */
pub const PAUSER: Pauser = Pauser::new();