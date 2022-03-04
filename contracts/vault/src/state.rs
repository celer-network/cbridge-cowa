use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// this will save the bech32 string addr
use utils::owner::Owner;
pub const OWNER: Owner = Owner::new("owner"); // save Item under key: owner

use cosmwasm_std::{Addr};
use utils::pauser::Pauser;
use cw_storage_plus::{ Item, Map };
use crate::msg::NativeToken;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub sig_checker: Addr, // contract address that validates sigs
    pub native_tokens: Vec<NativeToken>,
}

pub const STATE: Item<State> = Item::new("state");

/*
    Pauser {
        &Owner,   // a reference of OWNER
        Paused,  // default storage_key is "paused"
        Pausers, // default storage_key is "pausers"
    }
 */
pub const PAUSER: Pauser = Pauser::new("paused", "pausers", &OWNER);

pub const DEP_IDS: Map<Vec<u8>, bool> = Map::new("dep_ids");
pub const WD_IDS: Map<Vec<u8>, bool> = Map::new("wd_ids");

pub const MIN_DEPOSIT: Map<Addr, u128> = Map::new("min_deposit");
pub const MAX_DEPOSIT: Map<Addr, u128> = Map::new("max_deposit");
