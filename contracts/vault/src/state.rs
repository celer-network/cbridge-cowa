use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// this will save the bech32 string addr
use utils::owner::Owner;
pub const OWNER: Owner = Owner::new("owner"); // save Item under key: owner

use cosmwasm_std::Addr;
use cw_storage_plus::Item;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub count: i32,
    pub owner: Addr,
}

pub const STATE: Item<State> = Item::new("state");