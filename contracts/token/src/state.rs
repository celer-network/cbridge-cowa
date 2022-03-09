use cosmwasm_std::Addr;
use cw_storage_plus::Item;
use utils::owner::Owner;

pub const OWNER: Owner = Owner::new("owner"); // save Item under key: owner
pub const BRIDGE: Item<Addr> = Item::new("bridge");