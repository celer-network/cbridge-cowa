use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cw_storage_plus::Item;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
}

pub const STATE: Item<State> = Item::new("state");

use utils::signers::Signers;
pub const SIGNERS: Signers = Signers::new();

use utils::owner::Owner;
pub const OWNER: Owner = Owner::new("owner");

