use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// this will save the bech32 string addr
use utils::owner::Owner;
pub const OWNER: Owner = Owner::new("owner"); // save Item under key: owner

use cosmwasm_std::Addr;
use cw_storage_plus::{Item, Map};
use utils::delayed_transfer::DelayedTransfer;
use utils::governor::Governor;
use utils::pauser::Pauser;
use utils::volume_control::VolumeControl;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub sig_checker: Addr, // contract address that validates sigs
}

pub const STATE: Item<State> = Item::new("state");
pub const MINT_IDS: Map<Vec<u8>, bool> = Map::new("mint_ids");

/*
    pub struct Pauser<'a>{
        owner: &'a Owner<'a>,
        paused: Item<'a, bool>,
        pausers: Map<'a, &'a Addr, bool>,
}
 */
pub const PAUSER: Pauser = Pauser::new("paused", "pausers", &OWNER);
/*
    pub struct Governor<'a>{
        owner: &'a Owner<'a>,
        governors: Map<'a, &'a Addr, bool>,
}
 */
pub const GOVERNOR: Governor = Governor::new("governors", &OWNER);
/*
    pub struct DelayedTransfer<'a>{
        governor: &'a Governor<'a>,
        delay_period: Item<'a, u64>,
        delay_thresholds: Map<'a, &'a Addr, Uint256>,
        delayed_transfers: Map<'a, Vec<u8>, DelayedXfer>,
}
*/
pub const DELAYED_TRANSFER: DelayedTransfer = DelayedTransfer::new(&GOVERNOR);
/*
    pub struct VolumeControl<'a>{
        governor: &'a Governor<'a>,
        epoch_length: Item<'a, u64>,
        epoch_volumes: Map<'a, &'a Addr, Uint256>,
        epoch_volume_caps: Map<'a, &'a Addr, Uint256>,
        last_op_timestamps: Map<'a, &'a Addr, u64>,
}
*/
pub const VOLUME_CONTROL: VolumeControl = VolumeControl::new(&GOVERNOR);