use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// this will save the bech32 string addr
use utils::owner::Owner;
pub const OWNER: Owner = Owner::new("owner"); // save Item under key: owner

use cosmwasm_std::{Addr};
use utils::pauser::Pauser;
use cw_storage_plus::{ Item, Map };
use utils::delayed_transfer::DelayedTransfer;
use utils::governor::Governor;
use utils::volume_control::VolumeControl;
use crate::msg::NativeToken;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct State {
    pub sig_checker: Addr, // contract address that validates sigs
    pub native_tokens: Vec<NativeToken>,
}

pub const STATE: Item<State> = Item::new("state");

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

pub const DEP_IDS: Map<Vec<u8>, bool> = Map::new("dep_ids");
pub const WD_IDS: Map<Vec<u8>, bool> = Map::new("wd_ids");

pub const MIN_DEPOSIT: Map<Addr, u128> = Map::new("min_deposit");
pub const MAX_DEPOSIT: Map<Addr, u128> = Map::new("max_deposit");
