use cosmwasm_std::{Addr, Binary, Uint256};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use token::msg::Cw20BurnMsg;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub sig_checker: Addr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {    
    /// update contract owner, must be valid cosmwasm bech32 string
    UpdateOwner{ newowner: String },
    /// update sig_checker contract addr as withdraw msg must come from it
    /// we can't use signers within vault because sgn only update signers
    /// in cbridge module and cbridge contract
    /// must be valid cosmwasm bech32 string
    UpdateSigChecker{ newaddr: String },
    /// add new pauser
    /// only called by owner
    AddPauser{new_pauser: String},
    /// remove pauser
    /// only called by owner
    RemovePauser{pauser: String},
    /// renounce pauser
    /// only called by a pauser
    RenouncePauser{},
    /// pause this contract
    /// only called by a pauser
    Pause{},
    /// unpause this contract
    /// only called by a pauser
    Unpause{},
    /// add new governor
    /// only called by owner
    AddGovernor{new_governor: String},
    /// remove governor
    /// only called by owner
    RemoveGovernor{governor: String},
    /// renounce governor
    /// only called by a governor
    RenounceGovernor{},
    /// set delay thresholds
    /// only called by a governor
    SetDelayThresholds{tokens: Vec<String>, thresholds: Vec<Uint256>},
    /// set delay period
    /// only called by a governor
    SetDelayPeriod{period: u64},
    /// set epoch volume caps
    /// only called by a governor
    SetEpochVolumeCaps{tokens: Vec<String>, caps: Vec<Uint256>},
    /// set epoch length
    /// only called by a governor
    SetEpochLength{length: u64},

    /// Mint for user, pegbridge contract will query sig_checker to verify sigs
    /// unlike solidity, no need to send current signers and their powers
    Mint {
        pbmsg: Binary,
        sigs: Vec<Binary>,
    },
    /// This must be called by governor, will allow a new cw20 token to be burn
    Allow(AllowMsg),
    /// called by a CW20 based test token
    Burn ( Cw20BurnMsg ),
    UpdateMinBurn{ token_addr: String, amount: u128 },
    UpdateMaxBurn{ token_addr: String, amount: u128 },
    SetSupply{ token_addr: String, amount: u128 },

    ExecuteDelayedTransfer{id: String},
    EmitEvent{
        method: String,
        params: Vec<Binary>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct AllowMsg {
    pub contract: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct BurnMsg { // user call cw20 based token.burn with this msg
    pub to_chid: u64,
    pub to_acnt: String, /// ETH address Hex string without 0x prefix
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetConfig {}, /// return owner, sig checker contract addr and other info, see GetConfigResp
    /// Return if this address is a pauser.
    /// Return type: bool
    Pauser {address: String},
    /// Return if this contract is paused.
    /// Return type: bool
    Paused {},
    /// Return if this address is a governor.
    /// Return type: bool
    Governor {address: String},
    /// Return the delay period.
    /// Return type: u64
    DelayPeriod {},
    /// Return a token's delay threshold.
    /// Return type: Uint256
    DelayThreshold {token: String},
    /// Return the delayed transfer by its id.
    /// Return type: DelayedTransfer::DelayedXfer
    DelayedTransfer {id: String},
    /// Return the epoch length
    /// Return type: u64
    EpochLength {},
    /// Return a token's epoch volume.
    /// Return type: Uint256
    EpochVolume {token: String},
    /// Return a token's epoch volume cap.
    /// Return type: Uint256
    EpochVolumeCap {token: String},
    /// Return a token's last operation timestamp.
    /// Return type: u64
    LastOpTimestamp {token: String},
    /// Return a token's min burn amount.
    /// Return type: u128
    MinBurn {token: String},
    /// Return a token's max burn amount.
    /// Return type: u128
    MaxBurn {token: String},
    /// Query if a given cw20 contract is allowed. Returns AllowedResponse
    Allowed { contract: String },
    /// Return if a transfer id is recorded.
    /// Return type: bool
    Record {id: String, is_burn: bool},
    // Query the minted amount of the token
    Supply {token: String},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct GetConfigResp {
    pub owner: Addr,
    pub sig_checker: Addr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BridgeQueryMsg {
    VerifySigs {
        msg: Binary, 
        sigs: Vec<Binary>
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct MigrateMsg {
}