use cosmwasm_std::{Addr, Binary, Uint256};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub sig_checker: Addr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {    
    /// update contract owner, must be valid cosmwasm bech32 string
    UpdateOwner{ new_owner: String },
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

    /// update sig_checker contract addr as withdraw msg must come from it
    /// we can't use signers within vault because sgn only update signers
    /// in cbridge module and cbridge contract
    /// must be valid cosmwasm bech32 string
    UpdateSigChecker{ newaddr: String },

    UpdateMinDeposit{ token_addr: String, amount: u128 },

    UpdateMaxDeposit{ token_addr: String, amount: u128 },

    UpdateNativeTokens { native_tokens: Vec<NativeToken> },

    /// withdraw from user, vault contract will query sig_checker to verify sigs
    /// unlike solidity, no need to send current signers and their powers
    Withdraw {
        pbmsg: Binary,
        sigs: Vec<Binary>,
    },

    /// to be called by cw20 token contract for user deposit
    /// Cw20ReceiveMsg.msg is Deposit
    Receive(cw20::Cw20ReceiveMsg),

    DepositNative(DepositMsg),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DepositMsg { // user call cw20.send with this msg
    pub dst_chid: u64,
    pub mint_acnt: String, /// ETH address Hex string without 0x prefix
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetConfig {}, // return owner, sig checker contract addr and other info, see GetConfigResp
    // Return if this address is a pauser.
    // Return type: bool
    Pauser {address: String},
    // Return if this contract is paused.
    // Return type: bool
    Paused {},
    // Return if this address is a governor.
    // Return type: bool
    Governor {address: String},
    // Return the delay period.
    // Return type: u64
    DelayPeriod {},
    // Return a token's delay threshold.
    // Return type: Uint256
    DelayThreshold {token: String},
    // Return the delayed transfer by its id.
    // Return type: DelayedTransfer::DelayedXfer
    DelayedTransfer {id: Vec<u8>},
    // Return the epoch length
    // Return type: u64
    EpochLength {},
    // Return a token's epoch volume.
    // Return type: Uint256
    EpochVolume {token: String},
    // Return a token's epoch volume cap.
    // Return type: Uint256
    EpochVolumeCap {token: String},
    // Return a token's last operation timestamp.
    // Return type: u64
    LastOpTimestamp {token: String},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct GetConfigResp {
    pub owner: Addr,
    pub sig_checker: Addr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct NativeToken {
    pub denom: String,
    pub mapped_addr: Addr,
}
