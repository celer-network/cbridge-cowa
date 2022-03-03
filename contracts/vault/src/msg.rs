use cosmwasm_std::{Addr,Binary};
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
    UpdateOwner{ newowner: String },
    /// add new pauser
    /// only called by owner
    AddPauser{newpauser: String},
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
    /// update sig_checker contract addr as withdraw msg must come from it
    /// we can't use signers within vault because sgn only update signers
    /// in cbridge module and cbridge contract
    /// must be valid cosmwasm bech32 string
    UpdateSigChecker{ newaddr: String },

    UpdateMinDeposit{ token_addr: String, amount: u128 },

    UpdateMaxDeposit{ token_addr: String, amount: u128 },

    /// withdraw from user, vault contract will query sig_checker to verify sigs
    /// unlike solidity, no need to send current signers and their powers
    Withdraw {
        pbmsg: Binary,
        sigs: Vec<Binary>,
    },

    /// to be called by cw20 token contract for user deposit
    /// Cw20ReceiveMsg.msg is Deposit
    Receive(cw20::Cw20ReceiveMsg),
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
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct GetConfigResp {
    pub owner: Addr,
    pub sig_checker: Addr,
}
