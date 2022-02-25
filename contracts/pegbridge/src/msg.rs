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
    /// update sig_checker contract addr as withdraw msg must come from it
    /// we can't use signers within vault because sgn only update signers
    /// in cbridge module and cbridge contract
    /// must be valid cosmwasm bech32 string
    UpdateSigChecker{ newaddr: String },

    /// Mint for user, pegbridge contract will query sig_checker to verify sigs
    /// unlike solidity, no need to send current signers and their powers
    Mint {
        pbmsg: Binary,
        sigs: Vec<Binary>,
    },

    Burn { 
        token: String, /// CW20 pegged token addr, cosmwasm bech32 string
        amount: u128,
        to_chain_id: u64,
        to_account: String, /// ETH address Hex string without 0x prefix
        nonce: u64,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetConfig {}, // return owner, sig checker contract addr and other info, see GetConfigResp
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct GetConfigResp {
    pub owner: Addr,
    pub sig_checker: Addr,
}
