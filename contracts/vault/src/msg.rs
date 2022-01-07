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
    // update contract owner
    UpdateOwner{ newowner: Addr},
    // update sig_checker contract addr as withdraw msg must come from it
    // we can't use signers within vault because sgn only update signers
    // in cbridge module and cbridge contract
    UpdateSigChecker{ newaddr: Addr},

    // withdraw, info.sender must be sig_checker contract addr
    // user need to send pbmsg along with sigs to sigverify contract first
    Withdraw { pbmsg: Binary },

    // to be called by cw20 token contract for user deposit
    // Cw20ReceiveMsg.msg is Deposit
    Receive(cw20::Cw20ReceiveMsg),
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct DepositMsg { // user call cw20.send with this msg
    pub dst_chid: u64,
    pub mint_acnt: Addr,
    pub nonce: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    GetSigChecker {}, // return sig checker contract addr
}