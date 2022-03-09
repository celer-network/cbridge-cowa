use cosmwasm_std::{Addr, CosmosMsg, StdResult, to_binary, Binary, Uint128, WasmMsg};
use cw20_base::state::MinterData;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: Uint128,
    pub mint: Option<MinterData>,
    pub bridge: Addr,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    /// Only with the "mintable" extension. If authorized, creates amount new tokens
    /// and adds to the recipient balance.
    Mint { recipient: String, amount: Uint128 },
    /// Transfer is a base message to move tokens to another account without triggering actions
    Transfer { recipient: String, amount: Uint128 },
    /// Burn is a base message to destroy tokens forever and trigger an action on the bridge
    Burn { amount: Uint128, msg: Binary },
    /// Send is a base message to transfer tokens to a contract and trigger an action
    /// on the receiving contract.
    Send {
        contract: String,
        amount: Uint128,
        msg: Binary,
    },
    /// Update bridge address
    UpdateBridge { bridge: String },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    // GetBridge returns the current bridge
    QueryBridge {},
    QueryBalance {address: String},
    QueryMinter {},
    QueryOwner {},
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub struct Cw20BurnMsg {
    pub sender: String,
    pub amount: Uint128,
    pub msg: Binary,
}

impl Cw20BurnMsg {
    /// serializes the message
    pub fn into_binary(self) -> StdResult<Binary> {
        let msg = ReceiverExecuteMsg::Burn(self);
        to_binary(&msg)
    }

    /// creates a cosmos_msg sending this struct to the named contract
    pub fn into_cosmos_msg<T: Into<String>>(self, contract_addr: T) -> StdResult<CosmosMsg> {
        let msg = self.into_binary()?;
        let execute = WasmMsg::Execute {
            contract_addr: contract_addr.into(),
            msg,
            funds: vec![],
        };
        Ok(execute.into())
    }
}

// This is just a helper to properly serialize the above message
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
enum ReceiverExecuteMsg {
    Burn(Cw20BurnMsg),
}