use cosmwasm_std::{Binary, CanonicalAddr, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    ResetSigners {
        signers:Vec<CanonicalAddr>, 
        powers: Vec<Uint128>
    },
    UpdateSigners {
        signers:Vec<CanonicalAddr>, 
        powers: Vec<Uint128>,
        sigs: Vec<Binary>
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    VerifySigs {
        msg: Binary, 
        sigs: Vec<Binary>
    },
}