use cosmwasm_std::{Binary, Uint128};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct InstantiateMsg {
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ExecuteMsg {
    ResetSigners {
        signers: Vec<String>, 
        powers: Vec<Uint128>
    },
    UpdateSigners {
        trigger_time: u64,
        signers: Vec<String>, 
        powers: Vec<Uint128>,
        sigs: Vec<Binary>
    },
    NotifyResetSigners {
    },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    VerifySigs {
        msg: Binary, 
        sigs: Vec<Binary>
    },
    ChainSigners {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct MigrateMsg {
}