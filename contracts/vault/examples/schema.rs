use std::env::current_dir;
use std::fs::create_dir_all;

use cosmwasm_schema::{export_schema, remove_schemas, schema_for};

use vault::msg::{InstantiateMsg, ExecuteMsg, QueryMsg, DepositMsg, GetConfigResp};
use vault::state::State;

fn main() {
    let mut out_dir = current_dir().unwrap();
    out_dir.push("schema");
    create_dir_all(&out_dir).unwrap();
    remove_schemas(&out_dir).unwrap();

    export_schema(&schema_for!(InstantiateMsg), &out_dir);
    export_schema(&schema_for!(ExecuteMsg), &out_dir);
    export_schema(&schema_for!(QueryMsg), &out_dir);
    export_schema(&schema_for!(DepositMsg), &out_dir);
    export_schema(&schema_for!(GetConfigResp), &out_dir);
    export_schema(&schema_for!(State), &out_dir);
}