#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, StdError, to_binary};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, MigrateMsg};
use crate::state::{SIGNERS, OWNER};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:bridge";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    _: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    OWNER.init_set(deps.storage, &info.sender.clone())?;
    SIGNERS.init_set(deps.storage, &info.sender)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ResetSigners {signers, powers} =>
            Ok(SIGNERS.reset_signers(deps, info, _env.block.time.seconds(), signers.as_slice(), powers.as_slice())?),
        ExecuteMsg::UpdateSigners {trigger_time, signers, powers, sigs} =>
            Ok(SIGNERS.update_signers(deps, trigger_time, _env.contract.address, signers.as_slice(), powers.as_slice(), sigs.as_slice())?),
        ExecuteMsg::NotifyResetSigners {} =>
            Ok(SIGNERS.notify_reset_signers(deps, info, _env.block.time.seconds())?),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VerifySigs {msg, sigs} => verify_sigs(deps, msg, sigs),
        QueryMsg::ChainSigners {} => to_binary(&SIGNERS.get_signer_powers(deps)?),
    }
}

pub fn verify_sigs(deps: Deps, msg: Binary, sigs: Vec<Binary>) -> StdResult<Binary> {
    match SIGNERS.verify_sigs(deps, msg.as_slice(), sigs.as_slice()) {
        Ok(_) => to_binary("success"),
        Err(error) => StdResult::Err(StdError::generic_err(error.to_string())),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{Uint128};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg{};
        let info = mock_info("creator", &[]);

        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg.clone());
        assert!(!res.is_err());
        
        // could not initialize twice
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg.clone());
        assert!(res.is_err());    
    }

    #[test]
    fn update_signers() {
        let mut deps = mock_dependencies();
        let info = mock_info("creator", &[]);
        let env = mock_env();
        instantiate(deps.as_mut(), env.clone(), info.clone(), InstantiateMsg{}).unwrap();

        let bytes: &[u8] = &[0xC1, 0x69, 0x9e, 0x89, 0x63, 0x9a, 0xDd, 0xa8, 0xf3, 0x9f, 0xAe, 0xFc, 0x0F, 0xc2, 0x94, 0xee, 0x5C, 0x3B, 0x46, 0x2d]; 
        let msg = ExecuteMsg::ResetSigners {
            signers: vec![hex::encode(bytes)],
            powers: vec![Uint128::from(100000000000u128)],
        };

        let s = serde_json_wasm::to_string(&msg).unwrap();
        println!("{}", s);

        // unwrap successfully
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        let bytes0: &[u8] = &[0xC3, 0x10, 0x19, 0x5e, 0x28, 0x44, 0x79, 0x1C, 0xFd, 0x11, 0xD1, 0x58, 0xbD, 0x13, 0xe5, 0x64, 0x9B, 0xae, 0x83, 0x2d];
        let bytes1: &[u8] = &[0xc2, 0x2c, 0x30, 0x46, 0x60, 0xD5, 0xF1, 0xD2, 0xa7, 0xA4, 0x59, 0xCE, 0xEf, 0xc0, 0xc2, 0xcB, 0x30, 0xf5, 0xCF, 0xe4];
        let bytes2: &[u8] = &[0xC1, 0x69, 0x9e, 0x89, 0x63, 0x9a, 0xDd, 0xa8, 0xf3, 0x9f, 0xAe, 0xFc, 0x0F, 0xc2, 0x94, 0xee, 0x5C, 0x3B, 0x46, 0x2d];
        let bytes3: &[u8] = &[0xC4, 0xEb, 0xeA, 0x4E, 0xBD, 0x51, 0xC4, 0x3a, 0x92, 0xCb, 0x97, 0x00, 0xf0, 0x87, 0x70, 0xbc, 0x8f, 0x26, 0x4D, 0x32];
        let msg = ExecuteMsg::UpdateSigners {
            trigger_time: 1,
            signers: vec![hex::encode(bytes0), hex::encode(bytes1), hex::encode(bytes2), hex::encode(bytes3)],
            powers: vec![Uint128::from(12000000000000000000u128),Uint128::from(11000000000000000000u128),Uint128::from(10000000000000000000u128),Uint128::from(9000000000000000000u128)],
            sigs: vec![Binary::from([232,210,131,234,128,44,120,86,224,125,234,228,54,146,101,110,29,79,2,42,93,124,83,238,186,32,110,95,78,250,251,211,82,148,62,4,114,56,88,126,39,254,45,54,214,192,5,85,32,248,71,40,14,244,1,92,2,173,186,30,20,68,24,177,27])],
        };
        let res = execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());
    }
}