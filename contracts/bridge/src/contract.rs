#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, CanonicalAddr, Uint128};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
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
    SIGNERS.init_set(deps.storage)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    _: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::VerifySigs {msg, sigs} => verify_sigs(deps, msg, sigs),
        ExecuteMsg::ResetSigners {signers, powers} => reset_signers(deps, signers, powers),
        ExecuteMsg::UpdateSigners {signers, powers, sigs} => update_signers(deps, signers, powers, sigs),
    }
}

pub fn verify_sigs(deps: DepsMut, msg: Binary, sigs: Vec<Binary>) -> Result<Response, ContractError> {
    //to impl
    Ok(Response::new().add_attribute("method", "verify_sigs"))
}

pub fn reset_signers(deps: DepsMut, signers: Vec<CanonicalAddr>, powers: Vec<Uint128>) -> Result<Response, ContractError> {
    //to impl
    Ok(Response::new().add_attribute("method", "reset_signers"))
}

pub fn update_signers(deps: DepsMut, signers: Vec<CanonicalAddr>, powers: Vec<Uint128>, sigs: Vec<Binary>) -> Result<Response, ContractError> {
    //to impl
    Ok(Response::new().add_attribute("method", "update_signers"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
    }
}