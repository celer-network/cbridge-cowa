#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, CanonicalAddr, Uint128, StdError};
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
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::ResetSigners {signers, powers} => reset_signers(deps, _env.block.time.seconds(), info, signers, powers),
        ExecuteMsg::UpdateSigners {signers, powers, sigs} => update_signers(deps, _env.block.time.seconds(), _env.contract.address, signers, powers, sigs),
    }
}

pub fn reset_signers(deps: DepsMut, block_time: u64, info: MessageInfo, signers: Vec<CanonicalAddr>, powers: Vec<Uint128>) -> Result<Response, ContractError> {
    // must called by owner
    OWNER.assert_owner(deps.as_ref(), &info)?;
    SIGNERS.reset_signers(deps.storage, block_time, signers.as_slice(), powers.as_slice())?;
    Ok(Response::new().add_attribute("method", "reset_signers"))
}

pub fn update_signers(deps: DepsMut, trigger_time: u64, contract_addr: Addr, signers: Vec<CanonicalAddr>, powers: Vec<Uint128>, sigs: Vec<Binary>) -> Result<Response, ContractError> {
    let sigs: Vec<&[u8]> = sigs.iter().map(
        |s| s.as_slice()
    ).collect();
    SIGNERS.update_signers(deps, trigger_time, contract_addr, signers.as_slice(), powers.as_slice(), sigs.as_slice())?;
    Ok(Response::new().add_attribute("method", "update_signers"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::VerifySigs {msg, sigs} => verify_sigs(deps, msg, sigs),
    }
}

pub fn verify_sigs(deps: Deps, msg: Binary, sigs: Vec<Binary>) -> StdResult<Binary> {
    let sigs: Vec<&[u8]> = sigs.iter().map(
        |s| s.as_slice()
    ).collect();
    match SIGNERS.verify_sigs(deps, msg.as_slice(), sigs.as_slice()) {
        Ok(_) => StdResult::Ok(Binary::default()),
        Err(error) => StdResult::Err(StdError::generic_err(error.to_string())),
    }
}