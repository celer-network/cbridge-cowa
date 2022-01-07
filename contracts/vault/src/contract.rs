#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;
use cw20::{Cw20ReceiveMsg};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, DepositMsg, GetConfigResp};
use crate::state::{ State, STATE, OWNER};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:vault";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // set version
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    // set state eg. sig_checker, if more cfg is needed, add to InstantiateMsg and State
    let state = State {
        sig_checker: msg.sig_checker.clone(),
    };
    STATE.save(deps.storage, &state)?;
    // set init owner
    OWNER.init_set(deps, &info.sender.clone())?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender)
        .add_attribute("sig_checker", msg.sig_checker))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        // ONLY owner. set new owner, execute_update_owner checks info.sender equals saved owner
        ExecuteMsg::UpdateOwner { newowner } => Ok(OWNER.update_owner(deps, info, &newowner)?),
        // ONLY owner. update address for sig checker contract
        ExecuteMsg::UpdateSigChecker { newaddr } => update_sigchecker(deps, info, &newaddr),
        // only sig checker can call this
        ExecuteMsg::Withdraw {pbmsg} => do_withdraw(deps, info, pbmsg),
        // cw20 Receive for user deposit
        ExecuteMsg::Receive(msg) => do_deposit(deps, info, msg),
    }
}

pub fn do_withdraw(
    deps: DepsMut,
    info: MessageInfo,
    pbmsg: Binary,
) -> Result<Response, ContractError> {
    let state = STATE.load(deps.storage)?;
    if state.sig_checker != info.sender {
        return Err(ContractError::Unauthorized {});
    }
    let res = Response::new();
    Ok(res)
}

pub fn update_sigchecker(
    deps: DepsMut,
    info: MessageInfo,
    newaddr: &str,
) -> Result<Response, ContractError> {
    // must called by owner
    OWNER.assert_owner(deps.as_ref(), &info)?;
    // make sure newaddr is valid
    let valid_addr = deps.api.addr_validate(newaddr)?;
    STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
        state.sig_checker = valid_addr;
        Ok(state)
    })?;

    Ok(Response::new()
        .add_attribute("action", "update_sigchecker")
        .add_attribute("newaddr", newaddr))
}

pub fn do_deposit(
    deps: DepsMut,
    info: MessageInfo,
    wrapped: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    let token = info.sender; // cw20 contract Addr
    let user = wrapped.sender; // user who called cw20.send
    let amount = wrapped.amount; // Uint128 amount

    let msg: DepositMsg = from_binary(&wrapped.msg)?;
    // check per token deposit min/max, return err if violate
    // calculate depositId
    // check if depositId exists, return err if found
    // save new depositId
    let res = Response::new()
        .add_attribute("action", "deposit")
        .add_attribute("depid", "") // calculated depid
        .add_attribute("from", user)
        .add_attribute("token", token)
        .add_attribute("amount", amount)
        .add_attribute("dst_chid", msg.dst_chid.to_string())
        .add_attribute("mint_", msg.mint_acnt);
    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_binary(&get_config(deps)?),
    }
}

fn get_config(deps: Deps) -> StdResult<GetConfigResp> {
    let state = STATE.load(deps.storage)?;
    let owner = OWNER.get(deps)?;
    let resp = GetConfigResp {
        owner: Addr::unchecked(owner),
        sig_checker: state.sig_checker, 
    };
    Ok(resp)
}