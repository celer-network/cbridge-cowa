#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, GetConfigResp};
use crate::pegbridge;
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
    OWNER.init_set(deps.storage, &info.sender.clone())?;

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
        
        ExecuteMsg::Burn {token, amount, to_chain_id, to_account, nonce} 
            => do_burn(deps, info,token, amount, to_chain_id, to_account, nonce),

        ExecuteMsg::Mint {pbmsg, sigs} => do_mint(deps, info, pbmsg, sigs),
    }
}

pub fn do_mint(
    deps: DepsMut,
    info: MessageInfo,
    pbmsg: Binary,
    sigs: Vec<Binary>,
) -> Result<Response, ContractError> {
    let state = STATE.load(deps.storage)?;
    let mint: pegbridge::Mint = pegbridge::deserialize_mint(pbmsg.as_slice())?;
    // deps.querier, state.sig_checker, calculate  pbmsg, sigs, "Mint"
    // bytes32 domain = keccak256(abi.encodePacked(block.chainid, address(this), "Mint"));
    // sigsVerifier.verifySigs(abi.encodePacked(domain, _request), _sigs, _signers, _powers);
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

pub fn do_burn(
    deps: DepsMut,
    info: MessageInfo,
    token: String, // CW20 pegged token addr, cosmwasm bech32 string
    amount: u128,
    to_chain_id: u64,
    to_account: String, // ETH address Hex string without 0x prefix
    nonce: u64,
) -> Result<Response, ContractError> {

    // to impl
    let res = Response::new()
        .add_attribute("action", "burn")
        .add_attribute("burnid", "") // calculated burnid
        .add_attribute("token", token)
        .add_attribute("amount", amount.to_string())
        .add_attribute("src_chid", to_chain_id.to_string());
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