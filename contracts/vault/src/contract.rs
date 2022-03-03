use std::borrow::Borrow;
use std::convert::TryInto;

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, StdError, CosmosMsg, WasmMsg, Uint128};
use cw2::set_contract_version;

use cw20::{Cw20ReceiveMsg, Cw20ExecuteMsg};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, DepositMsg, GetConfigResp};
use crate::vault;

use crate::state::{ State, STATE, OWNER, PAUSER, WD_IDS};

use utils::{abi, func};

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
    // instantiate pauser
    let resp = PAUSER.instantiate(deps.storage, info.sender.borrow())?;

    Ok(resp.add_attribute("method", "instantiate")
        .add_attribute("sig_checker", msg.sig_checker))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        // ONLY owner. set new owner, execute_update_owner checks info.sender equals saved owner
        ExecuteMsg::UpdateOwner { newowner } => Ok(PAUSER.owner.update_owner(deps, info, &newowner)?),
        // ONLY owner. update address for sig checker contract
        ExecuteMsg::UpdateSigChecker { newaddr } => update_sigchecker(deps, info, &newaddr),
        // ONLY owner. add a new pauser.
        ExecuteMsg::AddPauser {newpauser} => PAUSER.execute_add_pauser(deps, info, newpauser),
        // ONLY owner. remove a pauser.
        ExecuteMsg::RemovePauser {pauser} => PAUSER.execute_remove_pauser(deps, info, pauser),

        // ONLY pauser. renounce pauser.
        ExecuteMsg::RenouncePauser {} => PAUSER.execute_renounce_pauser(deps, info),
        // ONLY pauser. pause this contract.
        ExecuteMsg::Pause {} => PAUSER.execute_pause(deps, info),
        // ONLY pauser. unpause this contract.
        ExecuteMsg::Unpause {} => PAUSER.execute_unpause(deps, info),
        
        // cw20 Receive for user deposit, should be called by some cw20 contract, but no guarantee
        // we don't care. because in solidity, anyone can call deposit w/ rogue erc20 contract
        // what about deposit id collision? same issue exists in solidity
        ExecuteMsg::Receive(msg) => do_deposit(deps, info, msg),

        // info.sender could be anyone, withdraw fund works as long as sigs are valid and wdid doesn't exist
        ExecuteMsg::Withdraw {pbmsg, sigs} => do_withdraw(deps, env.contract.address, pbmsg, sigs),
    }
}

pub fn do_withdraw(
    deps: DepsMut,
    contract_addr: Addr,
    pbmsg: Binary,
    sigs: Vec<Binary>,
) -> Result<Response, ContractError> {
    let domain = func::get_domain(contract_addr.clone(), "Withdraw");
    let msg = abi::encode_packed(
            &[
                abi::SolType::Bytes(&domain), 
                abi::SolType::Bytes(pbmsg.as_slice()),
            ]);
    let verify_sig_msg = bridge::msg::QueryMsg::VerifySigs {
        msg: Binary::from(msg), 
        sigs: sigs,
    };
    let state = STATE.load(deps.storage)?;
    deps.querier.query_wasm_smart(state.sig_checker, &verify_sig_msg)?;

    let withdraw: vault::Withdraw = vault::deserialize_withdraw(pbmsg.as_slice())?;
    let wd_id = func::keccak256(&abi::encode_packed(
        &[
            abi::SolType::Bytes(&withdraw.receiver),
            abi::SolType::Bytes(&withdraw.token),
            abi::SolType::Bytes(&withdraw.amount),
            abi::SolType::Bytes(&withdraw.burn_account),
            abi::SolType::Bytes(&withdraw.ref_chain_id.to_be_bytes()),
            abi::SolType::Bytes(&withdraw.ref_id),
            abi::SolType::Bytes(&contract_addr.as_bytes())
        ]));
    if WD_IDS.has(deps.storage, wd_id.clone()) {
        return Err(ContractError::Std(StdError::generic_err("record exists")));
    }
    WD_IDS.save(deps.storage, wd_id.clone(), &true)?;

    // TODO: impl native token support
    let send_token_msg = CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: hex::encode(&withdraw.token),
        msg: to_binary(&Cw20ExecuteMsg::Transfer {
            recipient: hex::encode(&withdraw.receiver), 
            amount: Uint128::from(u128::from_be_bytes(withdraw.amount.clone().try_into().unwrap())),
        })?,
        funds: vec![],
    });

    let res = Response::new()
        .add_attribute("action", "mint")
        .add_attribute("wd_id", hex::encode(wd_id))
        .add_attribute("receiver", hex::encode(withdraw.receiver))
        .add_attribute("token", hex::encode(withdraw.token))
        .add_attribute("amount", hex::encode(withdraw.amount))
        .add_attribute("ref_chain_id", withdraw.ref_chain_id.to_string())
        .add_attribute("ref_id", hex::encode(withdraw.ref_id))
        .add_attribute("burn_acct", hex::encode(withdraw.burn_account))
        .add_message(send_token_msg);
    Ok(res)
}

pub fn update_sigchecker(
    deps: DepsMut,
    info: MessageInfo,
    newaddr: &str,
) -> Result<Response, ContractError> {
    // must called by owner
    PAUSER.owner.assert_owner(deps.as_ref(), &info)?;
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
        QueryMsg::Pauser {address} => to_binary(&PAUSER.query_pauser(deps, address)?),
        QueryMsg::Paused {} => to_binary(&PAUSER.query_paused(deps)?),
    }
}

fn get_config(deps: Deps) -> StdResult<GetConfigResp> {
    let state = STATE.load(deps.storage)?;
    let owner = PAUSER.owner.get(deps)?;
    let resp = GetConfigResp {
        owner: Addr::unchecked(owner),
        sig_checker: state.sig_checker, 
    };
    Ok(resp)
}