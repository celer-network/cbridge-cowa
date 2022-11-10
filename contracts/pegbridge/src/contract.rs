#[cfg(not(feature = "library"))]
use std::ops::Deref;
use std::str::FromStr;
use cosmwasm_std::{SubMsgResult, entry_point, Reply, ReplyOn, SubMsg};
use cosmwasm_std::{to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, StdError, CosmosMsg, WasmMsg, Uint128, Uint256, CanonicalAddr, from_binary, Storage};
use cw2::set_contract_version;
use utils::func::keccak256;
use cw20::{Cw20CoinVerified, Cw20ExecuteMsg};
use token::msg::Cw20BurnMsg;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, GetConfigResp, BurnMsg, BridgeQueryMsg, MigrateMsg, AllowMsg};
use crate::pegbridge;
use crate::state::{State, STATE, OWNER, MINT_IDS, GOVERNOR, PAUSER, DELAYED_TRANSFER, VOLUME_CONTROL, MIN_BURN, MAX_BURN, BURN_IDS, ALLOW_LIST, SUPPLIES};

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
    // set init owner
    OWNER.init_set(deps.storage, &info.sender.clone())?;
    // instantiate governor
    let resp_governor = GOVERNOR.instantiate(deps.storage, &info.sender)?;
    // instantiate pauser
    let resp_pauser = PAUSER.instantiate(deps.storage, &info.sender)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender)
        .add_attribute("sig_checker", msg.sig_checker)
        .add_attributes(resp_pauser.attributes)
        .add_attributes(resp_governor.attributes)
    )
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
        ExecuteMsg::UpdateOwner { newowner } => Ok(OWNER.update_owner(deps, info, &newowner)?),
        // ONLY owner. update address for sig checker contract
        ExecuteMsg::UpdateSigChecker { newaddr } => update_sigchecker(deps, info, &newaddr),

        // ONLY owner. add a new pauser.
        ExecuteMsg::AddPauser {new_pauser} => Ok(PAUSER.execute_add_pauser(deps, info, new_pauser)?),
        // ONLY owner. remove a pauser.
        ExecuteMsg::RemovePauser {pauser} => Ok(PAUSER.execute_remove_pauser(deps, info, pauser)?),
        // ONLY pauser. renounce pauser.
        ExecuteMsg::RenouncePauser {} => Ok(PAUSER.execute_renounce_pauser(deps, info)?),
        // ONLY pauser. pause this contract.
        ExecuteMsg::Pause {} => Ok(PAUSER.execute_pause(deps, info)?),
        // ONLY pauser. unpause this contract.
        ExecuteMsg::Unpause {} => Ok(PAUSER.execute_unpause(deps, info)?),

        // ONLY owner. add a new governor.
        ExecuteMsg::AddGovernor {new_governor} => Ok(GOVERNOR.execute_add_governor(deps, info, new_governor)?),
        // ONLY owner. remove a governor.
        ExecuteMsg::RemoveGovernor {governor} => Ok(GOVERNOR.execute_remove_governor(deps, info, governor)?),
        // ONLY governor. renounce governor.
        ExecuteMsg::RenounceGovernor {} => Ok(GOVERNOR.execute_renounce_governor(deps, info)?),
        // ONLY governor. set delay thresholds.
        ExecuteMsg::SetDelayThresholds {tokens, thresholds} => Ok(DELAYED_TRANSFER.execute_set_delay_thresholds(deps, info, tokens, thresholds)?),
        // ONLY governor. set delay period.
        ExecuteMsg::SetDelayPeriod {period} => Ok(DELAYED_TRANSFER.execute_set_delay_period(deps, info, period)?),
        // ONLY governor. set epoch volume caps.
        ExecuteMsg::SetEpochVolumeCaps {tokens, caps} => Ok(VOLUME_CONTROL.execute_set_epoch_volume_caps(deps, info, tokens, caps)?),
        // ONLY governor. set epoch length.
        ExecuteMsg::SetEpochLength {length} => Ok(VOLUME_CONTROL.execute_set_epoch_length(deps, info, length)?),

        ExecuteMsg::Allow(msg) => execute_allow(deps, env, info, msg),
        ExecuteMsg::Burn (msg) => execute_burn(deps, info, env.contract.address, msg),
        ExecuteMsg::Mint {pbmsg, sigs} => do_mint(deps, env, pbmsg, sigs),
        ExecuteMsg::UpdateMinBurn {token_addr, amount} => update_burn_amt_setting(deps, info, token_addr.as_str(), amount, true),
        ExecuteMsg::UpdateMaxBurn {token_addr, amount} => update_burn_amt_setting(deps, info, token_addr.as_str(), amount, false),
        ExecuteMsg::SetSupply {token_addr, amount} => set_supply(deps, info, token_addr.as_str(), amount),

        // execute a delayed transfer
        ExecuteMsg::ExecuteDelayedTransfer {id} => do_execute_delayed_transfer(deps, env, id),

        // emit an evnet
        ExecuteMsg::EmitEvent {method, params} => do_emit_event(deps.as_ref(), env, info, method, params),
    }
}

pub fn do_emit_event(
    deps: Deps,
    env: Env,
    info: MessageInfo,
    method: String,
    params: Vec<Binary>
) -> Result<Response, ContractError> {
    if info.sender.ne(&env.contract.address) {
        return Err(ContractError::Std(StdError::generic_err("only called by self")));
    }
    match method.as_str() {
        "delayed_transfer_added" => {
            if params.len() != 1 {
                return Err(ContractError::Std(StdError::generic_err("invalid params")));
            }
            Ok(DELAYED_TRANSFER.emit_delayed_transfer_added(deps.storage, &from_binary(&params[0])?)?)
        }
        "delayed_transfer_executed" => {
            if params.len() != 1 {
                return Err(ContractError::Std(StdError::generic_err("invalid params")));
            }
            Ok(DELAYED_TRANSFER.emit_delayed_transfer_executed(deps.storage, &from_binary(&params[0])?)?)
        }
        &_ => {Err(ContractError::Std(StdError::generic_err("unknown event method")))} }
}

pub fn do_execute_delayed_transfer(deps: DepsMut, env: Env, id_str: String) -> Result<Response, ContractError> {
    // solidity modifier whenNotPaused
    PAUSER.when_not_paused(deps.storage.deref())?;
    let id = hex::decode(id_str)?;
    let dt = DELAYED_TRANSFER.execute_delayed_transfer(deps.storage, env.block.time.seconds(), &id)?;
    if let Ok(amount) = u128::from_str(&dt.amount.to_string()) {
        let msg = _mint(dt.token, dt.receiver, amount)?;
        let sub_msg = SubMsg{
            id: 1,
            msg: CosmosMsg::Wasm(
                WasmMsg::Execute {
                    contract_addr: env.contract.address.into_string(),
                    msg: to_binary(&ExecuteMsg::EmitEvent {
                        method: String::from("delayed_transfer_executed"),
                        params: vec![to_binary(&id)?],
                    })?,
                    funds: vec![],
                }
            ),
            gas_limit: Some(100000),
            reply_on: ReplyOn::Always
        };
        Ok(Response::new().add_message(msg).add_submessage(sub_msg))
    } else {
        Err(ContractError::Std(StdError::generic_err("err when parsing Uint256 into u128.")))
    }
}

pub fn do_mint(
    deps: DepsMut,
    env: Env,
    pbmsg: Binary,
    sigs: Vec<Binary>,
) -> Result<Response, ContractError> {
    // solidity modifier whenNotPaused
    PAUSER.when_not_paused(deps.storage.deref())?;
    let contract_addr = env.contract.address;
    let domain = func::get_domain(deps.api.addr_canonicalize(contract_addr.as_str()).unwrap(), "Mint");
    let msg = abi::encode_packed(
            &[
                abi::SolType::Bytes(&domain), 
                abi::SolType::Bytes(pbmsg.as_slice()),
            ]);
    let verify_sig_msg = BridgeQueryMsg::VerifySigs {
        msg: Binary::from(msg), 
        sigs: sigs,
    };
    let state = STATE.load(deps.storage)?;
    let _s: String = deps.querier.query_wasm_smart(state.sig_checker, &verify_sig_msg)?;

    let mint: pegbridge::Mint = pegbridge::deserialize_mint(pbmsg.as_slice())?;
    let mint_id = keccak256(&abi::encode_packed(
        &[
            abi::SolType::Bytes(&mint.account),
            abi::SolType::Bytes(&mint.token),
            abi::SolType::Bytes(&abi::pad_to_32_bytes(&mint.amount)),
            abi::SolType::Bytes(&mint.depositor),
            abi::SolType::Bytes(&mint.ref_chain_id.to_be_bytes()),
            abi::SolType::Bytes(&mint.ref_id),
        ]));
    if MINT_IDS.has(deps.storage, mint_id.clone()) {
        return Err(ContractError::Std(StdError::generic_err("record exists")));
    }
    MINT_IDS.save(deps.storage, mint_id.clone(), &true)?;

    let token = deps.api.addr_humanize(&CanonicalAddr::from(mint.token.clone())).unwrap();
    let receiver = deps.api.addr_humanize(&CanonicalAddr::from(mint.account.clone())).unwrap();
    let amount = u128::from_be_bytes(abi::pad_to_16_bytes(&mint.amount.clone()));

    let mut res = Response::new()
        .add_attribute("action", "mint")
        .add_attribute("m_mint_id", hex::encode(mint_id.clone()))
        .add_attribute("m_token", hex::encode(mint.token))
        .add_attribute("m_account", hex::encode(mint.account))
        .add_attribute("m_amount", amount.to_string())
        .add_attribute("m_ref_chain_id", mint.ref_chain_id.to_string())
        .add_attribute("m_ref_id", hex::encode(mint.ref_id))
        .add_attribute("m_depositor", hex::encode(mint.depositor));

    VOLUME_CONTROL.update_volume(deps.storage, env.block.time.seconds(), &token, &Uint256::from(amount))?;
    let delay_threshold = DELAYED_TRANSFER.get_delay_threshold(deps.storage.deref(), &token)?;
    if !delay_threshold.is_zero() && Uint256::from(amount) > delay_threshold {
        // delay transfer
        DELAYED_TRANSFER.add_delayed_transfer(
            deps.storage,
            env.block.time.seconds(),
            mint_id.as_ref(),
            &receiver,
            &token,
            &Uint256::from(amount),
        )?;
        let sub_msg = SubMsg{
            id: 0,
            msg: CosmosMsg::Wasm(
                WasmMsg::Execute {
                    contract_addr: contract_addr.into_string(),
                    msg: to_binary(&ExecuteMsg::EmitEvent {
                        method: String::from("delayed_transfer_added"),
                        params: vec![to_binary(&mint_id)?],
                    })?,
                    funds: vec![],
                }
            ),
            gas_limit: Some(100000),
            reply_on: ReplyOn::Always
        };
        res = res.add_submessage(sub_msg)
    } else {
        // mint token
        let mint_msg: CosmosMsg = _mint(token.clone(), receiver, amount)?;
        res = res.add_message(mint_msg);
    }
    increase_supply(deps.storage, token, amount)?;
    Ok(res)
}

fn _mint(token: Addr, receiver: Addr, amount: u128) -> StdResult<CosmosMsg> {
    // cw20 token
    Ok(CosmosMsg::Wasm(WasmMsg::Execute {
        contract_addr: token.into_string(),
        msg: to_binary(&Cw20ExecuteMsg::Mint {
            recipient: receiver.into_string(),
            amount: Uint128::from(amount),
        })?,
        funds: vec![],
    }))
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

/// Allow new contracts(allow new token to be burnable).
pub fn execute_allow(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    allow: AllowMsg,
) -> Result<Response, ContractError> {
    // must called by governor
    GOVERNOR.only_governor(deps.storage.deref(), &info.sender)?;

    let contract = deps.api.addr_validate(&allow.contract)?;
    ALLOW_LIST.save(deps.storage, &contract, &true)?;

    let res = Response::new()
        .add_attribute("action", "allow")
        .add_attribute("contract", allow.contract);
    Ok(res)
}

pub fn execute_burn(deps: DepsMut, info: MessageInfo, _this: Addr, wrapper: Cw20BurnMsg) -> Result<Response, ContractError> {
    // solidity modifier whenNotPaused
    PAUSER.when_not_paused(deps.storage)?;
    let msg: BurnMsg = from_binary(&wrapper.msg)?;
    let amount = Cw20CoinVerified{
        address: info.sender,
        amount: wrapper.amount
    };
    let api = deps.api;
    do_burn(deps, msg, amount, api.addr_validate(&wrapper.sender)?)
}

pub fn do_burn(
    deps: DepsMut,
    msg: BurnMsg,
    amt: Cw20CoinVerified,
    sender: Addr,
) -> Result<Response, ContractError> {
    ALLOW_LIST
        .may_load(deps.storage, &amt.address)?
        .ok_or(ContractError::NotOnAllowList)?;
    let token = amt.address; // cw20 contract Addr
    let amount = amt.amount; // Uint128 amount

    let min = MIN_BURN.may_load(deps.storage, token.clone())?;
    if let Some(min) = min {
        if amount.u128() <= min {
            return Err(ContractError::Std(StdError::generic_err("amount too small")));
        }
    }
    let max = MAX_BURN.may_load(deps.storage, token.clone())?;
    if let Some(max) = max {
        if amount.u128() > max {
            return Err(ContractError::Std(StdError::generic_err("amount too large")));
        }
    }
    decrease_supply(deps.storage, token.clone(), amount.u128())?;

    let token = deps.api.addr_canonicalize(token.as_str()).unwrap(); // sgnd uses canonical addr
    let burner = deps.api.addr_canonicalize(sender.as_str()).unwrap(); // sgnd uses canonical addr
    let to_acnt = hex::decode(msg.to_acnt.trim_start_matches("0x").trim_start_matches("0X")).unwrap();
    let burn_id = func::keccak256(&abi::encode_packed(
        &[
            abi::SolType::Bytes(&burner),
            abi::SolType::Bytes(&token),
            abi::SolType::Bytes32(&abi::pad_to_32_bytes(&amount.u128().to_be_bytes())),
            abi::SolType::Bytes(&msg.to_chid.to_be_bytes()),
            abi::SolType::Bytes(&to_acnt),
            abi::SolType::Bytes(&msg.nonce.to_be_bytes()),
            abi::SolType::Bytes(&abi::CHAIN_ID.to_be_bytes()),
        ]));
    if BURN_IDS.has(deps.storage, burn_id.clone()) {
        return Err(ContractError::Std(StdError::generic_err("record exists")));
    }
    BURN_IDS.save(deps.storage, burn_id.clone(), &true)?;

    let res = Response::new()
        .add_attribute("action", "burn")
        .add_attribute("b_burnid", hex::encode(burn_id)) // calculated burnid
        .add_attribute("b_token", token.to_string())
        .add_attribute("b_amount", amount.to_string())
        .add_attribute("b_burner", burner.to_string())
        .add_attribute("b_to_chid", msg.to_chid.to_string())
        .add_attribute("b_to_acnt", msg.to_acnt)
        .add_attribute("b_nonce", msg.nonce.to_string());
    Ok(res)
}

pub fn update_burn_amt_setting(
    deps: DepsMut,
    info: MessageInfo,
    token_addr: &str,
    amount: u128,
    is_min: bool,
) -> Result<Response, ContractError> {
    // must called by governor
    GOVERNOR.only_governor(deps.storage.deref(), &info.sender)?;
    // make sure token is valid
    let valid_addr = deps.api.addr_validate(token_addr)?;
    if is_min {
        MIN_BURN.save(deps.storage, valid_addr, &amount)?;
    } else {
        MAX_BURN.save(deps.storage, valid_addr, &amount)?;
    }

    Ok(Response::new()
        .add_attribute("action", "update_".to_owned() + if is_min { "min" } else { "max" } + "_burn")
        .add_attribute("token", token_addr)
        .add_attribute("amount", amount.to_string()))
}

fn set_supply(
    deps: DepsMut,
    info: MessageInfo,
    token_addr: &str,
    amount: u128,
) -> Result<Response, ContractError> {
    OWNER.assert_owner(deps.as_ref(), &info)?;
    let valid_addr = deps.api.addr_validate(token_addr)?;
    SUPPLIES.save(deps.storage, valid_addr, &amount)?;
    Ok(Response::new()
        .add_attribute("action", "set_supply")
        .add_attribute("token", token_addr)
        .add_attribute("amount", amount.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetConfig {} => to_binary(&get_config(deps)?),
        QueryMsg::Pauser {address} => to_binary(&PAUSER.query_pauser(deps, address)?),
        QueryMsg::Paused {} => to_binary(&PAUSER.query_paused(deps)?),
        QueryMsg::Governor {address} => to_binary(&GOVERNOR.query_governor(deps, address)?),
        QueryMsg::DelayPeriod {} => to_binary(&DELAYED_TRANSFER.query_delay_period(deps)?),
        QueryMsg::DelayThreshold {token} => to_binary(&DELAYED_TRANSFER.query_delay_threshold(deps, token)?),
        QueryMsg::DelayedTransfer {id} => to_binary(&DELAYED_TRANSFER.query_delayed_transfer(deps, id)?),
        QueryMsg::EpochLength {} => to_binary(&VOLUME_CONTROL.query_epoch_length(deps)?),
        QueryMsg::EpochVolume {token} => to_binary(&VOLUME_CONTROL.query_epoch_volume(deps, token)?),
        QueryMsg::EpochVolumeCap {token} => to_binary(&VOLUME_CONTROL.query_epoch_volume_cap(deps, token)?),
        QueryMsg::LastOpTimestamp {token} => to_binary(&VOLUME_CONTROL.query_last_op_timestamp(deps, token)?),
        QueryMsg::MinBurn {token} => to_binary(&query_min_burn(deps, token)?),
        QueryMsg::MaxBurn {token} => to_binary(&query_max_burn(deps, token)?),
        QueryMsg::Allowed { contract } => to_binary(&query_allowed(deps, contract)?),
        QueryMsg::Record {id, is_burn} => to_binary(&query_record(deps, id, is_burn)?),
        QueryMsg::Supply {token} => to_binary(&query_supply(deps, token)?),
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

fn query_min_burn(deps: Deps, token: String) -> StdResult<u128> {
    let token = deps.api.addr_validate(&token)?;
    if let Ok(amount) = MIN_BURN.load(deps.storage, token) {
        Ok(amount)
    } else {
        Ok(0)
    }
}

fn query_max_burn(deps: Deps, token: String) -> StdResult<u128> {
    let token = deps.api.addr_validate(&token)?;
    if let Ok(amount) = MAX_BURN.load(deps.storage, token) {
        Ok(amount)
    } else {
        Ok(0)
    }
}

fn query_allowed(deps: Deps, contract: String) -> StdResult<bool> {
    let addr = deps.api.addr_validate(&contract)?;
    Ok(ALLOW_LIST.has(deps.storage, &addr))
}

fn query_supply(deps: Deps, token: String) -> StdResult<u128> {
    let token = deps.api.addr_validate(&token)?;
    if let Ok(amount) = SUPPLIES.load(deps.storage, token) {
        Ok(amount)
    } else {
        Ok(0)
    }
}

fn increase_supply(store: &mut dyn Storage, token: Addr, delta: u128) -> StdResult<u128> {
    let supply = SUPPLIES.may_load(store, token.clone())?;
    let sup_amt;
    if let Some(i) = supply {
        sup_amt = i.checked_add(delta).unwrap();
    } else {
        sup_amt = delta;
    }
    SUPPLIES.save(store, token, &sup_amt)?;

    return Ok(sup_amt)
}

fn decrease_supply(store: &mut dyn Storage, token: Addr, delta: u128) -> StdResult<u128> {
    let supply = SUPPLIES.may_load(store, token.clone())?;
    let sup_amt;
    if let Some(i) = supply {
        sup_amt = i.checked_sub(delta).unwrap();
    } else {
        sup_amt = delta;
    }
    SUPPLIES.save(store, token, &sup_amt)?;

    return Ok(sup_amt)
}

fn query_record(deps: Deps, id_str: String, is_burn: bool) -> StdResult<bool> {
    if let Ok(id) = hex::decode(id_str) {
        if is_burn {
            Ok(BURN_IDS.has(deps.storage, id.clone()))
        } else {
            Ok(MINT_IDS.has(deps.storage, id.clone()))
        }
    } else {
        Err(StdError::generic_err("cannot convert id from hex into byte array"))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_deps: DepsMut, _env: Env, msg: Reply) -> Result<Response, ContractError> {
    match msg.id {
        _ => {
            match msg.result {
                SubMsgResult::Ok(_) => Ok(Response::new()),
                SubMsgResult::Err(err) => Err(ContractError::Std(StdError::generic_err(err)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    #[test]
    fn instantiate_test() {
        let mut deps = mock_dependencies();
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let signer_addr = Addr::unchecked("0x7F4A47e039328F95deC1919aA557E998774eD8dA");
        let msg = InstantiateMsg { sig_checker: signer_addr };
        let info = mock_info(owner_addr.as_ref(), &[]);

        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg.clone());
        assert!(!res.is_err());

        // could not initialize twice
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg.clone());
        assert!(res.is_err());
    }
}