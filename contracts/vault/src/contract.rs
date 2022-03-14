use std::convert::TryInto;
use std::ops::Deref;
use std::str::FromStr;

#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{from_binary, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, StdError, CosmosMsg, WasmMsg, Uint128, CanonicalAddr, BankMsg, coin, Uint256};
use cw2::set_contract_version;

use cw20::{Cw20ReceiveMsg, Cw20ExecuteMsg};

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg, DepositMsg, GetConfigResp, NativeToken, BridgeQueryMsg};
use crate::vault;

use crate::state::{State, STATE, PAUSER, DEP_IDS, WD_IDS, MIN_DEPOSIT, MAX_DEPOSIT, OWNER, GOVERNOR, DELAYED_TRANSFER, VOLUME_CONTROL};

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
        native_tokens: vec![],
    };
    STATE.save(deps.storage, &state)?;
    // init owner
    OWNER.init_set(deps.storage, &info.sender)?;
    // instantiate governor
    let resp_governor = GOVERNOR.instantiate(deps.storage, &info.sender)?;
    // instantiate pauser
    let resp_pauser = PAUSER.instantiate(deps.storage, &info.sender)?;

    let resp = Response::new();
    Ok(resp.add_attribute("method", "instantiate")
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
        ExecuteMsg::UpdateOwner { new_owner } => Ok(OWNER.update_owner(deps, info, &new_owner)?),
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



        ExecuteMsg::UpdateMinDeposit { token_addr, amount } => update_deposit_amt_setting(deps, info, &token_addr, amount, true),
        ExecuteMsg::UpdateMaxDeposit { token_addr, amount } => update_deposit_amt_setting(deps, info, &token_addr, amount, false),

        ExecuteMsg::UpdateNativeTokens { native_tokens } => update_native_tokens(deps, info, native_tokens),
        
        // cw20 Receive for user deposit, should be called by some cw20 contract, but no guarantee
        // we don't care. because in solidity, anyone can call deposit w/ rogue erc20 contract
        // what about deposit id collision? same issue exists in solidity
        ExecuteMsg::Receive(msg) => do_deposit(deps, info, env.contract.address, msg),

        // Deposit native token, e.g., LUNA and UST
        ExecuteMsg::DepositNative(msg) => do_deposit_native(deps, info, env.contract.address, msg),

        // info.sender could be anyone, withdraw fund works as long as sigs are valid and wdid doesn't exist
        ExecuteMsg::Withdraw {pbmsg, sigs} => do_withdraw(deps, env, pbmsg, sigs),

        // execute a delayed transfer
        ExecuteMsg::ExecuteDelayedTransfer {id} => do_execute_delayed_transfer(deps, env, id),

        // emit an evnet
        ExecuteMsg::EmitEvent {method, params} => do_emit_event(deps.as_ref(), method, params),
    }
}

pub fn do_emit_event(deps: Deps, method: String, params: Vec<Binary>) -> Result<Response, ContractError> {
    match method.as_str() {
        "delayed_transfer_added" => {
            if params.len() != 1 {
                return Err(ContractError::Std(StdError::generic_err("invalid params")));
            }
            Ok(DELAYED_TRANSFER.emit_delayed_transfer_added(deps.storage, &params[0].to_vec())?)
        }
        "delayed_transfer_executed" => {
            if params.len() != 1 {
                return Err(ContractError::Std(StdError::generic_err("invalid params")));
            }
            Ok(DELAYED_TRANSFER.emit_delayed_transfer_executed(deps.storage, &params[0].to_vec())?)
        }
        &_ => {Err(ContractError::Std(StdError::generic_err("unknown event method")))} }
}

pub fn do_execute_delayed_transfer(deps: DepsMut, env: Env, id: Vec<u8>) -> Result<Response, ContractError> {
    // solidity modifier whenNotPaused
    PAUSER.when_not_paused(deps.storage.deref())?;
    let dt = DELAYED_TRANSFER.execute_delayed_transfer(deps.storage, env.block.time.seconds(), &id)?;
    let state = STATE.load(deps.storage)?;
    if let Ok(amount) = u128::from_str(&dt.amount.to_string()) {
        let msg = _send_token(state.native_tokens, dt.token, dt.receiver, amount)?;
        Ok(Response::new().add_message(msg).add_message(
            CosmosMsg::Wasm(
                WasmMsg::Execute {
                    contract_addr: env.contract.address.into_string(),
                    msg: to_binary(&ExecuteMsg::EmitEvent {
                        method: String::from("delayed_transfer_executed"),
                        params: vec![to_binary(&id)?],
                    })?,
                    funds: vec![],
                }
        )))
    } else {
        Err(ContractError::Std(StdError::generic_err("err when parsing Uint256 into u128.")))
    }
}

pub fn do_withdraw(
    deps: DepsMut,
    env: Env,
    pbmsg: Binary,
    sigs: Vec<Binary>,
) -> Result<Response, ContractError> {
    // solidity modifier whenNotPaused
    PAUSER.when_not_paused(deps.storage)?;
    let contract_addr = env.contract.address;
    let domain = func::get_domain(deps.api.addr_canonicalize(contract_addr.as_str()).unwrap(), "Withdraw");
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

    let token = deps.api.addr_humanize(&CanonicalAddr::from(withdraw.token.clone())).unwrap();
    let receiver = deps.api.addr_humanize(&CanonicalAddr::from(withdraw.receiver.clone())).unwrap();
    let amount = u128::from_be_bytes(withdraw.amount.clone().try_into().unwrap());

    let mut res = Response::new()
        .add_attribute("action", "withdraw")
        .add_attribute("wd_id", hex::encode(wd_id.clone()))
        .add_attribute("receiver", hex::encode(withdraw.receiver))
        .add_attribute("token", hex::encode(withdraw.token))
        .add_attribute("amount", hex::encode(withdraw.amount))
        .add_attribute("ref_chain_id", withdraw.ref_chain_id.to_string())
        .add_attribute("ref_id", hex::encode(withdraw.ref_id))
        .add_attribute("burn_acct", hex::encode(withdraw.burn_account));

    VOLUME_CONTROL.update_volume(deps.storage, env.block.time.seconds(), &token, &Uint256::from(amount))?;
    let delay_threshold = DELAYED_TRANSFER.get_delay_threshold(deps.storage.deref(), &token)?;
    if Uint256::from(amount) > delay_threshold {
        // delay transfer
        DELAYED_TRANSFER.add_delayed_transfer(
            deps.storage,
            env.block.time.seconds(),
            wd_id.as_ref(),
            &receiver,
            &token,
            &Uint256::from(amount),
        )?;
        res = res.add_message(
            CosmosMsg::Wasm(
                WasmMsg::Execute {
                    contract_addr: contract_addr.into_string(),
                    msg: to_binary(&ExecuteMsg::EmitEvent {
                        method: String::from("delayed_transfer_added"),
                        params: vec![to_binary(&wd_id)?],
                    })?,
                    funds: vec![],
                }
            )
        )
    } else {
        // send token
        let send_token_msg: CosmosMsg = _send_token(state.native_tokens, token, receiver, amount)?;
        res = res.add_message(send_token_msg);
    }

    Ok(res)
}

fn _send_token(native_tokens: Vec<NativeToken>, token: Addr, receiver: Addr, amount: u128) -> StdResult<CosmosMsg> {
    if let Ok(i) = native_tokens.binary_search_by_key(&token, |n| n.mapped_addr.clone()) {
        // native token
        Ok(CosmosMsg::Bank(BankMsg::Send {
            to_address: receiver.into_string(),
            amount: vec![coin(amount, &native_tokens[i].denom)],
        }))
    } else {
        // cw20 token
        Ok(CosmosMsg::Wasm(WasmMsg::Execute {
            contract_addr: token.into_string(),
            msg: to_binary(&Cw20ExecuteMsg::Transfer {
                recipient: receiver.into_string(),
                amount: Uint128::from(amount),
            })?,
            funds: vec![],
        }))
    }
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

pub fn update_deposit_amt_setting(
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
        MIN_DEPOSIT.save(deps.storage, valid_addr, &amount)?;
    } else {
        MAX_DEPOSIT.save(deps.storage, valid_addr, &amount)?;
    }

    Ok(Response::new()
        .add_attribute("action", "update_".to_owned() + if is_min { "min" } else { "max" } + "_deposit")
        .add_attribute("token", token_addr)
        .add_attribute("amount", amount.to_string()))
}

pub fn update_native_tokens(
    deps: DepsMut,
    info: MessageInfo,
    native_tokens: Vec<NativeToken>,
) -> Result<Response, ContractError> {
    // must called by owner
    OWNER.assert_owner(deps.as_ref(), &info)?;
    
    STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
        state.native_tokens = native_tokens.clone();
        Ok(state)
    })?;

    Ok(Response::new()
        .add_attribute("action", "update_native_tokens")
        .add_attribute("native_tokens", serde_json_wasm::to_string(&native_tokens).unwrap()))
}

pub fn do_deposit(
    deps: DepsMut,
    info: MessageInfo,
    contract_addr: Addr,
    wrapped: Cw20ReceiveMsg,
) -> Result<Response, ContractError> {
    // solidity modifier whenNotPaused
    PAUSER.when_not_paused(deps.storage)?;
    let token = info.sender; // cw20 contract Addr
    let user = wrapped.sender; // user who called cw20.send
    let amount = wrapped.amount; // Uint128 amount

    let min = MIN_DEPOSIT.may_load(deps.storage, token.clone())?;
    if let Some(min) = min {
        if amount.u128() <= min {
            return Err(ContractError::Std(StdError::generic_err("amount too small")));
        }
    }
    let max = MAX_DEPOSIT.may_load(deps.storage, token.clone())?;
    if let Some(max) = max {
        if amount.u128() > max {
            return Err(ContractError::Std(StdError::generic_err("amount too large")));
        }
    }

    let dep_msg: DepositMsg = from_binary(&wrapped.msg)?;
    let dep_id = func::keccak256(&abi::encode_packed(
        &[
            abi::SolType::Str(&user),
            abi::SolType::Bytes(token.as_bytes()),
            abi::SolType::Bytes(&amount.u128().to_be_bytes()),
            abi::SolType::Bytes(&dep_msg.dst_chid.to_be_bytes()),
            abi::SolType::Str(&dep_msg.mint_acnt),
            abi::SolType::Bytes(&dep_msg.nonce.to_be_bytes()),
            abi::SolType::Bytes(&abi::CHAIN_ID.to_be_bytes()),
            abi::SolType::Bytes(contract_addr.as_bytes())
        ]));
    if DEP_IDS.has(deps.storage, dep_id.clone()) {
        return Err(ContractError::Std(StdError::generic_err("record exists")));
    }
    DEP_IDS.save(deps.storage, dep_id.clone(), &true)?;

    let res = Response::new()
        .add_attribute("action", "deposit")
        .add_attribute("depid", hex::encode(dep_id))
        .add_attribute("from", deps.api.addr_canonicalize(&user).unwrap().to_string())
        .add_attribute("token", deps.api.addr_canonicalize(token.as_str()).unwrap().to_string())
        .add_attribute("amount", amount)
        .add_attribute("dst_chid", dep_msg.dst_chid.to_string())
        .add_attribute("mint_acct", dep_msg.mint_acnt);
    Ok(res)
}

pub fn do_deposit_native(
    deps: DepsMut,
    info: MessageInfo,
    contract_addr: Addr,
    dep_msg: DepositMsg,
) -> Result<Response, ContractError> {
    // solidity modifier whenNotPaused
    PAUSER.when_not_paused(deps.storage)?;

    let tokens = info.funds;
    if tokens.len() != 1 {
        return Err(ContractError::Std(StdError::generic_err("one token type per deposit only")));
    }

    let token_denom = &tokens[0].denom;
    let amount = tokens[0].amount;
    let user = info.sender.into_string();
    let state = STATE.load(deps.storage)?;
    let token: Addr;

    if let Ok(i) = state.native_tokens.binary_search_by_key(token_denom, |n| n.denom.clone()) {
        token = state.native_tokens[i].mapped_addr.clone();
    } else {
        return Err(ContractError::Std(StdError::generic_err("not supported token")));
    }

    let min = MIN_DEPOSIT.may_load(deps.storage, token.clone())?;
    if let Some(min) = min {
        if amount.u128() <= min {
            return Err(ContractError::Std(StdError::generic_err("amount too small")));
        }
    }
    let max = MAX_DEPOSIT.may_load(deps.storage, token.clone())?;
    if let Some(max) = max {
        if amount.u128() > max {
            return Err(ContractError::Std(StdError::generic_err("amount too large")));
        }
    }

    let dep_id = func::keccak256(&abi::encode_packed(
        &[
            abi::SolType::Str(&user),
            abi::SolType::Bytes(token.as_bytes()),
            abi::SolType::Bytes(&amount.u128().to_be_bytes()),
            abi::SolType::Bytes(&dep_msg.dst_chid.to_be_bytes()),
            abi::SolType::Str(&dep_msg.mint_acnt),
            abi::SolType::Bytes(&dep_msg.nonce.to_be_bytes()),
            abi::SolType::Bytes(&abi::CHAIN_ID.to_be_bytes()),
            abi::SolType::Bytes(contract_addr.as_bytes())
        ]));
    if DEP_IDS.has(deps.storage, dep_id.clone()) {
        return Err(ContractError::Std(StdError::generic_err("record exists")));
    }
    DEP_IDS.save(deps.storage, dep_id.clone(), &true)?;

    let res = Response::new()
        .add_attribute("action", "deposit")
        .add_attribute("depid", hex::encode(dep_id))
        .add_attribute("from", deps.api.addr_canonicalize(&user).unwrap().to_string())
        .add_attribute("token", deps.api.addr_canonicalize(token.as_str()).unwrap().to_string())
        .add_attribute("amount", amount)
        .add_attribute("dst_chid", dep_msg.dst_chid.to_string())
        .add_attribute("mint_acct", dep_msg.mint_acnt);
    Ok(res)
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

#[cfg(test)]
mod tests {
    use super::*;

    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    #[test]
    fn instantiate_test() {
        let mut deps = mock_dependencies(&[]);
        let owner_addr = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let signer_addr = Addr::unchecked("0x7F4A47e039328F95deC1919aA557E998774eD8dA");
        let msg = InstantiateMsg{ sig_checker: signer_addr };
        let info = mock_info(owner_addr.as_ref(), &[]);

        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg.clone());
        assert!(!res.is_err());

        // could not initialize twice
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg.clone());
        assert!(res.is_err());
    }
}
