#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128, Addr};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{Cw20BurnMsg, ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use crate::state::{BRIDGE, OWNER};

use cw20_base::{
    contract::{
        execute_mint,
        execute_send,
        execute_transfer,
        query_balance,
        query_minter,
        query_token_info,
    },
    state::{
        MinterData,
        TokenInfo,
        TOKEN_INFO,
        BALANCES,
    },
};

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:token";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    // init owner
    OWNER.init_set(deps.storage, &info.sender)?;

    // set bridge addr
    BRIDGE.save(deps.storage, &msg.bridge)?;

    // store token info
    let data = TokenInfo {
        name: msg.name,
        symbol: msg.symbol,
        decimals: msg.decimals,
        total_supply: Uint128::zero(),
        // set creator as minter
        mint: Some(MinterData {
            minter: msg.bridge.clone(),
            cap: None,
        }),
    };
    TOKEN_INFO.save(deps.storage, &data)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("bridge", msg.bridge.as_str()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Mint {recipient, amount} => Ok(execute_mint(deps, _env, info, recipient, amount)?),
        ExecuteMsg::Burn {amount, msg } => execute_burn(deps, _env, info, amount, msg),
        ExecuteMsg::Send {contract, amount, msg} => Ok(execute_send(deps, _env, info, contract, amount, msg)?),
        ExecuteMsg::Transfer {recipient, amount} => Ok(execute_transfer(deps, _env, info, recipient, amount)?),
        ExecuteMsg::UpdateBridge {bridge} => execute_update_bridge(deps, info, bridge),
    }
}

pub fn execute_update_bridge(deps: DepsMut, info: MessageInfo, bridge: String) -> Result<Response, ContractError> {
    // must called by owner
    OWNER.assert_owner(deps.as_ref(), &info)?;
    let bridge_addr = deps.api.addr_validate(bridge.as_str())?;
    BRIDGE.save(deps.storage, &bridge_addr)?;
    // update minter
    TOKEN_INFO.update(deps.storage, |mut info| -> StdResult<_> {
        info.mint = Some(MinterData{minter: bridge_addr.clone(), cap: None});
        Ok(info)
    })?;
    Ok(Response::new().add_attribute("action", "update_bridge")
        .add_attribute("bridge", bridge_addr.as_str()))
}

pub fn execute_burn(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: Uint128,
    msg: Binary,
) -> Result<Response, ContractError> {
    if amount == Uint128::zero() {
        return Err(ContractError::InvalidZeroAmount {});
    }

    // lower balance
    BALANCES.update(
        deps.storage,
        &info.sender,
        |balance: Option<Uint128>| -> StdResult<_> {
            Ok(balance.unwrap_or_default().checked_sub(amount)?)
        },
    )?;
    // reduce total_supply
    TOKEN_INFO.update(deps.storage, |mut info| -> StdResult<_> {
        info.total_supply = info.total_supply.checked_sub(amount)?;
        Ok(info)
    })?;

    let bridge = BRIDGE.load(deps.storage)?;

    let res = Response::new()
        .add_attribute("action", "burn")
        .add_attribute("from", info.sender.as_str())
        .add_attribute("amount", amount)
        .add_message(
            Cw20BurnMsg {
                sender: info.sender.into(),
                amount,
                msg,
            }.into_cosmos_msg(bridge)?,
        );
    Ok(res)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Bridge {} => to_binary(&query_bridge(deps)?),
        QueryMsg::Balance {address} => to_binary(&query_balance(deps, address)?),
        QueryMsg::Minter {} => to_binary(&query_minter(deps)?),
        QueryMsg::Owner {} => to_binary(&OWNER.get(deps)?),
        QueryMsg::TokenInfo {} => to_binary(&query_token_info(deps)?),
    }
}

fn query_bridge(deps: Deps) -> StdResult<Addr> {
    BRIDGE.load(deps.storage)
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
    use cosmwasm_std::{coins, from_binary};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies(&[]);
        let bridge = Addr::unchecked("0x6F4A47e039328F95deC1919aA557E998774eD8dA");
        let msg = InstantiateMsg {
            name: "Integers".to_string(),
            symbol: "INT".to_string(),
            decimals: 10,
            bridge: bridge.clone(),
        };
        let info = mock_info("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), mock_env(), QueryMsg::Bridge {}).unwrap();
        let address: Addr = from_binary(&res).unwrap();
        assert_eq!(bridge, address);
    }
}