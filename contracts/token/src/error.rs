use cosmwasm_std::StdError;
use thiserror::Error;
use cw20_base::ContractError as CW20ContractError;
use utils::owner::OwnerError;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    Owner(#[from] OwnerError),

    #[error("{0}")]
    CW20(#[from] CW20ContractError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Invalid zero amount")]
    InvalidZeroAmount {},
}