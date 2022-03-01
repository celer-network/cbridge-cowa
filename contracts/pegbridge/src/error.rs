use cosmwasm_std::StdError;
use thiserror::Error;
use utils::owner::OwnerError;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    // OwnerError could happen from owner funcs
    #[error("{0}")]
    Owner(#[from] OwnerError),

    #[error("{0}")]
    DecodeError(#[from] prost::DecodeError)
}