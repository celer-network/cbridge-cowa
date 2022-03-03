use cosmwasm_std::StdError;
use thiserror::Error;
use utils::pauser::PauserError;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    // PauserError could happen from pauser funcs
    #[error("{0}")]
    Owner(#[from] PauserError),

    #[error("{0}")]
    DecodeError(#[from] prost::DecodeError)
}