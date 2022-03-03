use cosmwasm_std::StdError;
use thiserror::Error;
use utils::owner::OwnerError;
use utils::pauser::PauserError;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("{0}")]
    Owner(#[from] OwnerError),

    #[error("{0}")]
    Pauser(#[from] PauserError),

    #[error("{0}")]
    DecodeError(#[from] prost::DecodeError)
}