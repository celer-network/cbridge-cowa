use cosmwasm_std::StdError;
use hex::FromHexError;
use thiserror::Error;
use utils::delayed_transfer::DelayedTransferError;
use utils::governor::GovernorError;
use utils::owner::OwnerError;
use utils::pauser::PauserError;
use utils::volume_control::VolumeControlError;

#[derive(Error, Debug)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("You cannot lower the gas limit for a contract on the allow list")]
    CannotLowerGas,

    #[error("You can only burn cw20 tokens that have been explicitly allowed")]
    NotOnAllowList,

    #[error("{0}")]
    Owner(#[from] OwnerError),

    #[error("{0}")]
    Pauser(#[from] PauserError),

    #[error("{0}")]
    Governor(#[from] GovernorError),

    #[error("{0}")]
    DelayedTransfer(#[from] DelayedTransferError),

    #[error("{0}")]
    VolumeControl(#[from] VolumeControlError),

    #[error("{0}")]
    DecodeError(#[from] prost::DecodeError),

    #[error("{0}")]
    HexError(#[from] FromHexError)
}