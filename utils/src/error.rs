use cosmwasm_std::{StdError, RecoverPubkeyError};
use thiserror::Error;
use crate::owner::{OwnerError};

/// Errors returned from Signers
#[derive(Error, Debug)]
pub enum SignersError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    OwnerError(#[from] OwnerError),

    #[error("signing power not enough")]
    NotEnoughPower {},

    #[error("triggerTime is not valid")]
    BadTriggerTime {},

    #[error("{0}")]
    RecoverPubkeyError(#[from] RecoverPubkeyError),
}