use cosmwasm_std::StdError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("CW20 error: {0}")]
    Cw20(String),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Invalid proof: {reason}")]
    InvalidProof { reason: String },

    #[error("Verification failed")]
    VerificationFailed {},

    #[error("Invalid hex input: {reason}")]
    InvalidHex { reason: String },

    #[error("No token to burn: insufficient CW20 balance")]
    NoTokenToBurn {},

    #[error("Insufficient vault depth: need at least {required} active entries, have {available}")]
    InsufficientVaultDepth { required: u64, available: u64 },

    #[error("No active payloads available for selection")]
    NoActivePayloads {},

    #[error("Commitment already used: duplicate deposit rejected")]
    CommitmentAlreadyUsed {},

    #[error("Invalid oracle signature: semantic binding verification failed")]
    InvalidOracleSignature {},

    #[error("Payload nullifier already used: duplicate data rejected")]
    NullifierAlreadyUsed {},

    #[error(
        "Invalid payload nullifier: must be a 64-character lowercase hex string (SHA-256 digest)"
    )]
    InvalidNullifier {},

    #[error("A randomness request is already pending for this sender")]
    RequestAlreadyPending {},

    #[error("No pending randomness request found for the specified buyer")]
    NoPendingRequest {},

    #[error("Unauthorized: only the oracle relayer may call this entry point")]
    UnauthorizedOracle {},

    #[error("Oracle address not configured: BurnAndRequest / FulfillRandomness unavailable")]
    OracleNotConfigured {},

    #[error("Oracle timeout not yet elapsed: recovery available after {timeout_height} (current: {current_height})")]
    OracleTimeoutNotElapsed {
        timeout_height: u64,
        current_height: u64,
    },

    #[error("Invalid random seed: must be a decimal string representing a u64 value")]
    InvalidRandomSeed {},
}

impl From<cw20_base::ContractError> for ContractError {
    fn from(err: cw20_base::ContractError) -> Self {
        ContractError::Cw20(err.to_string())
    }
}
