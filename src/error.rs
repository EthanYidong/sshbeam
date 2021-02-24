use thiserror::Error;

#[derive(Error, Debug)]
pub enum SBError {
    #[error("{0}")]
    Custom(&'static str),
    #[error(transparent)]
    ThrusshKeysError(#[from] thrussh_keys::Error),
    #[error(transparent)]
    ThrusshConfigError(#[from] thrussh_config::Error),
    #[error(transparent)]
    ThrusshError(#[from] thrussh::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}
