use thiserror::Error as ThisError;

#[derive(ThisError, Debug, PartialEq, Clone)]
pub enum Error {
    #[error("parse url {0}")]
    Parse(String),
    #[error("invalid host {0}")]
    InvalidHost(String),
    #[error("missing protocol scheme")]
    MissingProtocolScheme,
    #[error("invalid control character in url")]
    InvalidControlCharacterInURL,
    #[error("empty url")]
    EmptyURL,
    #[error("invalid uri {0}")]
    InvalidURI(String),
    #[error("{0}")]
    NormalURL(String),
    #[error("invalid port {0}")]
    InvalidPort(String),
    #[error("invalid userinfo")]
    InvalidUserInfo,
    #[error("invalid semicolon separator in query")]
    InvalidSemicolonSeparatorInQuery,
}
