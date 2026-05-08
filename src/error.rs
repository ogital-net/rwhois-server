//! Crate error type.

use std::io;

use crate::wire::code::ResponseCode;

/// Convenience alias for `Result<T, rwhois::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors produced by the rwhois server library.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// Underlying I/O failure on the connection.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// A line exceeded [`crate::MAX_LINE`].
    #[error("line exceeded maximum length of {max} bytes")]
    LineTooLong {
        /// Configured maximum line length.
        max: usize,
    },

    /// Malformed input that should be reported to the peer with a response
    /// code (e.g. `350 Invalid Query Syntax`).
    #[error("protocol error ({code:?}): {message}")]
    Protocol {
        /// Response code to surface to the client.
        code: ResponseCode,
        /// Human-readable detail. Sent verbatim after the code.
        message: String,
    },

    /// A handler returned an error that should be reported as `402` unless
    /// otherwise specified.
    #[error("handler error: {0}")]
    Handler(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// The session's idle timer fired.
    #[error("idle timeout exceeded")]
    IdleTimeout,
}

impl Error {
    /// Build a protocol error from a code and detail string.
    pub fn protocol(code: ResponseCode, message: impl Into<String>) -> Self {
        Self::Protocol {
            code,
            message: message.into(),
        }
    }

    /// Wrap any error as a generic handler failure.
    pub fn handler<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::Handler(err.into())
    }
}
