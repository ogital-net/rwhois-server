//! Per-connection session state.

use std::net::SocketAddr;
use std::time::Duration;

/// Session phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionState {
    /// Normal request/response loop — non-directive lines are queries.
    Query,
    /// Inside `-register on … -register off` — non-directive lines are
    /// appended to the registration spool.
    Spool,
}

/// Mutable per-connection state.
///
/// Mirrors the C reference's `rwhois_state_struct` plus the per-process
/// settings that, in the fork-per-connection model, are effectively per
/// connection (`hit_limit`, `hold_connect`, `forward`, `display`).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Session {
    /// Remote peer address.
    pub peer: SocketAddr,
    /// Current phase.
    pub state: SessionState,
    /// Hold the connection open after a query? Default `false`.
    pub hold_connect: bool,
    /// Maximum number of objects to return per query.
    pub hit_limit: usize,
    /// Whether the server should follow referrals on behalf of the client.
    pub forward: bool,
    /// Display format name (`"dump"` is the only built-in).
    pub display: String,
    /// Whether `-security` has placed the session in secure mode.
    pub secure_mode: bool,
    /// Client implementation string from `-rwhois`.
    pub client_vendor_id: Option<String>,
    /// Idle timeout applied between client lines.
    pub idle_timeout: Duration,
    /// Email associated with an in-flight `-register`.
    pub register_email: Option<String>,
    /// Action of an in-flight `-register` (`add`/`mod`/`del`).
    pub register_action: Option<String>,
}

impl Session {
    /// Build a session with reference-server defaults.
    #[must_use] 
    pub fn new(peer: SocketAddr) -> Self {
        Self {
            peer,
            state: SessionState::Query,
            hold_connect: false,
            hit_limit: 0,
            forward: false,
            display: "dump".to_owned(),
            secure_mode: false,
            client_vendor_id: None,
            idle_timeout: Duration::from_secs(120),
            register_email: None,
            register_action: None,
        }
    }

    /// True iff the session is currently spooling registration lines.
    #[must_use] 
    pub fn is_spooling(&self) -> bool {
        matches!(self.state, SessionState::Spool)
    }
}
