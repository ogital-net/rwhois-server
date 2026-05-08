//! Shared, immutable per-server context handed to every directive and
//! handler.
//!
//! `ServerContext` exposes the directive registry, the (optional) provider
//! and handler trait objects, and a few server-wide knobs (hostname, idle
//! timeout). It is constructed by [`crate::ServerBuilder`] and shared via
//! `Arc` across all per-connection tasks.

use std::sync::Arc;
use std::time::Duration;

use crate::directive::Registry;
use crate::handler::{
    AuthHandler, ClassProvider, QueryHandler, ReferralProvider, RegisterHandler, SchemaProvider,
    SoaProvider, XferProvider,
};
use crate::wire::{Banner, Capability};

/// Immutable per-server context. Cheap to clone (`Arc` internally is shared
/// by reference); also passed by `&` to handlers and directives.
#[non_exhaustive]
pub struct ServerContext {
    /// Registered directive table (built-ins + any consumer overrides).
    pub directives: Registry,
    /// Server hostname advertised in the banner.
    pub hostname: String,
    /// Per-line idle timeout applied between client lines.
    pub idle_timeout: Duration,
    /// Maximum line length (bytes including CRLF).
    pub max_line: usize,

    /// Required: query handler.
    pub query: Option<Arc<dyn QueryHandler>>,
    /// Optional: class metadata.
    pub class: Option<Arc<dyn ClassProvider>>,
    /// Optional: schema metadata.
    pub schema: Option<Arc<dyn SchemaProvider>>,
    /// Optional: SOA.
    pub soa: Option<Arc<dyn SoaProvider>>,
    /// Optional: bulk xfer.
    pub xfer: Option<Arc<dyn XferProvider>>,
    /// Optional: registration.
    pub register: Option<Arc<dyn RegisterHandler>>,
    /// Optional: referrals.
    pub referral: Option<Arc<dyn ReferralProvider>>,
    /// Optional: auth.
    pub auth: Option<Arc<dyn AuthHandler>>,
}

impl ServerContext {
    /// Build the `%rwhois` greeting banner that should be sent to a newly
    /// connected peer (and re-emitted in response to a `-rwhois` directive).
    /// The capability mask reflects the currently-registered directives.
    #[must_use]
    pub fn banner(&self) -> Banner {
        Banner::single(
            1,
            5,
            Capability::new(self.directives.capability_mask() & 0x00ff_ffff, 0),
            self.hostname.clone(),
            Some("(rwhois rust server)".to_owned()),
        )
    }
}

impl std::fmt::Debug for ServerContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerContext")
            .field("directives", &self.directives)
            .field("hostname", &self.hostname)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_line", &self.max_line)
            .field("has_query", &self.query.is_some())
            .field("has_class", &self.class.is_some())
            .field("has_schema", &self.schema.is_some())
            .field("has_soa", &self.soa.is_some())
            .field("has_xfer", &self.xfer.is_some())
            .field("has_register", &self.register.is_some())
            .field("has_referral", &self.referral.is_some())
            .field("has_auth", &self.auth.is_some())
            .finish()
    }
}
