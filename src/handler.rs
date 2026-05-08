//! Consumer-facing handler traits.
//!
//! All traits return [`futures::future::BoxFuture`] so they remain
//! object-safe (`Arc<dyn QueryHandler>` etc.). Implementations typically use
//! the `async move { ... }.boxed()` pattern from [`futures::FutureExt`]:
//!
//! ```no_run
//! use futures::FutureExt;
//! use futures::future::BoxFuture;
//! use rwhois::handler::QueryHandler;
//! use rwhois::query::Query;
//! use rwhois::wire::ResponseWriter;
//!
//! struct MyHandler;
//! impl QueryHandler for MyHandler {
//!     fn handle<'a>(
//!         &'a self,
//!         _q: &'a Query,
//!         _out: &'a mut ResponseWriter,
//!     ) -> BoxFuture<'a, rwhois::Result<()>> {
//!         async move { Ok(()) }.boxed()
//!     }
//! }
//! ```
//!
//! A `Server` is built by registering one or more of these. Only
//! [`QueryHandler`] is required; the rest are optional.

use futures::future::BoxFuture;

use crate::Result;
use crate::context::ServerContext;
use crate::query::Query;
use crate::session::Session;
use crate::wire::response::ResponseWriter;

/// Convenience alias for handler return types.
pub type HandlerFuture<'a, T = ()> = BoxFuture<'a, Result<T>>;

/// Handles non-directive query lines.
pub trait QueryHandler: Send + Sync + 'static {
    /// Append zero or more record lines (and any `%referral` lines) to `out`.
    /// Returning `Ok(())` is success; the session writes the terminating
    /// `%ok` after flushing. Return `Err(Error::Protocol { .. })` to surface
    /// a specific response code.
    fn handle<'a>(
        &'a self,
        query: &'a Query,
        out: &'a mut ResponseWriter,
    ) -> HandlerFuture<'a>;
}

/// Provides per-class metadata for the `-class` directive (RFC 2167 §3.3.1).
pub trait ClassProvider: Send + Sync + 'static {
    /// Append `%class …` lines for the requested auth area / classes.
    /// `classes` is empty when the client requested all classes.
    fn list<'a>(
        &'a self,
        auth_area: &'a str,
        classes: &'a [String],
        out: &'a mut ResponseWriter,
    ) -> HandlerFuture<'a>;
}

/// Provides per-class schema for the `-schema` directive (RFC 2167 §3.3.10).
pub trait SchemaProvider: Send + Sync + 'static {
    /// Append `%schema …` lines for the requested auth area / classes.
    fn list<'a>(
        &'a self,
        auth_area: &'a str,
        classes: &'a [String],
        out: &'a mut ResponseWriter,
    ) -> HandlerFuture<'a>;
}

/// Provides Start-of-Authority info for `-soa` (RFC 2167 §3.3.12).
pub trait SoaProvider: Send + Sync + 'static {
    /// Append `%soa …` lines for the listed auth areas (empty = all).
    fn list<'a>(
        &'a self,
        auth_areas: &'a [String],
        out: &'a mut ResponseWriter,
    ) -> HandlerFuture<'a>;
}

/// Bulk record transfer for `-xfer` (RFC 2167 §3.3.14).
pub trait XferProvider: Send + Sync + 'static {
    /// Append `%xfer …` lines for the requested transfer.
    /// `args` is the remainder of the directive line (already trimmed).
    fn xfer<'a>(
        &'a self,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> HandlerFuture<'a>;
}

/// Handles the `-register` flow (RFC 2167 §3.3.9).
///
/// The dispatcher calls these in this order per registration:
///
/// 1. [`Self::begin`] when `-register on <action> <email> [args]` arrives.
/// 2. [`Self::accept_line`] zero or more times for each spool line.
/// 3. [`Self::finish`] when `-register off` arrives.
pub trait RegisterHandler: Send + Sync + 'static {
    /// Called when `-register on …` is received.
    fn begin<'a>(
        &'a self,
        action: &'a str,
        email: &'a str,
        args: &'a str,
    ) -> HandlerFuture<'a>;

    /// Called for each spooled line between `-register on` and `-register off`.
    fn accept_line<'a>(&'a self, line: &'a str) -> HandlerFuture<'a>;

    /// Called on `-register off`. Push response lines (e.g. `%register ID:…`)
    /// onto `out`; the dispatcher writes the trailing `%ok`.
    fn finish<'a>(&'a self, out: &'a mut ResponseWriter) -> HandlerFuture<'a>;
}

/// Generates `%referral` URLs for queries that fall outside local data.
pub trait ReferralProvider: Send + Sync + 'static {
    /// Append zero or more `%referral …` lines.
    fn referrals<'a>(
        &'a self,
        query: &'a Query,
        out: &'a mut ResponseWriter,
    ) -> HandlerFuture<'a>;
}

/// Handles `-security` authentication exchanges (RFC 2167 §3.3.11).
pub trait AuthHandler: Send + Sync + 'static {
    /// Process a security directive payload.
    fn authenticate<'a>(
        &'a self,
        ctx: &'a ServerContext,
        session: &'a mut Session,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> HandlerFuture<'a>;
}
