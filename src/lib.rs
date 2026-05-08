//! # rwhois
//!
//! Async, tokio-based server library for the **Referral Whois** protocol
//! (RFC 2167). The crate handles the wire protocol — line framing, the banner,
//! response codes, directive dispatch, session state, idle timeouts and
//! hold-connect semantics — and delegates all data lookups to consumer-supplied
//! trait implementations.
//!
//! See `CLAUDE.md` at the repo root for design notes and a map back to the
//! reference C implementation under `ref/rwhoisd/`.
//!
//! # Quick start
//!
//! ```no_run
//! use futures::FutureExt;
//! use futures::future::BoxFuture;
//! use rwhois::handler::QueryHandler;
//! use rwhois::query::Query;
//! use rwhois::wire::response::ResponseWriter;
//! use rwhois::{Result, Server};
//!
//! struct Echo;
//! impl QueryHandler for Echo {
//!     fn handle<'a>(
//!         &'a self,
//!         q: &'a Query,
//!         out: &'a mut ResponseWriter,
//!     ) -> BoxFuture<'a, Result<()>> {
//!         async move {
//!             out.record_attr("echo", "query", &q.raw);
//!             Ok(())
//!         }
//!         .boxed()
//!     }
//! }
//!
//! # async fn run() -> Result<()> {
//! let server = Server::builder()
//!     .hostname("rwhois.example.com")
//!     .query_handler(Echo)
//!     .bind("127.0.0.1:0")
//!     .await?;
//! server.serve().await
//! # }
//! ```
//!
//! For graceful shutdown, use [`Server::serve_with_shutdown`] with any
//! `Future<Output = ()>` (e.g. `tokio::signal::ctrl_c()`).

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]

pub mod codec;
pub mod context;
pub mod directive;
pub mod error;
pub mod handler;
pub mod query;
pub mod server;
pub mod session;
pub mod wire;

pub use context::ServerContext;

pub use error::{Error, Result};
pub use server::{Server, ServerBuilder};
pub use wire::code::ResponseCode;

/// Maximum length of a single protocol line, in bytes.
///
/// Mirrors `MAX_LINE` in the reference C implementation
/// (`ref/rwhoisd/common/defines.h`).
pub const MAX_LINE: usize = 512;

/// Protocol version advertised in the `%rwhois` banner.
///
/// Mirrors `RWHOIS_PROTOCOL_VERSION` in `ref/rwhoisd/common/conf.h`.
pub const PROTOCOL_VERSION: &str = "1.5";
