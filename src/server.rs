//! Top-level [`Server`] type and builder.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::BytesMut;
use futures::{SinkExt, StreamExt};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::Semaphore;
use tokio_util::codec::Framed;
use tracing::{Instrument, debug, error, info, info_span, warn};

use crate::codec::RwhoisCodec;
use crate::context::ServerContext;
use crate::directive::{DirectiveOutcome, Registry};
use crate::handler::{
    AuthHandler, ClassProvider, QueryHandler, ReferralProvider, RegisterHandler, SchemaProvider,
    SoaProvider, XferProvider,
};
use crate::query::Query;
use crate::session::{Session, SessionState};
use crate::wire::code::ResponseCode;
use crate::wire::request::Request;
use crate::wire::response::{ResponseWriter, write_error, write_ok};
use crate::{Error, MAX_LINE, Result};

/// Default connection cap when the consumer doesn't specify one.
///
/// Matches a sensible "small server" default; raise it via
/// [`ServerBuilder::max_connections`].
pub const DEFAULT_MAX_CONNECTIONS: usize = 128;

/// Builder for [`Server`].
pub struct ServerBuilder {
    directives: Registry,
    query: Option<Arc<dyn QueryHandler>>,
    class: Option<Arc<dyn ClassProvider>>,
    schema: Option<Arc<dyn SchemaProvider>>,
    soa: Option<Arc<dyn SoaProvider>>,
    xfer: Option<Arc<dyn XferProvider>>,
    register: Option<Arc<dyn RegisterHandler>>,
    referral: Option<Arc<dyn ReferralProvider>>,
    auth: Option<Arc<dyn AuthHandler>>,
    idle_timeout: Duration,
    max_line: usize,
    max_connections: usize,
    hostname: String,
}

impl std::fmt::Debug for ServerBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerBuilder")
            .field("directives", &self.directives)
            .field("idle_timeout", &self.idle_timeout)
            .field("max_line", &self.max_line)
            .field("max_connections", &self.max_connections)
            .field("hostname", &self.hostname)
            .finish_non_exhaustive()
    }
}

impl ServerBuilder {
    /// Builder pre-populated with the protocol-level built-ins.
    #[must_use]
    pub fn new() -> Self {
        Self {
            directives: Registry::with_builtins(),
            query: None,
            class: None,
            schema: None,
            soa: None,
            xfer: None,
            register: None,
            referral: None,
            auth: None,
            idle_timeout: Duration::from_secs(120),
            max_line: MAX_LINE,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            hostname: "localhost".to_owned(),
        }
    }

    /// Hostname advertised in the banner.
    #[must_use]
    pub fn hostname(mut self, h: impl Into<String>) -> Self {
        self.hostname = h.into();
        self
    }

    /// Override the per-line idle timeout (default 120s).
    #[must_use]
    pub fn idle_timeout(mut self, d: Duration) -> Self {
        self.idle_timeout = d;
        self
    }

    /// Override the maximum line length (default 512 bytes).
    #[must_use]
    pub fn max_line(mut self, n: usize) -> Self {
        self.max_line = n;
        self
    }

    /// Cap the number of in-flight connections the accept loop will run
    /// concurrently. New TCP connections beyond the cap are accepted and
    /// then immediately closed (after a `503` is written) until capacity
    /// frees up.
    ///
    /// Defaults to [`DEFAULT_MAX_CONNECTIONS`]. Setting `n = 0` disables
    /// the cap (unbounded).
    #[must_use]
    pub fn max_connections(mut self, n: usize) -> Self {
        self.max_connections = n;
        self
    }

    /// Replace the directive registry wholesale.
    #[must_use]
    pub fn directives(mut self, r: Registry) -> Self {
        self.directives = r;
        self
    }

    /// Register an additional directive (or override a built-in).
    #[must_use]
    pub fn register_directive<D: crate::directive::Directive>(mut self, d: D) -> Self {
        self.directives.register(d);
        self
    }

    /// Required: the query handler.
    #[must_use]
    pub fn query_handler<H: QueryHandler>(mut self, h: H) -> Self {
        self.query = Some(Arc::new(h));
        self
    }

    /// Optional: class metadata provider.
    #[must_use]
    pub fn class_provider<P: ClassProvider>(mut self, p: P) -> Self {
        self.class = Some(Arc::new(p));
        self
    }

    /// Optional: schema metadata provider.
    #[must_use]
    pub fn schema_provider<P: SchemaProvider>(mut self, p: P) -> Self {
        self.schema = Some(Arc::new(p));
        self
    }

    /// Optional: SOA provider.
    #[must_use]
    pub fn soa_provider<P: SoaProvider>(mut self, p: P) -> Self {
        self.soa = Some(Arc::new(p));
        self
    }

    /// Optional: bulk-xfer provider.
    #[must_use]
    pub fn xfer_provider<P: XferProvider>(mut self, p: P) -> Self {
        self.xfer = Some(Arc::new(p));
        self
    }

    /// Optional: registration handler.
    #[must_use]
    pub fn register_handler<H: RegisterHandler>(mut self, h: H) -> Self {
        self.register = Some(Arc::new(h));
        self
    }

    /// Optional: referral provider.
    #[must_use]
    pub fn referral_provider<P: ReferralProvider>(mut self, p: P) -> Self {
        self.referral = Some(Arc::new(p));
        self
    }

    /// Optional: authentication handler.
    #[must_use]
    pub fn auth_handler<H: AuthHandler>(mut self, h: H) -> Self {
        self.auth = Some(Arc::new(h));
        self
    }

    /// Bind to the given address. Returns a [`Server`] ready to `serve()`.
    ///
    /// # Errors
    /// Returns an [`Error::Io`] if the underlying TCP bind fails.
    pub async fn bind<A: ToSocketAddrs>(self, addr: A) -> Result<Server> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        info!(?local, "rwhois server listening");
        let max_conn = self.max_connections;
        let conn_limit = if max_conn == 0 {
            None
        } else {
            Some(Arc::new(Semaphore::new(max_conn)))
        };
        Ok(Server {
            listener,
            ctx: Arc::new(self.into_context()),
            conn_limit,
        })
    }

    /// Consume the builder into a standalone [`ServerContext`] (useful for
    /// tests that want to drive `dispatch` without a real socket).
    #[must_use]
    pub fn into_context(self) -> ServerContext {
        ServerContext {
            directives: self.directives,
            hostname: self.hostname,
            idle_timeout: self.idle_timeout,
            max_line: self.max_line,
            query: self.query,
            class: self.class,
            schema: self.schema,
            soa: self.soa,
            xfer: self.xfer,
            register: self.register,
            referral: self.referral,
            auth: self.auth,
        }
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// A bound listener ready to serve `RWhois` connections.
pub struct Server {
    listener: TcpListener,
    ctx: Arc<ServerContext>,
    conn_limit: Option<Arc<Semaphore>>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("ctx", &self.ctx)
            .field("conn_limit", &self.conn_limit.is_some())
            .finish_non_exhaustive()
    }
}

impl Server {
    /// Construct a [`ServerBuilder`].
    #[must_use]
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Local socket address the listener is bound to.
    ///
    /// # Errors
    /// Returns an [`Error::Io`] if the underlying socket query fails.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.listener.local_addr()?)
    }

    /// Shared, immutable context — exposed for advanced consumers.
    #[must_use]
    pub fn context(&self) -> Arc<ServerContext> {
        Arc::clone(&self.ctx)
    }

    /// Run the accept loop forever.
    ///
    /// # Errors
    /// Returns an [`Error::Io`] if the listener's `accept()` fails fatally.
    /// Per-connection errors are logged but do not abort the accept loop.
    pub async fn serve(self) -> Result<()> {
        self.serve_with_shutdown(std::future::pending::<()>()).await
    }

    /// Run the accept loop until `shutdown` resolves.
    ///
    /// On shutdown:
    /// 1. The listener stops accepting new connections.
    /// 2. In-flight connection tasks are awaited before returning, so the
    ///    caller can safely drop any application state once `serve_with_shutdown`
    ///    completes.
    ///
    /// # Errors
    /// Returns an [`Error::Io`] if the listener's `accept()` fails fatally
    /// before `shutdown` resolves.
    pub async fn serve_with_shutdown<S>(self, shutdown: S) -> Result<()>
    where
        S: std::future::Future<Output = ()> + Send,
    {
        let Server {
            listener,
            ctx,
            conn_limit,
        } = self;
        // Track in-flight tasks so we can drain on shutdown.
        let drain = Arc::new(Semaphore::new(0));
        let mut spawned: u32 = 0;

        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (stream, peer) = match accept {
                        Ok(v) => v,
                        Err(e) => {
                            error!(error = %e, "accept failed");
                            return Err(e.into());
                        }
                    };
                    let permit = if let Some(sem) = conn_limit.as_ref() {
                        if let Ok(p) = Arc::clone(sem).try_acquire_owned() {
                            Some(p)
                        } else {
                            debug!(%peer, "rejecting: connection cap reached");
                            tokio::spawn(async move {
                                let mut buf = BytesMut::new();
                                write_error(
                                    &mut buf,
                                    ResponseCode::SERVICE_NOT_AVAILABLE,
                                    Some("server at capacity"),
                                );
                                let mut s = stream;
                                let _ = s.write_all(&buf).await;
                                let _ = s.shutdown().await;
                            });
                            continue;
                        }
                    } else {
                        None
                    };
                    let ctx = Arc::clone(&ctx);
                    let drain_handle = Arc::clone(&drain);
                    let span = info_span!("rwhois", %peer);
                    spawned = spawned.saturating_add(1);
                    tokio::spawn(async move {
                        let _permit = permit; // hold for connection lifetime
                        match run_connection(stream, peer, ctx).await {
                            Ok(()) => debug!("connection closed"),
                            Err(Error::IdleTimeout) => debug!("connection idle-timeout"),
                            Err(e) => warn!(error = %e, "connection ended with error"),
                        }
                        drain_handle.add_permits(1);
                    }.instrument(span));
                }
                () = &mut shutdown => {
                    info!(spawned, "shutdown signalled, draining connections");
                    break;
                }
            }
        }
        if spawned > 0 {
            let _ = drain.acquire_many(spawned).await;
        }
        info!("server shut down cleanly");
        Ok(())
    }
}

async fn run_connection(
    stream: TcpStream,
    peer: SocketAddr,
    ctx: Arc<ServerContext>,
) -> Result<()> {
    let codec = RwhoisCodec::with_max_line(ctx.max_line);
    let mut framed = Framed::new(stream, codec);
    let mut session = Session::new(peer);
    session.idle_timeout = ctx.idle_timeout;

    // Banner (RFC 2167 §3.1.9).
    framed.send(ctx.banner().to_line()).await?;

    loop {
        let line = match tokio::time::timeout(session.idle_timeout, framed.next()).await {
            Ok(Some(Ok(line))) => line,
            Ok(Some(Err(e))) => return Err(e),
            Ok(None) => return Ok(()), // EOF
            Err(_) => {
                let mut buf = BytesMut::new();
                write_error(&mut buf, ResponseCode::IDLE_TIME_EXCEEDED, None);
                let _ = framed.get_mut().write_all(&buf).await;
                return Err(Error::IdleTimeout);
            }
        };

        let req = Request::classify(&line, session.is_spooling());
        let req_was_query = matches!(req, Request::Query(_));
        let mut out = ResponseWriter::new();
        let outcome = dispatch(&ctx, &mut session, req, &mut out).await;

        let mut buf = out.take();
        match outcome {
            Ok(Outcome::Silent | Outcome::Handled) => {}
            Ok(Outcome::Ok) => write_ok(&mut buf),
            Ok(Outcome::Quit) => {
                write_ok(&mut buf);
                send_buf(&mut framed, buf).await?;
                return Ok(());
            }
            Err(Error::Protocol { code, message }) => {
                write_error(&mut buf, code, Some(&message));
            }
            Err(e) => {
                error!(error = %e, "handler error");
                write_error(&mut buf, ResponseCode::UNIDENTIFIED_ERROR, None);
            }
        }
        send_buf(&mut framed, buf).await?;

        // Close after a non-directive query unless hold-connect is on.
        if !session.hold_connect && session.state == SessionState::Query && req_was_query {
            return Ok(());
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Outcome {
    Silent,
    Ok,
    Handled,
    Quit,
}

async fn dispatch(
    ctx: &ServerContext,
    session: &mut Session,
    req: Request,
    out: &mut ResponseWriter,
) -> Result<Outcome> {
    match req {
        Request::Empty => Ok(Outcome::Silent),
        Request::Directive { name, args } => {
            let Some(d) = ctx.directives.get(&name) else {
                return Err(Error::protocol(ResponseCode::DIRECTIVE_NOT_AVAILABLE, name));
            };
            let outcome = d.run(ctx, session, &args, out).await?;
            Ok(match outcome {
                DirectiveOutcome::Ok => Outcome::Ok,
                DirectiveOutcome::Handled => Outcome::Handled,
                DirectiveOutcome::Quit => Outcome::Quit,
            })
        }
        Request::Query(line) => {
            let Some(handler) = ctx.query.as_ref() else {
                return Err(Error::protocol(
                    ResponseCode::SERVICE_NOT_AVAILABLE,
                    "no query handler",
                ));
            };
            let q = Query::parse(&line)?;
            handler.handle(&q, out).await?;
            if let Some(refs) = ctx.referral.as_ref() {
                refs.referrals(&q, out).await?;
            }
            Ok(Outcome::Ok)
        }
        Request::Spool(line) => {
            if let Some(reg) = ctx.register.as_ref() {
                reg.accept_line(&line).await?;
                Ok(Outcome::Silent)
            } else {
                Err(Error::protocol(
                    ResponseCode::REGISTRATION_NOT_AUTHORIZED,
                    "registration not supported",
                ))
            }
        }
    }
}

async fn send_buf(framed: &mut Framed<TcpStream, RwhoisCodec>, buf: BytesMut) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    framed.get_mut().write_all(&buf).await?;
    Ok(())
}
