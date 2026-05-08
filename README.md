# rwhois-server

[![crates.io](https://img.shields.io/crates/v/rwhois-server.svg)](https://crates.io/crates/rwhois-server)
[![docs.rs](https://docs.rs/rwhois-server/badge.svg)](https://docs.rs/rwhois-server)

Async, [tokio](https://tokio.rs)-based server library for the
**Referral Whois (RWhois) protocol**, [RFC 2167](https://datatracker.ietf.org/doc/html/rfc2167).

The crate handles all wire-protocol concerns — line framing, the `%rwhois`
banner, response codes, directive dispatch, session state, idle timeouts,
hold-connect semantics, and registration spool framing — and exposes a small
set of `async` traits so consumers can plug in their own data sources for
queries, schema, SOA, registration, referrals and authentication.

This is a **library**. Examples live under `examples/`.

```toml
[dependencies]
rwhois-server = "0.1"
tokio         = { version = "1", features = ["rt-multi-thread", "macros"] }
futures       = "0.3"
```

## Quick start

```rust,no_run
use futures::FutureExt;
use futures::future::BoxFuture;
use rwhois::handler::QueryHandler;
use rwhois::query::Query;
use rwhois::wire::response::ResponseWriter;
use rwhois::{Result, Server};

struct Echo;
impl QueryHandler for Echo {
    fn handle<'a>(
        &'a self,
        q: &'a Query,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<()>> {
        async move {
            out.record_attr("echo", "query", &q.raw);
            Ok(())
        }
        .boxed()
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let server = Server::builder()
        .hostname("rwhois.example.com")
        .query_handler(Echo)
        .bind("127.0.0.1:4321")
        .await?;
    server.serve().await
}
```

See [`examples/`](./examples) for richer demos: an in-memory directory,
referral-only server, registration spool, and a sqlite-backed directory.

## What this crate provides

* `wire::{Banner, ResponseLine, ResponseWriter, Tag, ResponseCode, …}` — the
  full RFC 2167 wire layer for both encoding and decoding.
* `codec::RwhoisCodec` — a `tokio_util::codec` line splitter/joiner that
  accepts both LF and CRLF on input and writes CRLF on output.
* `query::Query` — parsed query AST, ported from the reference C parser.
* `directive::{Directive, Registry}` and a default `builtin` set covering
  every protocol-level directive (`-quit`, `-rwhois`, `-holdconnect`,
  `-limit`, `-forward`, `-display`, `-status`, `-directive`, `-class`,
  `-schema`, `-soa`, `-xfer`, `-register`, `-security`, `-notify`).
* `handler::*` traits for query, class, schema, SOA, xfer, registration,
  referral and auth — all object-safe (`Arc<dyn …>`).
* `Server` / `ServerBuilder` for binding and running an accept loop, with
  optional graceful shutdown and a connection cap.

## What this crate does NOT provide

* Storage or indexing (the C reference's `mkdb/`).
* A schema or auth-area data model.
* Registration spool persistence.
* IP-based access control.
* Slave/transfer client logic.

These are intentionally left to the consumer; the crate exposes traits and
gets out of your way.

## License

Dual-licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.
