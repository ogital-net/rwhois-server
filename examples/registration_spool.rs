//! Registration spool: implements the `-register on … -register off` flow
//! (RFC 2167 §3.3.9).
//!
//! Demonstrates the three-call lifecycle of [`RegisterHandler`]:
//!
//! 1. `begin(action, email, args)` when `-register on …` arrives;
//! 2. `accept_line(line)` for each spooled line;
//! 3. `finish(out)` when `-register off` arrives — which can push a
//!    `%register` block back to the client.
//!
//! Per-connection mutable state lives behind a `Mutex`; in real code you'd
//! want one inner state per session, e.g. by storing a `Slab` keyed off
//! the peer addr or by giving each connection its own handler clone.
//!
//! Run:
//! ```bash
//! cargo run --example registration_spool
//! ```
//!
//! Then:
//! ```text
//! -holdconnect on
//! -register on add user@example.com
//! Person:Jane Doe
//! Email:jane@example.com
//! -register off
//! ```

use std::env;
use std::sync::Mutex;

use futures::FutureExt;
use futures::future::BoxFuture;
use rwhois::Server;
use rwhois::handler::{QueryHandler, RegisterHandler};
use rwhois::query::Query;
use rwhois::wire::response::{ResponseWriter, Tag};

#[derive(Default)]
struct Spool {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    action: String,
    email: String,
    lines: Vec<String>,
    next_id: u64,
}

struct Stub;
impl QueryHandler for Stub {
    fn handle<'a>(
        &'a self,
        _q: &'a Query,
        _out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        async move { Ok(()) }.boxed()
    }
}

impl RegisterHandler for Spool {
    fn begin<'a>(
        &'a self,
        action: &'a str,
        email: &'a str,
        _args: &'a str,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            let mut g = self.inner.lock().unwrap();
            g.action = action.to_owned();
            g.email = email.to_owned();
            g.lines.clear();
            tracing::info!(action, email, "registration started");
            Ok(())
        }
        .boxed()
    }

    fn accept_line<'a>(&'a self, line: &'a str) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            self.inner.lock().unwrap().lines.push(line.to_owned());
            Ok(())
        }
        .boxed()
    }

    fn finish<'a>(&'a self, out: &'a mut ResponseWriter) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            let mut g = self.inner.lock().unwrap();
            g.next_id += 1;
            let id = g.next_id;
            tracing::info!(
                id,
                action = %g.action,
                email = %g.email,
                lines = g.lines.len(),
                "registration committed"
            );
            out.tagged(Tag::Register, &format!("Registration-ID:{id}"));
            out.tagged(Tag::Register, &format!("Action:{}", g.action));
            out.tagged(Tag::Register, &format!("Lines-Received:{}", g.lines.len()));
            out.end_block(Tag::Register);
            Ok(())
        }
        .boxed()
    }
}

#[tokio::main]
async fn main() -> rwhois::Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:4324".into());

    Server::builder()
        .hostname("register.example.com")
        .query_handler(Stub)
        .register_handler(Spool::default())
        .bind(addr)
        .await?
        .serve()
        .await
}
