//! Referral-only server: holds no local data; every query is answered with a
//! `%referral` URL pointing at a downstream rwhois server.
//!
//! Demonstrates implementing [`ReferralProvider`] alongside a degenerate
//! [`QueryHandler`] that simply yields no records (referrals are appended
//! after the query handler runs).
//!
//! Run:
//! ```bash
//! cargo run --example referral_only
//! # then: nc 127.0.0.1 4323
//! #   foo.example.net
//! ```

use std::env;

use futures::FutureExt;
use futures::future::BoxFuture;
use rwhois::Server;
use rwhois::handler::{QueryHandler, ReferralProvider};
use rwhois::query::Query;
use rwhois::wire::response::ResponseWriter;

struct Empty;
impl QueryHandler for Empty {
    fn handle<'a>(
        &'a self,
        _q: &'a Query,
        _out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        async move { Ok(()) }.boxed()
    }
}

struct PunntoUpstream {
    host: String,
    port: u16,
    auth_area: String,
}

impl ReferralProvider for PunntoUpstream {
    fn referrals<'a>(
        &'a self,
        _q: &'a Query,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            out.referral(&self.host, self.port, &self.auth_area);
            Ok(())
        }
        .boxed()
    }
}

#[tokio::main]
async fn main() -> rwhois::Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:4323".into());

    Server::builder()
        .hostname("referral.example.com")
        .query_handler(Empty)
        .referral_provider(PunntoUpstream {
            host: "rwhois.arin.net".into(),
            port: 4321,
            auth_area: "arin.net".into(),
        })
        .bind(addr)
        .await?
        .serve()
        .await
}
