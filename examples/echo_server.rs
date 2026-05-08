//! Minimal example: an rwhois server that accepts queries but always returns
//! "no objects found" via the `230` response code.
//!
//! Run with:
//! ```bash
//! cargo run --example echo_server -- 127.0.0.1:4321
//! ```
//! Then `nc 127.0.0.1 4321` and try `-status`, `-holdconnect on`, `foo`, `-quit`.

use std::env;

use futures::FutureExt;
use futures::future::BoxFuture;
use rwhois::handler::QueryHandler;
use rwhois::query::Query;
use rwhois::wire::response::ResponseWriter;
use rwhois::{ResponseCode, Server};

struct AlwaysEmpty;

impl QueryHandler for AlwaysEmpty {
    fn handle<'a>(
        &'a self,
        _q: &'a Query,
        _out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            Err(rwhois::Error::protocol(
                ResponseCode::NO_OBJECTS_FOUND,
                "no records",
            ))
        }
        .boxed()
    }
}

#[tokio::main]
async fn main() -> rwhois::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:4321".into());
    Server::builder()
        .hostname("example.invalid")
        .query_handler(AlwaysEmpty)
        .bind(addr)
        .await?
        .serve()
        .await
}
