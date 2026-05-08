//! In-memory directory: a more realistic server that stores a handful of
//! records and answers queries against them.
//!
//! Demonstrates:
//!
//! - implementing [`QueryHandler`] over an `Arc<Vec<Record>>`
//! - using the parsed [`rwhois::query::Query`] AST to filter records
//! - implementing [`SoaProvider`] and [`ClassProvider`] so `-soa` / `-class`
//!   return real data rather than `400 Directive Not Available`
//!
//! Run:
//! ```bash
//! cargo run --example in_memory_directory
//! # then: nc 127.0.0.1 4322
//! #   -holdconnect on
//! #   -soa
//! #   -class example.com
//! #   widget=alpha
//! #   id=2
//! #   -quit
//! ```

use std::env;
use std::sync::Arc;

use futures::FutureExt;
use futures::future::BoxFuture;
use rwhois::handler::{ClassProvider, QueryHandler, SoaProvider};
use rwhois::query::{Expr, Query, Term, Value, ValueKind};
use rwhois::wire::response::{ResponseWriter, Tag};
use rwhois::{ResponseCode, Server};

#[derive(Debug, Clone)]
struct Record {
    class: &'static str,
    id: u32,
    name: &'static str,
    email: &'static str,
}

const RECORDS: &[Record] = &[
    Record { class: "widget", id: 1, name: "alpha",   email: "alpha@example.com" },
    Record { class: "widget", id: 2, name: "bravo",   email: "bravo@example.com" },
    Record { class: "widget", id: 3, name: "charlie", email: "charlie@example.com" },
    Record { class: "person", id: 1, name: "alice",   email: "alice@example.com" },
    Record { class: "person", id: 2, name: "bob",     email: "bob@example.com" },
];

struct Directory;

impl Directory {
    fn matches(rec: &Record, expr: &Expr) -> bool {
        match expr {
            Expr::And(l, r) => Self::matches(rec, l) && Self::matches(rec, r),
            Expr::Or(l, r)  => Self::matches(rec, l) || Self::matches(rec, r),
            Expr::Term(t)   => Self::term_matches(rec, t),
        }
    }

    fn term_matches(rec: &Record, t: &Term) -> bool {
        match t {
            Term::AttrEq { attr, value } => Self::attr_eq(rec, attr, value),
            Term::AttrNe { attr, value } => !Self::attr_eq(rec, attr, value),
            Term::Value(v)               => Self::any_attr_match(rec, v),
        }
    }

    fn attr_eq(rec: &Record, attr: &str, value: &Value) -> bool {
        let field = match attr.to_ascii_lowercase().as_str() {
            "class" => rec.class.to_owned(),
            "id"    => rec.id.to_string(),
            "name"  => rec.name.to_owned(),
            "email" => rec.email.to_owned(),
            _       => return false,
        };
        value_match(&field, value)
    }

    fn any_attr_match(rec: &Record, v: &Value) -> bool {
        value_match(rec.name, v)
            || value_match(rec.email, v)
            || value_match(&rec.id.to_string(), v)
    }
}

fn value_match(field: &str, v: &Value) -> bool {
    let f = field.to_ascii_lowercase();
    let needle = v.text.to_ascii_lowercase();
    match v.kind {
        ValueKind::Exact | ValueKind::Quoted => f == needle,
        ValueKind::Prefix    => f.starts_with(&needle),
        ValueKind::Suffix    => f.ends_with(&needle),
        ValueKind::Substring => f.contains(&needle),
    }
}

impl QueryHandler for Directory {
    fn handle<'a>(
        &'a self,
        q: &'a Query,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            let mut found = 0usize;
            for rec in RECORDS {
                if let Some(c) = q.class.as_deref() {
                    if !c.eq_ignore_ascii_case(rec.class) {
                        continue;
                    }
                }
                if Self::matches(rec, &q.expr) {
                    out.record_attr(rec.class, "id",    &rec.id.to_string());
                    out.record_attr(rec.class, "name",  rec.name);
                    out.record_attr(rec.class, "email", rec.email);
                    found += 1;
                }
            }
            if found == 0 {
                return Err(rwhois::Error::protocol(
                    ResponseCode::NO_OBJECTS_FOUND,
                    "no matches",
                ));
            }
            Ok(())
        }
        .boxed()
    }
}

struct StaticSoa;
impl SoaProvider for StaticSoa {
    fn list<'a>(
        &'a self,
        _areas: &'a [String],
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            out.tagged(Tag::Soa, "Authority-Area:example.com");
            out.tagged(Tag::Soa, "Primary-Server:rwhois.example.com:4321");
            out.tagged(Tag::Soa, "Hostmaster:hostmaster@example.com");
            out.tagged(Tag::Soa, "Serial-Number:2026043001");
            Ok(())
        }
        .boxed()
    }
}

struct StaticClasses;
impl ClassProvider for StaticClasses {
    fn list<'a>(
        &'a self,
        _area: &'a str,
        _classes: &'a [String],
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            for class in ["widget", "person"] {
                out.tagged(Tag::Class, &format!("Class-Name:{class}"));
                out.tagged(Tag::Class, "Attribute:id");
                out.tagged(Tag::Class, "Attribute:name");
                out.tagged(Tag::Class, "Attribute:email");
            }
            Ok(())
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

    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:4322".into());

    Server::builder()
        .hostname("rwhois.example.com")
        .query_handler(Directory)
        .soa_provider(StaticSoa)
        .class_provider(StaticClasses)
        .bind(addr)
        .await?
        .serve()
        .await?;

    // Hold a strong reference so RECORDS-style demo closures live for the
    // lifetime of the server (no-op here; included to show the pattern).
    let _keepalive: Arc<()> = Arc::new(());
    Ok(())
}
