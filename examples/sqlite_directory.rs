//! SQLite-backed directory: a more realistic example showing how to plug a
//! synchronous external data store (here, `rusqlite`) into the async server.
//!
//! Demonstrates:
//!
//! - holding a connection pool (here a single `Arc<Mutex<Connection>>` for
//!   brevity — swap in `r2d2` / `deadpool-sqlite` for production) on the
//!   handler struct,
//! - bridging blocking DB calls into async land with
//!   [`tokio::task::spawn_blocking`],
//! - translating the parsed [`rwhois::query::Query`] into bind parameters,
//! - implementing both [`QueryHandler`] and [`SoaProvider`] against the same
//!   backing store.
//!
//! Run:
//! ```bash
//! cargo run --example sqlite_directory
//! # then: nc 127.0.0.1 4325
//! #   -holdconnect on
//! #   -soa
//! #   alpha                       # bare term, searches name/email/id
//! #   name=bravo                  # attribute equality
//! #   email=*@example.com         # suffix wildcard
//! #   widget alpha                # class-restricted bare term
//! ```

use std::env;
use std::sync::{Arc, Mutex};

use futures::FutureExt;
use futures::future::BoxFuture;
use rusqlite::{Connection, params};
use rwhois::Server;
use rwhois::handler::{QueryHandler, SoaProvider};
use rwhois::query::{Expr, Query, Term, Value, ValueKind};
use rwhois::wire::response::{ResponseWriter, Tag};
use rwhois::{Error, ResponseCode};

#[derive(Clone)]
struct Db {
    conn: Arc<Mutex<Connection>>,
}

impl Db {
    fn new_in_memory() -> rusqlite::Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            r"
            CREATE TABLE record (
                class TEXT NOT NULL,
                id    INTEGER NOT NULL,
                name  TEXT NOT NULL,
                email TEXT NOT NULL,
                PRIMARY KEY (class, id)
            );
            INSERT INTO record VALUES
                ('widget', 1, 'alpha',   'alpha@example.com'),
                ('widget', 2, 'bravo',   'bravo@example.com'),
                ('widget', 3, 'charlie', 'charlie@example.com'),
                ('person', 1, 'alice',   'alice@example.com'),
                ('person', 2, 'bob',     'bob@example.com');
            ",
        )?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }
}

/// Translate the parsed query AST into a SQL `WHERE` fragment + bind values.
///
/// Only the subset needed for the demo is supported:
///
/// - `attr=value`        → `LOWER(attr) = LOWER(?)`
/// - `attr=val*`/`*val`/`*val*` → `LOWER(attr) LIKE LOWER(?)`
/// - bare `value`        → matches any of `name`, `email`, `id`
/// - `AND` / `OR`        → SQL boolean operators with parentheses
///
/// `attr!=…` is rejected with `350 Invalid Query Syntax` so the handler
/// returns a clear error rather than silently dropping the negation.
fn lower_to_sql(expr: &Expr, sql: &mut String, binds: &mut Vec<String>) -> rwhois::Result<()> {
    match expr {
        Expr::And(l, r) => {
            sql.push('(');
            lower_to_sql(l, sql, binds)?;
            sql.push_str(" AND ");
            lower_to_sql(r, sql, binds)?;
            sql.push(')');
        }
        Expr::Or(l, r) => {
            sql.push('(');
            lower_to_sql(l, sql, binds)?;
            sql.push_str(" OR ");
            lower_to_sql(r, sql, binds)?;
            sql.push(')');
        }
        Expr::Term(Term::AttrEq { attr, value }) => {
            push_attr_match(attr, value, sql, binds)?;
        }
        Expr::Term(Term::AttrNe { .. }) => {
            return Err(Error::protocol(
                ResponseCode::INVALID_QUERY_SYNTAX,
                "!= not supported",
            ));
        }
        Expr::Term(Term::Value(v)) => {
            sql.push('(');
            push_attr_match("name", v, sql, binds)?;
            sql.push_str(" OR ");
            push_attr_match("email", v, sql, binds)?;
            sql.push_str(" OR ");
            push_attr_match("id", v, sql, binds)?;
            sql.push(')');
        }
    }
    Ok(())
}

fn push_attr_match(
    attr: &str,
    v: &Value,
    sql: &mut String,
    binds: &mut Vec<String>,
) -> rwhois::Result<()> {
    let column = match attr.to_ascii_lowercase().as_str() {
        // Allow-list to avoid SQL injection via attribute names.
        "id" | "name" | "email" | "class" => attr.to_ascii_lowercase(),
        other => {
            return Err(Error::protocol(
                ResponseCode::INVALID_ATTRIBUTE,
                format!("unknown attribute: {other}"),
            ));
        }
    };
    let needle = v.text.to_ascii_lowercase();
    match v.kind {
        ValueKind::Exact | ValueKind::Quoted => {
            sql.push_str(&format!("LOWER({column}) = ?"));
            binds.push(needle);
        }
        ValueKind::Prefix => {
            sql.push_str(&format!("LOWER({column}) LIKE ?"));
            binds.push(format!("{needle}%"));
        }
        ValueKind::Suffix => {
            sql.push_str(&format!("LOWER({column}) LIKE ?"));
            binds.push(format!("%{needle}"));
        }
        ValueKind::Substring => {
            sql.push_str(&format!("LOWER({column}) LIKE ?"));
            binds.push(format!("%{needle}%"));
        }
    }
    Ok(())
}

struct SqliteDirectory {
    db: Db,
}

impl QueryHandler for SqliteDirectory {
    fn handle<'a>(
        &'a self,
        q: &'a Query,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        let db = self.db.clone();
        // Build SQL on the async side so we can return protocol errors
        // without blocking.
        let mut where_sql = String::new();
        let mut binds: Vec<String> = Vec::new();
        if let Err(e) = lower_to_sql(&q.expr, &mut where_sql, &mut binds) {
            return async move { Err(e) }.boxed();
        }
        let class_filter = q.class.clone();

        async move {
            let rows = tokio::task::spawn_blocking(move || -> rusqlite::Result<Vec<(String, i64, String, String)>> {
                let mut sql = String::from("SELECT class, id, name, email FROM record WHERE ");
                sql.push_str(&where_sql);
                if class_filter.is_some() {
                    sql.push_str(" AND LOWER(class) = LOWER(?)");
                }
                sql.push_str(" ORDER BY class, id");

                let conn = db.conn.lock().unwrap();
                let mut stmt = conn.prepare(&sql)?;
                let mut params_dyn: Vec<&dyn rusqlite::ToSql> =
                    binds.iter().map(|s| s as &dyn rusqlite::ToSql).collect();
                if let Some(c) = class_filter.as_ref() {
                    params_dyn.push(c as &dyn rusqlite::ToSql);
                }
                let rows = stmt
                    .query_map(rusqlite::params_from_iter(params_dyn.iter()), |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, String>(2)?,
                            row.get::<_, String>(3)?,
                        ))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(rows)
            })
            .await
            .map_err(|e| Error::handler(Box::new(e)))?
            .map_err(|e| Error::handler(Box::new(e)))?;

            if rows.is_empty() {
                return Err(Error::protocol(
                    ResponseCode::NO_OBJECTS_FOUND,
                    "no matches",
                ));
            }
            for (class, id, name, email) in rows {
                out.record_attr(&class, "id", &id.to_string());
                out.record_attr(&class, "name", &name);
                out.record_attr(&class, "email", &email);
            }
            Ok(())
        }
        .boxed()
    }
}

struct SqliteSoa {
    db: Db,
}

impl SoaProvider for SqliteSoa {
    fn list<'a>(
        &'a self,
        _areas: &'a [String],
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        let db = self.db.clone();
        async move {
            let count = tokio::task::spawn_blocking(move || -> rusqlite::Result<i64> {
                let conn = db.conn.lock().unwrap();
                conn.query_row("SELECT COUNT(*) FROM record", params![], |r| r.get(0))
            })
            .await
            .map_err(|e| Error::handler(Box::new(e)))?
            .map_err(|e| Error::handler(Box::new(e)))?;

            out.tagged(Tag::Soa, "Authority-Area:example.com");
            out.tagged(Tag::Soa, "Primary-Server:rwhois.example.com:4321");
            out.tagged(Tag::Soa, &format!("Records:{count}"));
            Ok(())
        }
        .boxed()
    }
}

#[tokio::main]
async fn main() -> rwhois::Result<()> {
    tracing_subscriber::fmt::try_init().ok();
    let addr = env::args().nth(1).unwrap_or_else(|| "127.0.0.1:4325".into());

    let db = Db::new_in_memory().expect("init sqlite");

    Server::builder()
        .hostname("rwhois.example.com")
        .query_handler(SqliteDirectory { db: db.clone() })
        .soa_provider(SqliteSoa { db })
        .bind(addr)
        .await?
        .serve()
        .await
}
