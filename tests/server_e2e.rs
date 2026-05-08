//! End-to-end TCP integration tests against a real `Server` instance.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use futures::FutureExt;
use futures::future::BoxFuture;
use rwhois::handler::{QueryHandler, RegisterHandler};
use rwhois::query::Query;
use rwhois::wire::response::{ResponseLine, ResponseWriter, Tag};
use rwhois::{ResponseCode, Server};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::sync::oneshot;

struct EmptyHandler;
impl QueryHandler for EmptyHandler {
    fn handle<'a>(
        &'a self,
        _q: &'a Query,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            out.record_attr("widget", "name", "thing");
            out.record_attr("widget", "id", "42");
            Ok(())
        }
        .boxed()
    }
}

async fn read_until_terminator(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Vec<String> {
    let mut out = Vec::new();
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).await.expect("read");
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_owned();
        let done = trimmed.starts_with("%ok") || trimmed.starts_with("%error");
        out.push(trimmed);
        if done {
            break;
        }
    }
    out
}

#[tokio::test]
async fn end_to_end_banner_status_query_quit() {
    let _ = tracing_subscriber::fmt::try_init();
    let server = Server::builder()
        .hostname("test.invalid")
        .idle_timeout(Duration::from_secs(5))
        .query_handler(EmptyHandler)
        .bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let stream = TcpStream::connect(addr).await.expect("connect");
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);

    // Banner is the first line.
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();
    assert!(banner.starts_with("%rwhois "), "banner: {banner:?}");
    assert!(banner.contains("test.invalid"));

    // -holdconnect on so we can pipeline.
    wr.write_all(b"-holdconnect on\r\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines.last().unwrap(), "%ok");

    // -status produces a %status block followed by %ok.
    wr.write_all(b"-status\r\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert!(lines.iter().any(|l| l.starts_with("%status hold:on")), "{lines:?}");
    assert_eq!(lines.last().unwrap(), "%ok");

    // A query produces our two record lines + %ok.
    wr.write_all(b"some-query\r\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    let parsed: Vec<_> = lines.iter().map(|l| ResponseLine::parse(l)).collect();
    let records: Vec<_> = parsed
        .iter()
        .filter_map(|l| match l {
            ResponseLine::Record(r) => Some(r),
            _ => None,
        })
        .collect();
    assert_eq!(records.len(), 2, "lines: {lines:?}");
    assert_eq!(records[0].class, "widget");
    assert_eq!(records[0].attribute, "name");
    assert_eq!(records[0].value, "thing");
    assert_eq!(lines.last().unwrap(), "%ok");

    // -quit closes the connection after %ok.
    wr.write_all(b"-quit\r\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines.last().unwrap(), "%ok");
    let mut tail = String::new();
    let n = reader.read_line(&mut tail).await.unwrap();
    assert_eq!(n, 0, "expected EOF after -quit, got {tail:?}");
}

#[tokio::test]
async fn end_to_end_unknown_directive_yields_error() {
    let server = Server::builder()
        .hostname("t.invalid")
        .query_handler(EmptyHandler)
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();

    wr.write_all(b"-no-such-thing\r\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    let last = lines.last().unwrap();
    assert!(last.starts_with("%error 400 "), "got: {last:?}");
}

#[tokio::test]
async fn end_to_end_directive_listing() {
    let server = Server::builder()
        .hostname("t.invalid")
        .query_handler(EmptyHandler)
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();

    wr.write_all(b"-holdconnect on\r\n").await.unwrap();
    let _ = read_until_terminator(&mut reader).await;
    wr.write_all(b"-directive\r\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    // Should include at least one Directive: foo entry per built-in.
    let mut count = 0;
    for l in &lines {
        match ResponseLine::parse(l) {
            ResponseLine::Tagged { tag: Tag::Directive, body } if body.starts_with("Directive:") => {
                count += 1;
            }
            _ => {}
        }
    }
    assert!(count >= 8, "expected several Directive: entries; got {count} in {lines:?}");
    assert_eq!(lines.last().unwrap(), "%ok");
}

#[tokio::test]
async fn end_to_end_no_query_handler_fails_query() {
    // Server with no query handler — the directive table still works
    // (so we can test status), but a query yields 501.
    struct Stub;
    impl QueryHandler for Stub {
        fn handle<'a>(
            &'a self,
            _q: &'a Query,
            _out: &'a mut ResponseWriter,
        ) -> BoxFuture<'a, rwhois::Result<()>> {
            async move {
                Err(rwhois::Error::protocol(
                    ResponseCode::NO_OBJECTS_FOUND,
                    "nope",
                ))
            }
            .boxed()
        }
    }

    let server = Server::builder()
        .hostname("t.invalid")
        .query_handler(Stub)
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();

    wr.write_all(b"foo\r\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert!(lines.last().unwrap().starts_with("%error 230 "), "{lines:?}");
}

// -----------------------------------------------------------------------------
// Additional coverage: idle timeout, hold-off auto-close, register flow,
// oversized line handling, graceful shutdown.
// -----------------------------------------------------------------------------

#[tokio::test]
async fn end_to_end_hold_off_closes_after_query() {
    // Default hold_connect=false: the connection must close after the first
    // non-directive query.
    let server = Server::builder()
        .hostname("t.invalid")
        .query_handler(EmptyHandler)
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();

    wr.write_all(b"some-query\r\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert_eq!(lines.last().unwrap(), "%ok");

    // Server should now close the connection.
    let mut tail = String::new();
    let n = reader.read_line(&mut tail).await.unwrap();
    assert_eq!(n, 0, "expected EOF after first query (hold-connect off)");
}

#[tokio::test]
async fn end_to_end_idle_timeout_closes_with_503() {
    let server = Server::builder()
        .hostname("t.invalid")
        .idle_timeout(Duration::from_millis(75))
        .query_handler(EmptyHandler)
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, _wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();

    // Wait without sending; the server should send %error 503 then close.
    let mut got = Vec::new();
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .expect("idle timeout never fired")
            .unwrap();
        if n == 0 {
            break;
        }
        got.push(line.trim_end_matches(['\r', '\n']).to_owned());
    }
    assert!(got.iter().any(|l| l.starts_with("%error 503 ")), "{got:?}");
}

struct CountingRegister {
    began: AtomicUsize,
    spool_lines: AtomicUsize,
    finished: AtomicUsize,
}
impl RegisterHandler for CountingRegister {
    fn begin<'a>(
        &'a self,
        _action: &'a str,
        _email: &'a str,
        _args: &'a str,
    ) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            self.began.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        .boxed()
    }
    fn accept_line<'a>(&'a self, _line: &'a str) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            self.spool_lines.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        .boxed()
    }
    fn finish<'a>(&'a self, out: &'a mut ResponseWriter) -> BoxFuture<'a, rwhois::Result<()>> {
        async move {
            self.finished.fetch_add(1, Ordering::SeqCst);
            out.tagged(Tag::Register, "ID:42");
            Ok(())
        }
        .boxed()
    }
}

#[tokio::test]
async fn end_to_end_register_flow_dispatches_begin_spool_finish() {
    let counter = Arc::new(CountingRegister {
        began: AtomicUsize::new(0),
        spool_lines: AtomicUsize::new(0),
        finished: AtomicUsize::new(0),
    });
    struct Bridge(Arc<CountingRegister>);
    impl RegisterHandler for Bridge {
        fn begin<'a>(
            &'a self,
            a: &'a str,
            e: &'a str,
            x: &'a str,
        ) -> BoxFuture<'a, rwhois::Result<()>> {
            self.0.begin(a, e, x)
        }
        fn accept_line<'a>(&'a self, l: &'a str) -> BoxFuture<'a, rwhois::Result<()>> {
            self.0.accept_line(l)
        }
        fn finish<'a>(&'a self, o: &'a mut ResponseWriter) -> BoxFuture<'a, rwhois::Result<()>> {
            self.0.finish(o)
        }
    }
    let server = Server::builder()
        .hostname("t.invalid")
        .query_handler(EmptyHandler)
        .register_handler(Bridge(Arc::clone(&counter)))
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();

    wr.write_all(b"-holdconnect on\r\n").await.unwrap();
    let _ = read_until_terminator(&mut reader).await;

    wr.write_all(b"-register on add admin@example.com\r\n")
        .await
        .unwrap();
    let _ = read_until_terminator(&mut reader).await;

    // Two spool lines; these produce no client-visible output (Silent).
    wr.write_all(b"network:Name:Acme\r\n").await.unwrap();
    wr.write_all(b"network:Org:Acme Inc\r\n").await.unwrap();

    // -register off should run finish() and emit %register ID:42 then %ok.
    wr.write_all(b"-register off\r\n").await.unwrap();
    let lines = read_until_terminator(&mut reader).await;
    assert!(
        lines.iter().any(|l| l == "%register ID:42"),
        "expected register reply, got {lines:?}"
    );
    assert_eq!(lines.last().unwrap(), "%ok");

    assert_eq!(counter.began.load(Ordering::SeqCst), 1);
    assert_eq!(counter.spool_lines.load(Ordering::SeqCst), 2);
    assert_eq!(counter.finished.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn end_to_end_oversized_line_is_rejected() {
    let server = Server::builder()
        .hostname("t.invalid")
        .max_line(64)
        .query_handler(EmptyHandler)
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());

    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();

    let big = vec![b'x'; 200];
    wr.write_all(&big).await.unwrap();
    wr.write_all(b"\r\n").await.unwrap();

    // The codec returns a LineTooLong error; the connection task ends.
    let mut got = Vec::new();
    loop {
        let mut line = String::new();
        let n = tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut line))
            .await
            .expect("never closed")
            .unwrap();
        if n == 0 {
            break;
        }
        got.push(line);
    }
    // No server response is required for oversized — just clean close.
    // (Server side logs a warn; we just assert it didn't hang.)
    let _ = got;
}

#[tokio::test]
async fn end_to_end_graceful_shutdown_drains_connection() {
    let (tx, rx) = oneshot::channel::<()>();
    let server = Server::builder()
        .hostname("t.invalid")
        .query_handler(EmptyHandler)
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    let join = tokio::spawn(async move {
        server
            .serve_with_shutdown(async move {
                rx.await.ok();
            })
            .await
    });

    // Establish a hold-connect session so the connection persists.
    let stream = TcpStream::connect(addr).await.unwrap();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut banner = String::new();
    reader.read_line(&mut banner).await.unwrap();
    wr.write_all(b"-holdconnect on\r\n").await.unwrap();
    let _ = read_until_terminator(&mut reader).await;

    // Signal shutdown; drop the client to release the connection task.
    tx.send(()).unwrap();
    drop(wr);
    drop(reader);

    // serve_with_shutdown should resolve cleanly within a generous timeout.
    let res = tokio::time::timeout(Duration::from_secs(5), join)
        .await
        .expect("serve did not return after shutdown")
        .expect("task panicked");
    assert!(res.is_ok(), "serve returned {res:?}");
}
