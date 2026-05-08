# CLAUDE.md

Guidance for Claude / Copilot agents working in this repository.

## Project

`rwhois-server` is a Rust library that implements the **Referral Whois (RWhois)** protocol — RFC 2167 — on top of [tokio](https://tokio.rs).

The library handles **all protocol-level concerns** (framing, banner, directive dispatch, response codes, referral framing, session state, idle timeout, hold-connect semantics) and exposes **traits** so that downstream applications plug in their own data sources for queries, schemas, SOAs, registration, referrals, etc.

This is a **library**, not a binary. Examples live under `examples/`.

## Reference implementation

A vendored copy of the canonical C `rwhoisd` lives at [ref/rwhoisd/](ref/rwhoisd/). Treat it as the wire-format ground truth when behaviour is ambiguous. Highlights worth knowing before touching the wire code:

- TCP, plain-text, line-oriented. Server greets first with `%rwhois V-1.5:00<caps>:00 …`.
- Inbound lines: tolerant of LF or CRLF, max 512 bytes (`MAX_LINE`), trimmed and stripped of control chars.
- Outbound lines: the C reference emits **bare LF**, but RFC 2167 mandates **CRLF** — this library writes **CRLF** and accepts either on read.
- A line beginning with `-` followed by an alphabetic char is a **directive** (e.g. `-rwhois`, `-class`, `-soa`, `-xfer`, `-quit`, `-holdconnect`, `-limit`, `-display`, `-forward`, `-status`, `-directive`, `-register`, `-schema`, `-security`, `-notify`, `-X-*`). Anything else is a query (or a spool line if a `-register on` is in flight).
- Responses: untagged record lines (`<class>:<attr>:<val>`) for query results, tagged lines (`%class …`, `%schema …`, `%soa …`, `%xfer …`, `%directive …`, `%display …`, `%status …`, `%referral …`) for directives. A blank tagged line (`%foo\n`) terminates a block. The whole response is terminated by `%ok` (success) or `%error <code> <text>` (failure).
- Response codes: see [ref/rwhoisd/common/client_msgs.c](ref/rwhoisd/common/client_msgs.c) — mirrored in `src/response/code.rs`.
- Per-connection state: `state` (Query|Spool), `hold_connect`, `hit_limit`, `display` mode, `forward`, `secure_mode`, `client_vendor_id`, in-flight register info.
- `-quit` returns a `Quit` outcome from its handler; the server prints `%ok` and closes.
- If hold-connect is OFF (the default) the server closes the connection after the first non-directive query.
- Idle timeout sends `%error 503 Idle Time Exceeded` and closes.

A more detailed protocol writeup is captured in commit history — when in doubt, grep the C code (`ref/rwhoisd/server/*.c`, `ref/rwhoisd/common/client_msgs.c`).

## Crate layout

```
src/
  lib.rs              re-exports + crate docs
  error.rs            crate Error / Result
  codec.rs            tokio_util::codec::{Encoder,Decoder} for line framing
  wire/
    mod.rs
    request.rs        parsed inbound line: Directive | Query | Spool | Empty
    response.rs       outbound builders (record, tagged block, ok, error, referral)
    code.rs           ResponseCode enum mirroring RFC 2167 / client_msgs.c
  query.rs            parsed query AST + parser (port of mkdb/parse.{l,y})
  directive/
    mod.rs            Directive trait + Registry + dispatch
    builtin.rs        protocol-level built-ins (-rwhois, -quit, -holdconnect,
                      -limit, -display, -forward, -directive, -status)
  handler.rs          consumer-facing traits: QueryHandler, SchemaProvider,
                      SoaProvider, ClassProvider, XferProvider, RegisterHandler,
                      ReferralProvider, AuthHandler
  session.rs          per-connection Session struct (state machine)
  context.rs          ServerContext shared across connections (handlers + cfg)
  server.rs           Server builder + accept loop
examples/
  echo_server.rs      minimal handler that returns no records
```

Modules are stubbed at v0.1 — most types exist but `todo!()` bodies mark
unfinished work. Implement protocol pieces top-down: codec → response →
session loop → directive dispatch → query parser → builtins.

## Design conventions

- **Zero-copy where it matters**: use `bytes::Bytes` / `BytesMut` for inbound
  buffers and `tokio_util::codec::LinesCodec`-style framing. Response writers
  take `&mut BytesMut` and append rather than allocating per line.
- **Async traits**: handler/directive traits return `futures::future::BoxFuture`
  (manually desugared) so they stay object-safe (`Arc<dyn QueryHandler>`,
  `Arc<dyn Directive>`). Implementations use the
  `async move { … }.boxed()` pattern from `futures::FutureExt`. We do **not**
  use the `async-trait` crate.
- **No globals**: every piece of session state lives on `Session`. The C code
  uses file-static globals because it forks per connection — Rust must not.
- **Errors**: `thiserror`-based `Error` enum at the crate root. Protocol-level
  errors map to a `ResponseCode`; transport errors bubble up and end the task.
- **Tracing**: instrument the per-connection task with `tracing::info_span!`
  (peer addr, session id). No `println!`/`eprintln!` in library code.
- **CRLF on the wire**: encoder emits `\r\n`. Decoder splits on either `\n`
  (after stripping a trailing `\r`).
- **Max line length**: 512 bytes per RFC interop; surface as a const and a
  builder knob on `Server`.
- **Directive registration**: builtins are registered by default; consumers
  can `.register_directive(name, impl)` to add `-X-foo` extensions or override
  defaults.

## Working in this repo

- `cargo check` / `cargo test` should always be clean before declaring a task
  done.
- Run `cargo clippy --all-targets -- -W clippy::pedantic` after each change.
  Treat its output as advisory, not gospel — pedantic lints flag plenty of
  stylistic noise (and occasionally bad advice). Fix what's a real
  improvement, justify or `#[allow(...)]` the rest with a brief reason.
- Don't edit `ref/rwhoisd/**` — it's the reference, treat as read-only.
- Keep public API additions minimal and documented; this is `0.x`, breaking
  changes are fine but should be intentional.
- When porting C behaviour, cite the C source file:line in the Rust doc
  comment so future agents can verify.

## What is intentionally NOT in this library

- Storage / indexing (the `mkdb/` and most of `common/` in the C ref).
- Schema / auth-area data model — exposed only as traits.
- Registration spool persistence — surfaced as a trait callback.
- IP-based access control / `dir_security` — implement in the consumer.
- Full slave/transfer client (`server/s*.c`) — out of scope for v1.
