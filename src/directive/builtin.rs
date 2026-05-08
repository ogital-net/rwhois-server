//! Protocol-level built-in directives.
//!
//! These implement the directives defined directly by RFC 2167 — `-quit`,
//! `-rwhois`, `-holdconnect`, `-limit`, `-forward`, `-display`, `-status`,
//! `-directive`, `-class`, `-schema`, `-soa`, `-xfer`, `-register`,
//! `-security` and `-notify`. The provider-backed ones (`-class`, `-schema`,
//! `-soa`, `-xfer`, `-security`) delegate to the trait objects on
//! [`ServerContext`] and respond with `400 Directive Not Available` if the
//! consumer has not registered the corresponding handler.

use futures::FutureExt;
use futures::future::BoxFuture;

use super::{Capability, Directive, DirectiveOutcome, Registry};
use crate::context::ServerContext;
use crate::session::{Session, SessionState};
use crate::wire::code::ResponseCode;
use crate::wire::response::{ResponseWriter, Tag};
use crate::{Error, Result};

/// `CAP_HOLD` — `ref/rwhoisd/common/directive_conf.h`.
const CAP_HOLD: u32 = 0x0000_0001;
/// `CAP_LIMIT`.
const CAP_LIMIT: u32 = 0x0000_0002;
/// `CAP_FORWARD`.
const CAP_FORWARD: u32 = 0x0000_0004;
/// `CAP_DISPLAY`.
const CAP_DISPLAY: u32 = 0x0000_0008;
/// `CAP_INFO_OFF` (status info-on/info-off framing).
const CAP_STATUS: u32 = 0x0000_0010;

/// Register every built-in directive into `r`.
pub fn register_all(r: &mut Registry) {
    r.register(Quit);
    r.register(HoldConnect);
    r.register(Limit);
    r.register(Forward);
    r.register(Display);
    r.register(Status);
    r.register(Rwhois);
    r.register(DirectiveList);
    r.register(Class);
    r.register(Schema);
    r.register(Soa);
    r.register(Xfer);
    r.register(Register);
    r.register(Security);
    r.register(Notify);
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

fn split_args(args: &str) -> Vec<&str> {
    args.split_whitespace().collect()
}

fn ok<'a>(o: DirectiveOutcome) -> BoxFuture<'a, Result<DirectiveOutcome>> {
    async move { Ok(o) }.boxed()
}

fn err<'a>(code: ResponseCode, msg: impl Into<String>) -> BoxFuture<'a, Result<DirectiveOutcome>> {
    let m = msg.into();
    async move { Err(Error::protocol(code, m)) }.boxed()
}

// -----------------------------------------------------------------------------
// -quit
// -----------------------------------------------------------------------------

/// `-quit` — terminate the connection (RFC 2167 §3.3.6).
#[derive(Debug, Default)]
pub struct Quit;
impl Directive for Quit {
    fn name(&self) -> &'static str { "quit" }
    fn description(&self) -> &'static str { "close the session" }
    fn run<'a>(
        &'a self,
        _ctx: &'a ServerContext,
        _s: &'a mut Session,
        _args: &'a str,
        _out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        ok(DirectiveOutcome::Quit)
    }
}

// -----------------------------------------------------------------------------
// -holdconnect
// -----------------------------------------------------------------------------

/// `-holdconnect on|off` (RFC 2167 §3.3.5).
#[derive(Debug, Default)]
pub struct HoldConnect;
impl Directive for HoldConnect {
    fn name(&self) -> &'static str { "holdconnect" }
    fn capability(&self) -> Capability { Capability(CAP_HOLD) }
    fn description(&self) -> &'static str { "hold the connection open across queries" }
    fn run<'a>(
        &'a self,
        _ctx: &'a ServerContext,
        s: &'a mut Session,
        args: &'a str,
        _out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        match args.trim().to_ascii_lowercase().as_str() {
            "" | "on" => { s.hold_connect = true; ok(DirectiveOutcome::Ok) }
            "off"    => { s.hold_connect = false; ok(DirectiveOutcome::Ok) }
            other    => err(ResponseCode::INVALID_DIRECTIVE_SYNTAX, format!("holdconnect: {other}")),
        }
    }
}

// -----------------------------------------------------------------------------
// -limit
// -----------------------------------------------------------------------------

/// `-limit N` — cap rows returned per query (RFC 2167 §3.3.7).
#[derive(Debug, Default)]
pub struct Limit;
impl Directive for Limit {
    fn name(&self) -> &'static str { "limit" }
    fn capability(&self) -> Capability { Capability(CAP_LIMIT) }
    fn description(&self) -> &'static str { "cap the number of records returned per query" }
    fn run<'a>(
        &'a self,
        _ctx: &'a ServerContext,
        s: &'a mut Session,
        args: &'a str,
        _out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        match args.trim().parse::<usize>() {
            Ok(n) => { s.hit_limit = n; ok(DirectiveOutcome::Ok) }
            Err(_) => err(ResponseCode::INVALID_DIRECTIVE_SYNTAX, format!("limit: {args}")),
        }
    }
}

// -----------------------------------------------------------------------------
// -forward
// -----------------------------------------------------------------------------

/// `-forward on|off` (RFC 2167 §3.3.4).
#[derive(Debug, Default)]
pub struct Forward;
impl Directive for Forward {
    fn name(&self) -> &'static str { "forward" }
    fn capability(&self) -> Capability { Capability(CAP_FORWARD) }
    fn description(&self) -> &'static str { "follow referrals on behalf of the client" }
    fn run<'a>(
        &'a self,
        _ctx: &'a ServerContext,
        s: &'a mut Session,
        args: &'a str,
        _out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        match args.trim().to_ascii_lowercase().as_str() {
            "" | "on" => { s.forward = true; ok(DirectiveOutcome::Ok) }
            "off"    => { s.forward = false; ok(DirectiveOutcome::Ok) }
            other    => err(ResponseCode::INVALID_DIRECTIVE_SYNTAX, format!("forward: {other}")),
        }
    }
}

// -----------------------------------------------------------------------------
// -display
// -----------------------------------------------------------------------------

/// `-display NAME` (RFC 2167 §3.3.3).
#[derive(Debug, Default)]
pub struct Display;
impl Directive for Display {
    fn name(&self) -> &'static str { "display" }
    fn capability(&self) -> Capability { Capability(CAP_DISPLAY) }
    fn description(&self) -> &'static str { "select an output display format" }
    fn run<'a>(
        &'a self,
        _ctx: &'a ServerContext,
        s: &'a mut Session,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        let name = args.trim();
        if name.is_empty() {
            // Echo current display.
            out.tagged(Tag::Display, &format!("name:{}", s.display));
            out.end_block(Tag::Display);
            return ok(DirectiveOutcome::Ok);
        }
        // Only "dump" is a documented built-in display.
        if name.eq_ignore_ascii_case("dump") {
            "dump".clone_into(&mut s.display);
            ok(DirectiveOutcome::Ok)
        } else {
            err(ResponseCode::INVALID_DIRECTIVE_SYNTAX, format!("display: {name}"))
        }
    }
}

// -----------------------------------------------------------------------------
// -status
// -----------------------------------------------------------------------------

/// `-status` — emit the per-session status block (RFC 2167 §3.3.13).
#[derive(Debug, Default)]
pub struct Status;
impl Directive for Status {
    fn name(&self) -> &'static str { "status" }
    fn capability(&self) -> Capability { Capability(CAP_STATUS) }
    fn description(&self) -> &'static str { "report current session settings" }
    fn run<'a>(
        &'a self,
        _ctx: &'a ServerContext,
        s: &'a mut Session,
        _args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        out.tagged(Tag::Status, &format!("limit:{}", s.hit_limit));
        out.tagged(Tag::Status, &format!("hold:{}", on_off(s.hold_connect)));
        out.tagged(Tag::Status, &format!("forward:{}", on_off(s.forward)));
        out.tagged(Tag::Status, &format!("display:{}", s.display));
        out.tagged(
            Tag::Status,
            &format!(
                "contact:{}",
                s.client_vendor_id.as_deref().unwrap_or(""),
            ),
        );
        out.end_block(Tag::Status);
        ok(DirectiveOutcome::Ok)
    }
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

// -----------------------------------------------------------------------------
// -rwhois
// -----------------------------------------------------------------------------

/// `-rwhois <vendor-id>` — re-emit the banner and remember the vendor id
/// (RFC 2167 §3.3.8).
#[derive(Debug, Default)]
pub struct Rwhois;
impl Directive for Rwhois {
    fn name(&self) -> &'static str { "rwhois" }
    fn description(&self) -> &'static str { "negotiate version / record client identifier" }
    fn run<'a>(
        &'a self,
        ctx: &'a ServerContext,
        s: &'a mut Session,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        let v = args.trim();
        if !v.is_empty() {
            s.client_vendor_id = Some(v.to_owned());
        }
        // Banner::to_line includes no terminator; tagged()/raw_line() handles it.
        out.raw_line(&ctx.banner().to_line());
        ok(DirectiveOutcome::Ok)
    }
}

// -----------------------------------------------------------------------------
// -directive
// -----------------------------------------------------------------------------

/// `-directive` — list all registered directives (RFC 2167 §3.3.2).
#[derive(Debug, Default)]
pub struct DirectiveList;
impl Directive for DirectiveList {
    fn name(&self) -> &'static str { "directive" }
    fn description(&self) -> &'static str { "list directives supported by this server" }
    fn run<'a>(
        &'a self,
        ctx: &'a ServerContext,
        _s: &'a mut Session,
        _args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        let mut names: Vec<&str> = ctx.directives.iter().map(|(n, _)| n).collect();
        names.sort_unstable();
        for n in names {
            if let Some(d) = ctx.directives.get(n) {
                out.tagged(Tag::Directive, &format!("Directive:{}", d.name()));
                let desc = d.description();
                if !desc.is_empty() {
                    out.tagged(Tag::Directive, &format!("Description:{desc}"));
                }
            }
        }
        out.end_block(Tag::Directive);
        ok(DirectiveOutcome::Ok)
    }
}

// -----------------------------------------------------------------------------
// -class / -schema / -soa / -xfer / -security
// -----------------------------------------------------------------------------

fn parse_area_classes(args: &str) -> (String, Vec<String>) {
    let parts = split_args(args);
    let area = parts.first().copied().unwrap_or("").to_owned();
    let classes = parts.iter().skip(1).map(|s| (*s).to_owned()).collect();
    (area, classes)
}

/// `-class <auth-area> [class …]` (RFC 2167 §3.3.1).
#[derive(Debug, Default)]
pub struct Class;
impl Directive for Class {
    fn name(&self) -> &'static str { "class" }
    fn description(&self) -> &'static str { "list class metadata for an authority area" }
    fn run<'a>(
        &'a self,
        ctx: &'a ServerContext,
        _s: &'a mut Session,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        let Some(p) = ctx.class.as_ref() else {
            return err(ResponseCode::DIRECTIVE_NOT_AVAILABLE, "class");
        };
        let (area, classes) = parse_area_classes(args);
        let p = p.clone();
        async move {
            p.list(&area, &classes, out).await?;
            out.end_block(Tag::Class);
            Ok(DirectiveOutcome::Ok)
        }
        .boxed()
    }
}

/// `-schema <auth-area> [class …]` (RFC 2167 §3.3.10).
#[derive(Debug, Default)]
pub struct Schema;
impl Directive for Schema {
    fn name(&self) -> &'static str { "schema" }
    fn description(&self) -> &'static str { "fetch attribute schema for a class" }
    fn run<'a>(
        &'a self,
        ctx: &'a ServerContext,
        _s: &'a mut Session,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        let Some(p) = ctx.schema.as_ref() else {
            return err(ResponseCode::DIRECTIVE_NOT_AVAILABLE, "schema");
        };
        let (area, classes) = parse_area_classes(args);
        let p = p.clone();
        async move {
            p.list(&area, &classes, out).await?;
            out.end_block(Tag::Schema);
            Ok(DirectiveOutcome::Ok)
        }
        .boxed()
    }
}

/// `-soa [auth-area …]` (RFC 2167 §3.3.12).
#[derive(Debug, Default)]
pub struct Soa;
impl Directive for Soa {
    fn name(&self) -> &'static str { "soa" }
    fn description(&self) -> &'static str { "fetch start-of-authority records" }
    fn run<'a>(
        &'a self,
        ctx: &'a ServerContext,
        _s: &'a mut Session,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        let Some(p) = ctx.soa.as_ref() else {
            return err(ResponseCode::DIRECTIVE_NOT_AVAILABLE, "soa");
        };
        let areas: Vec<String> = split_args(args).into_iter().map(str::to_owned).collect();
        let p = p.clone();
        async move {
            p.list(&areas, out).await?;
            out.end_block(Tag::Soa);
            Ok(DirectiveOutcome::Ok)
        }
        .boxed()
    }
}

/// `-xfer …` (RFC 2167 §3.3.14).
#[derive(Debug, Default)]
pub struct Xfer;
impl Directive for Xfer {
    fn name(&self) -> &'static str { "xfer" }
    fn description(&self) -> &'static str { "bulk transfer of records" }
    fn run<'a>(
        &'a self,
        ctx: &'a ServerContext,
        _s: &'a mut Session,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        let Some(p) = ctx.xfer.as_ref() else {
            return err(ResponseCode::DIRECTIVE_NOT_AVAILABLE, "xfer");
        };
        let p = p.clone();
        async move {
            p.xfer(args, out).await?;
            out.end_block(Tag::Xfer);
            Ok(DirectiveOutcome::Ok)
        }
        .boxed()
    }
}

/// `-security …` (RFC 2167 §3.3.11).
#[derive(Debug, Default)]
pub struct Security;
impl Directive for Security {
    fn name(&self) -> &'static str { "security" }
    fn description(&self) -> &'static str { "negotiate authentication / security" }
    fn run<'a>(
        &'a self,
        ctx: &'a ServerContext,
        s: &'a mut Session,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        let Some(h) = ctx.auth.as_ref() else {
            return err(ResponseCode::DIRECTIVE_NOT_AVAILABLE, "security");
        };
        let h = h.clone();
        async move {
            h.authenticate(ctx, s, args, out).await?;
            Ok(DirectiveOutcome::Ok)
        }
        .boxed()
    }
}

// -----------------------------------------------------------------------------
// -register on|off
// -----------------------------------------------------------------------------

/// `-register on|off [args]` (RFC 2167 §3.3.9).
///
/// `-register on <action> <email> [more]` switches the session into
/// [`SessionState::Spool`]; subsequent non-directive lines are appended via
/// [`crate::handler::RegisterHandler::accept_line`] until `-register off`
/// returns the session to the query state.
#[derive(Debug, Default)]
pub struct Register;
impl Directive for Register {
    fn name(&self) -> &'static str { "register" }
    fn description(&self) -> &'static str { "submit object registration / modification" }
    fn run<'a>(
        &'a self,
        ctx: &'a ServerContext,
        s: &'a mut Session,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        let parts = split_args(args);
        let mode = parts.first().map(|s| s.to_ascii_lowercase());
        let Some(h) = ctx.register.as_ref() else {
            return err(ResponseCode::REGISTRATION_NOT_AUTHORIZED, "register");
        };
        let h = h.clone();
        match mode.as_deref() {
            Some("on") => {
                let action = parts.get(1).copied().unwrap_or("").to_owned();
                let email = parts.get(2).copied().unwrap_or("").to_owned();
                let extra = if parts.len() > 3 {
                    parts[3..].join(" ")
                } else {
                    String::new()
                };
                if action.is_empty() || email.is_empty() {
                    return err(
                        ResponseCode::INVALID_DIRECTIVE_SYNTAX,
                        "register on requires <action> <email>",
                    );
                }
                async move {
                    h.begin(&action, &email, &extra).await?;
                    s.state = SessionState::Spool;
                    s.register_action = Some(action);
                    s.register_email = Some(email);
                    Ok(DirectiveOutcome::Ok)
                }
                .boxed()
            }
            Some("off") => async move {
                h.finish(out).await?;
                s.state = SessionState::Query;
                s.register_action = None;
                s.register_email = None;
                Ok(DirectiveOutcome::Ok)
            }
            .boxed(),
            _ => err(ResponseCode::INVALID_DIRECTIVE_SYNTAX, "register on|off"),
        }
    }
}

// -----------------------------------------------------------------------------
// -notify (record updates) — accept and ignore by default
// -----------------------------------------------------------------------------

/// `-notify` — record-update notification (RFC 2167 §3.3.15). The default
/// implementation accepts the directive and returns `%ok` without doing
/// anything; consumers may register their own handler to override.
#[derive(Debug, Default)]
pub struct Notify;
impl Directive for Notify {
    fn name(&self) -> &'static str { "notify" }
    fn description(&self) -> &'static str { "post a record-update notification (default no-op)" }
    fn run<'a>(
        &'a self,
        _ctx: &'a ServerContext,
        _s: &'a mut Session,
        _args: &'a str,
        _out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>> {
        ok(DirectiveOutcome::Ok)
    }
}
