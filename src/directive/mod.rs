//! Directive trait, registry and dispatch.
//!
//! See [`builtin`] for the protocol-level built-ins that ship with the
//! crate. Consumers can register custom directives — including `-X-*`
//! extensions — via [`Registry::register`] or
//! [`crate::ServerBuilder::register_directive`].

pub mod builtin;

use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;

use crate::Result;
use crate::context::ServerContext;
use crate::session::Session;
use crate::wire::response::ResponseWriter;

/// Outcome of running a directive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DirectiveOutcome {
    /// Success — session writes `%ok` after flushing.
    Ok,
    /// Success but the directive is responsible for terminating the session
    /// after flushing (used by `-quit`).
    Quit,
    /// The directive printed its own terminator and the session must NOT
    /// append `%ok` / `%error`.
    Handled,
}

/// Capability bit advertised in the banner.
///
/// Mirrors the `CAP_*` macros in `ref/rwhoisd/common/directive_conf.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability(pub u32);

/// Trait implemented by directive handlers.
///
/// The registry stores directives behind `Arc<dyn Directive>`, so this
/// trait must be object-safe; the future is therefore returned as
/// [`BoxFuture`].
pub trait Directive: Send + Sync + 'static {
    /// Lowercased directive name (without the leading `-`).
    fn name(&self) -> &'static str;

    /// Capability bit contributed to the banner.
    fn capability(&self) -> Capability {
        Capability(0)
    }

    /// Human-readable description (for `-directive`).
    fn description(&self) -> &'static str {
        ""
    }

    /// Execute. The session is mutable so directives can flip flags
    /// (`hold_connect`, `display`, `limit`, …); the context exposes
    /// optional provider trait objects and other server-wide state.
    fn run<'a>(
        &'a self,
        ctx: &'a ServerContext,
        session: &'a mut Session,
        args: &'a str,
        out: &'a mut ResponseWriter,
    ) -> BoxFuture<'a, Result<DirectiveOutcome>>;
}

/// Lookup table for directive name → handler.
#[derive(Clone, Default)]
pub struct Registry {
    by_name: HashMap<String, Arc<dyn Directive>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut names: Vec<&String> = self.by_name.keys().collect();
        names.sort();
        f.debug_struct("Registry")
            .field("directives", &names)
            .finish()
    }
}

impl Registry {
    /// Empty registry.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Registry pre-populated with the protocol-level built-ins.
    #[must_use] 
    pub fn with_builtins() -> Self {
        let mut r = Self::new();
        builtin::register_all(&mut r);
        r
    }

    /// Register or replace a directive.
    pub fn register<D: Directive>(&mut self, directive: D) -> &mut Self {
        self.by_name
            .insert(directive.name().to_ascii_lowercase(), Arc::new(directive));
        self
    }

    /// Register a pre-boxed directive (useful for trait objects).
    pub fn register_arc(&mut self, directive: Arc<dyn Directive>) -> &mut Self {
        self.by_name
            .insert(directive.name().to_ascii_lowercase(), directive);
        self
    }

    /// Look up by lowercased name.
    #[must_use] 
    pub fn get(&self, name: &str) -> Option<Arc<dyn Directive>> {
        self.by_name.get(name).cloned()
    }

    /// Iterator over `(name, handler)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &Arc<dyn Directive>)> {
        self.by_name.iter().map(|(k, v)| (k.as_str(), v))
    }

    /// Number of registered directives.
    #[must_use] 
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// True iff no directives are registered.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// OR'd capability bitmask of all registered directives — used to render
    /// the banner's hex `00xxxx:00` field.
    #[must_use] 
    pub fn capability_mask(&self) -> u32 {
        self.by_name
            .values()
            .fold(0u32, |acc, d| acc | d.capability().0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_registered() {
        let r = Registry::with_builtins();
        for n in [
            "rwhois",
            "quit",
            "holdconnect",
            "limit",
            "forward",
            "display",
            "status",
            "directive",
            "class",
            "schema",
            "soa",
            "xfer",
            "register",
            "security",
            "notify",
        ] {
            assert!(r.get(n).is_some(), "missing builtin: {n}");
        }
    }

    #[test]
    fn capability_mask_is_or_of_bits() {
        let r = Registry::with_builtins();
        assert!(r.capability_mask() != 0);
    }
}
