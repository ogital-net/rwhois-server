//! Query AST + parser (RFC 2167 §3.4).
//!
//! ABNF (RFC 2167 §3.4):
//! ```text
//! rwhois-query     = [class-name space] query crlf
//! query            = query-string / attribute-query / query bin-boolean query
//! query-char       = <any-char, except """, space, tab>
//! quoted-query-char= query-char / space / tab / "
//! query-string     = ["*"] 1*query-char ["*"] /
//!                    """ ["*"] 1*quoted-query-char ["*"] """
//! attribute-query  = attribute-name "=" query-string
//! bin-boolean      = "and" / "or"
//! ```
//!
//! The `class-name` prefix is ambiguous against a bare query-string at parse
//! time (a `class-name` is just `1*id-char`). Disambiguation requires a class
//! table, which the wire layer doesn't have — so [`Query::parse`] does **not**
//! split off a leading class. Use [`Query::with_class_if`] to apply a
//! consumer-supplied class predicate after parsing.
//!
//! In addition to the ABNF, this parser accepts the `attr!=value` operator
//! found in the reference C parser (`ref/rwhoisd/mkdb/parse.{l,y}`).
//!
//! Boolean operators are case-insensitive and left-associative with equal
//! precedence (no parentheses are defined by the RFC).

use std::fmt;

use crate::{Error, ResponseCode};

/// Parsed query expression with an optional class scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    /// Optional leading class scope (`domain example.com` → `Some("domain")`).
    /// Always `None` when produced by [`Query::parse`]; a higher layer may
    /// populate it via [`Query::with_class_if`].
    pub class: Option<String>,
    /// Top-level expression.
    pub expr: Expr,
    /// Original raw text the parser was given.
    pub raw: String,
}

/// Boolean expression tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// A leaf term.
    Term(Term),
    /// `lhs and rhs`.
    And(Box<Expr>, Box<Expr>),
    /// `lhs or rhs`.
    Or(Box<Expr>, Box<Expr>),
}

/// One leaf of a query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    /// `attr=value`.
    AttrEq {
        /// Attribute name.
        attr: String,
        /// Right-hand value.
        value: Value,
    },
    /// `attr!=value` (extension over the strict RFC ABNF; accepted by the
    /// reference C parser).
    AttrNe {
        /// Attribute name.
        attr: String,
        /// Right-hand value.
        value: Value,
    },
    /// A bare `query-string` matched against any attribute.
    Value(Value),
}

/// A query value, possibly wildcarded or quoted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Value {
    /// Decoded text content (without surrounding quotes or wildcard `*`s).
    pub text: String,
    /// Match style derived from leading/trailing `*` and quoting.
    pub kind: ValueKind,
}

/// Match style for a [`Value`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValueKind {
    /// Exact match.
    Exact,
    /// `foo*` — prefix match.
    Prefix,
    /// `*foo` — suffix match.
    Suffix,
    /// `*foo*` — substring match.
    Substring,
    /// Quoted literal — match exactly, including any embedded `*`.
    Quoted,
}

// --------------------------------------------------------------------------
// Parser
// --------------------------------------------------------------------------

impl Query {
    /// Parse one query line (no terminator).
    ///
    /// # Errors
    /// Returns [`Error::Protocol`] with [`ResponseCode::INVALID_QUERY_SYNTAX`]
    /// (350) when the input is empty, contains an unterminated quoted string,
    /// has a missing value after `=` / `!=`, or has stray trailing input.
    pub fn parse(input: &str) -> crate::Result<Self> {
        let raw = input.to_owned();
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(Error::protocol(
                ResponseCode::INVALID_QUERY_SYNTAX,
                "empty query",
            ));
        }
        let mut p = Parser::new(trimmed);
        let expr = p.parse_expr()?;
        p.skip_ws();
        if !p.eof() {
            return Err(Error::protocol(
                ResponseCode::INVALID_QUERY_SYNTAX,
                format!("unexpected trailing input: {:?}", &p.input[p.pos..]),
            ));
        }
        Ok(Query {
            class: None,
            expr,
            raw,
        })
    }

    /// If `is_class(token)` accepts the first bare token of the query, lift
    /// that token into [`Self::class`] and replace the leaf with the rest.
    /// Returns `self` unchanged when the leading expression isn't a single
    /// bare unquoted [`Term::Value`].
    #[must_use]
    pub fn with_class_if<F: Fn(&str) -> bool>(mut self, is_class: F) -> Self {
        // Walk to the leftmost leaf; if it's a bare exact value AND
        // `is_class(text)` is true AND there is more to the right, set
        // `self.class` and drop that leaf.
        if let Expr::Term(Term::Value(Value {
            text,
            kind: ValueKind::Exact,
        })) = &self.expr
        {
            // Single-leaf query: a bare class with no rest doesn't make sense
            // as a class-restricted query, so don't lift it.
            if is_class(text) {
                // No-op for single-leaf queries (no right-hand side).
                return self;
            }
        }
        if let Some((
            Term::Value(Value {
                text,
                kind: ValueKind::Exact,
            }),
            rest,
        )) = split_leading_term(&self.expr)
        {
            if is_class(&text) {
                self.class = Some(text);
                self.expr = rest;
            }
        }
        self
    }
}

/// Split off the leftmost term in a left-associative AND/OR tree, returning
/// `(leftmost_term, rest_expr)`. Returns `None` if the expression is a single
/// term.
fn split_leading_term(e: &Expr) -> Option<(Term, Expr)> {
    match e {
        Expr::Term(_) => None,
        Expr::And(l, r) => if let Expr::Term(t) = l.as_ref() { Some((t.clone(), (**r).clone())) } else {
            let (t, new_l) = split_leading_term(l)?;
            Some((t, Expr::And(Box::new(new_l), r.clone())))
        },
        Expr::Or(l, r) => if let Expr::Term(t) = l.as_ref() { Some((t.clone(), (**r).clone())) } else {
            let (t, new_l) = split_leading_term(l)?;
            Some((t, Expr::Or(Box::new(new_l), r.clone())))
        },
    }
}

impl fmt::Display for Query {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

struct Parser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn eof(&self) -> bool {
        self.pos >= self.input.len()
    }

    fn peek(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn skip_ws(&mut self) {
        while let Some(c) = self.peek() {
            if c == ' ' || c == '\t' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
    }

    /// Try to consume a literal `kw` (case-insensitive) **only** if it is
    /// followed by whitespace or EOF. Restores `pos` on failure.
    fn try_keyword(&mut self, kw: &str) -> bool {
        let start = self.pos;
        let rest = &self.input[self.pos..];
        if rest.len() < kw.len() {
            return false;
        }
        if !rest[..kw.len()].eq_ignore_ascii_case(kw) {
            return false;
        }
        let after = &rest[kw.len()..];
        let next = after.chars().next();
        if next.is_some_and(|c| c != ' ' && c != '\t') {
            return false;
        }
        self.pos += kw.len();
        // require at least one whitespace after the keyword (unless EOF)
        if !after.is_empty() {
            self.skip_ws();
        }
        // sanity: rewind on lookahead failure not needed since we already
        // matched.
        let _ = start; // suppress unused-binding lint in release
        true
    }

    /// expr := term (("and"|"or") term)*
    fn parse_expr(&mut self) -> crate::Result<Expr> {
        self.skip_ws();
        let mut lhs = Expr::Term(self.parse_term()?);
        loop {
            self.skip_ws();
            if self.eof() {
                break;
            }
            let save = self.pos;
            if self.try_keyword("and") {
                let rhs = self.parse_term()?;
                lhs = Expr::And(Box::new(lhs), Box::new(Expr::Term(rhs)));
                continue;
            }
            self.pos = save;
            if self.try_keyword("or") {
                let rhs = self.parse_term()?;
                lhs = Expr::Or(Box::new(lhs), Box::new(Expr::Term(rhs)));
                continue;
            }
            self.pos = save;
            // No boolean operator — the grammar allows multi-token queries
            // implicitly meaning AND? RFC says AND/OR are the only combiners.
            // The reference C parser uses an implicit AND when two query
            // terms are juxtaposed. We do the same for interop.
            let rhs = self.parse_term()?;
            lhs = Expr::And(Box::new(lhs), Box::new(Expr::Term(rhs)));
        }
        Ok(lhs)
    }

    fn parse_term(&mut self) -> crate::Result<Term> {
        self.skip_ws();
        if self.eof() {
            return Err(Error::protocol(
                ResponseCode::INVALID_QUERY_SYNTAX,
                "unexpected end of query",
            ));
        }
        // Quoted bare value?
        if self.peek() == Some('"') {
            return Ok(Term::Value(self.parse_quoted_value()?));
        }
        // Try `attr=…` / `attr!=…`. We need to look ahead for `=` or `!=`
        // before any whitespace.
        let start = self.pos;
        let token = self.consume_id_chars();
        if !token.is_empty() {
            match self.peek() {
                Some('=') => {
                    self.pos += 1;
                    let val = self.parse_value_after_op()?;
                    return Ok(Term::AttrEq {
                        attr: token,
                        value: val,
                    });
                }
                Some('!') if self.input[self.pos..].starts_with("!=") => {
                    self.pos += 2;
                    let val = self.parse_value_after_op()?;
                    return Ok(Term::AttrNe {
                        attr: token,
                        value: val,
                    });
                }
                _ => {}
            }
        }
        // Otherwise it's a bare query-string. Rewind and parse as such.
        self.pos = start;
        Ok(Term::Value(self.parse_query_string()?))
    }

    fn parse_value_after_op(&mut self) -> crate::Result<Value> {
        if self.eof() {
            return Err(Error::protocol(
                ResponseCode::INVALID_QUERY_SYNTAX,
                "missing value after operator",
            ));
        }
        if self.peek() == Some('"') {
            self.parse_quoted_value()
        } else {
            self.parse_query_string()
        }
    }

    fn consume_id_chars(&mut self) -> String {
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                self.pos += c.len_utf8();
            } else {
                break;
            }
        }
        self.input[start..self.pos].to_owned()
    }

    /// Unquoted `["*"] 1*query-char ["*"]`.
    fn parse_query_string(&mut self) -> crate::Result<Value> {
        let leading_star = if self.peek() == Some('*') {
            self.pos += 1;
            true
        } else {
            false
        };
        let start = self.pos;
        while let Some(c) = self.peek() {
            // query-char excludes '"', space, tab. We additionally stop at
            // a trailing '*' so we can split it off.
            if c == '"' || c == ' ' || c == '\t' {
                break;
            }
            self.pos += c.len_utf8();
        }
        let mut text = self.input[start..self.pos].to_owned();
        let trailing_star = text.ends_with('*');
        if trailing_star {
            text.pop();
        }
        if text.is_empty() {
            return Err(Error::protocol(
                ResponseCode::INVALID_QUERY_SYNTAX,
                "empty query string",
            ));
        }
        let kind = match (leading_star, trailing_star) {
            (false, false) => ValueKind::Exact,
            (false, true) => ValueKind::Prefix,
            (true, false) => ValueKind::Suffix,
            (true, true) => ValueKind::Substring,
        };
        Ok(Value { text, kind })
    }

    /// `""" ["*"] 1*quoted-query-char ["*"] """`. The value is taken
    /// verbatim except the surrounding quotes; embedded `*` characters do
    /// **not** become wildcards (they're literal). Quoted values always have
    /// `kind = Quoted` per RFC §3.4 wording (clients must not infer wildcards
    /// from a quoted string).
    fn parse_quoted_value(&mut self) -> crate::Result<Value> {
        debug_assert_eq!(self.peek(), Some('"'));
        self.pos += 1;
        let start = self.pos;
        while let Some(c) = self.peek() {
            if c == '"' {
                break;
            }
            self.pos += c.len_utf8();
        }
        if self.peek() != Some('"') {
            return Err(Error::protocol(
                ResponseCode::INVALID_QUERY_SYNTAX,
                "unterminated quoted string",
            ));
        }
        let text = self.input[start..self.pos].to_owned();
        self.pos += 1; // closing quote
        if text.is_empty() {
            return Err(Error::protocol(
                ResponseCode::INVALID_QUERY_SYNTAX,
                "empty quoted string",
            ));
        }
        Ok(Value { text, kind: ValueKind::Quoted })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn val_exact(s: &str) -> Value {
        Value { text: s.into(), kind: ValueKind::Exact }
    }

    #[test]
    fn parses_bare_exact_value() {
        let q = Query::parse("ibm").unwrap();
        assert_eq!(q.expr, Expr::Term(Term::Value(val_exact("ibm"))));
        assert!(q.class.is_none());
    }

    #[test]
    fn parses_prefix_suffix_substring_wildcards() {
        // RFC 2167 §3.4: `["*"] 1*query-char ["*"]`.
        let q = Query::parse("foo*").unwrap();
        assert_eq!(
            q.expr,
            Expr::Term(Term::Value(Value {
                text: "foo".into(),
                kind: ValueKind::Prefix,
            }))
        );
        let q = Query::parse("*foo").unwrap();
        assert_eq!(
            q.expr,
            Expr::Term(Term::Value(Value {
                text: "foo".into(),
                kind: ValueKind::Suffix,
            }))
        );
        let q = Query::parse("*foo*").unwrap();
        assert_eq!(
            q.expr,
            Expr::Term(Term::Value(Value {
                text: "foo".into(),
                kind: ValueKind::Substring,
            }))
        );
    }

    #[test]
    fn parses_quoted_value_with_spaces() {
        let q = Query::parse(r#""hello world""#).unwrap();
        assert_eq!(
            q.expr,
            Expr::Term(Term::Value(Value {
                text: "hello world".into(),
                kind: ValueKind::Quoted,
            }))
        );
    }

    #[test]
    fn quoted_stars_are_literal() {
        let q = Query::parse(r#""*foo*""#).unwrap();
        assert_eq!(
            q.expr,
            Expr::Term(Term::Value(Value {
                text: "*foo*".into(),
                kind: ValueKind::Quoted,
            }))
        );
    }

    #[test]
    fn parses_attribute_eq_and_ne() {
        // RFC 2167 §3.4 attribute-query = attribute-name "=" query-string
        let q = Query::parse("Domain-Name=konabo.com").unwrap();
        assert_eq!(
            q.expr,
            Expr::Term(Term::AttrEq {
                attr: "Domain-Name".into(),
                value: val_exact("konabo.com"),
            })
        );

        // C-extension: attr!=value
        let q = Query::parse("Org-Name!=ACME").unwrap();
        assert_eq!(
            q.expr,
            Expr::Term(Term::AttrNe {
                attr: "Org-Name".into(),
                value: val_exact("ACME"),
            })
        );
    }

    #[test]
    fn attribute_eq_with_quoted_value() {
        // RFC 2167 §3.3.7 example: contact Last-Name="Beeblebrox"
        let q = Query::parse(r#"Last-Name="Beeblebrox""#).unwrap();
        assert_eq!(
            q.expr,
            Expr::Term(Term::AttrEq {
                attr: "Last-Name".into(),
                value: Value {
                    text: "Beeblebrox".into(),
                    kind: ValueKind::Quoted,
                },
            })
        );
    }

    #[test]
    fn boolean_and_or_left_associative() {
        // RFC 2167 §3.4 example: "ibm and jubliana*"
        let q = Query::parse("ibm and jubliana*").unwrap();
        assert_eq!(
            q.expr,
            Expr::And(
                Box::new(Expr::Term(Term::Value(val_exact("ibm")))),
                Box::new(Expr::Term(Term::Value(Value {
                    text: "jubliana".into(),
                    kind: ValueKind::Prefix,
                }))),
            )
        );

        let q = Query::parse("a or b and c").unwrap();
        // left-associative, equal precedence
        assert_eq!(
            q.expr,
            Expr::And(
                Box::new(Expr::Or(
                    Box::new(Expr::Term(Term::Value(val_exact("a")))),
                    Box::new(Expr::Term(Term::Value(val_exact("b")))),
                )),
                Box::new(Expr::Term(Term::Value(val_exact("c")))),
            )
        );
    }

    #[test]
    fn boolean_keywords_are_case_insensitive() {
        let q = Query::parse("a AND b OR c").unwrap();
        match q.expr {
            Expr::Or(l, _) => assert!(matches!(*l, Expr::And(_, _))),
            _ => panic!("expected or-and tree"),
        }
    }

    #[test]
    fn implicit_and_for_juxtaposed_tokens() {
        // The reference C parser treats `domain rwhois.net` as
        // class=domain, value=rwhois.net. Our wire-level parser doesn't know
        // about classes; it just produces an implicit AND of two terms.
        let q = Query::parse("domain rwhois.net").unwrap();
        match q.expr {
            Expr::And(l, r) => {
                assert!(matches!(*l, Expr::Term(Term::Value(_))));
                assert!(matches!(*r, Expr::Term(Term::Value(_))));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn class_lift_lifts_when_predicate_matches() {
        // domain example.com → class=domain, expr=value(example.com)
        let q = Query::parse("domain example.com")
            .unwrap()
            .with_class_if(|t| t == "domain");
        assert_eq!(q.class.as_deref(), Some("domain"));
        assert_eq!(q.expr, Expr::Term(Term::Value(val_exact("example.com"))));
    }

    #[test]
    fn class_lift_does_not_lift_single_term_query() {
        // A bare `domain` alone is just a query for "domain", not a class
        // scope with no body.
        let q = Query::parse("domain").unwrap().with_class_if(|t| t == "domain");
        assert!(q.class.is_none());
    }

    #[test]
    fn class_lift_does_not_lift_when_predicate_rejects() {
        let q = Query::parse("foo bar")
            .unwrap()
            .with_class_if(|t| t == "domain");
        assert!(q.class.is_none());
    }

    #[test]
    fn rejects_empty_input() {
        assert!(Query::parse("").is_err());
        assert!(Query::parse("    ").is_err());
    }

    #[test]
    fn rejects_unterminated_quote() {
        assert!(Query::parse(r#""abc"#).is_err());
    }

    #[test]
    fn rejects_lone_star() {
        assert!(Query::parse("*").is_err());
        assert!(Query::parse("**").is_err());
    }

    #[test]
    fn rejects_attr_with_missing_value() {
        assert!(Query::parse("foo=").is_err());
        assert!(Query::parse("foo!=").is_err());
    }
}
