//! Parsed inbound request line classifier (RFC 2167 §3.1.1, §3.1.3).

/// One trimmed line as classified by the session loop.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Request {
    /// Empty line — the reference server silently ignores these.
    Empty,
    /// A directive: `name` is lowercased without the leading `-`,
    /// `args` is the remainder of the line (already trimmed).
    Directive {
        /// Directive name (lowercased, without the leading `-`).
        name: String,
        /// Raw argument string (may be empty).
        args: String,
    },
    /// A non-directive line during normal session: a query.
    Query(String),
    /// A non-directive line received while the session is in spool mode
    /// (between `-register on` and `-register off`).
    Spool(String),
}

impl Request {
    /// Classify a trimmed line given the current spool flag.
    ///
    /// Mirrors `processline` in `ref/rwhoisd/server/session.c`.
    /// RFC 2167 §3.1.3: "The first character of a query must not be a `-`".
    pub fn classify(line: &str, spooling: bool) -> Self {
        if line.is_empty() {
            return Request::Empty;
        }
        if is_directive(line) {
            let rest = &line[1..]; // strip leading '-'
            let (name, args) = match rest.find(char::is_whitespace) {
                Some(idx) => (&rest[..idx], rest[idx..].trim_start()),
                None => (rest, ""),
            };
            return Request::Directive {
                name: name.to_ascii_lowercase(),
                args: args.to_owned(),
            };
        }
        if spooling {
            Request::Spool(line.to_owned())
        } else {
            Request::Query(line.to_owned())
        }
    }
}

/// True if `s` looks like a directive: leading `-` followed by an ASCII letter.
///
/// Mirrors `is_directive` in `ref/rwhoisd/server/directive.c`.
#[must_use] 
pub fn is_directive(s: &str) -> bool {
    let mut bytes = s.as_bytes().iter();
    matches!(bytes.next(), Some(b'-')) && matches!(bytes.next(), Some(c) if c.is_ascii_alphabetic())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(name: &str, args: &str) -> Request {
        Request::Directive {
            name: name.into(),
            args: args.into(),
        }
    }

    #[test]
    fn empty_line() {
        assert_eq!(Request::classify("", false), Request::Empty);
    }

    #[test]
    fn directive_no_args() {
        assert_eq!(Request::classify("-quit", false), d("quit", ""));
    }

    #[test]
    fn directive_with_args_lowercases_name() {
        assert_eq!(
            Request::classify("-Limit 50", false),
            d("limit", "50")
        );
        assert_eq!(
            Request::classify("-HOLDCONNECT on", false),
            d("holdconnect", "on")
        );
    }

    #[test]
    fn directive_collapses_inter_token_whitespace_only_once() {
        // The leading whitespace between name and args is trimmed; remaining
        // whitespace within args is preserved verbatim.
        assert_eq!(
            Request::classify("-rwhois   V-1.5  NSI Client 1.2.3", false),
            d("rwhois", "V-1.5  NSI Client 1.2.3")
        );
    }

    #[test]
    fn extension_directive_names_keep_x_prefix() {
        // RFC 2167 §3.3.15: "-X-name [args]"
        assert_eq!(
            Request::classify("-X-date", false),
            d("x-date", "")
        );
    }

    #[test]
    fn lone_dash_is_not_a_directive() {
        // is_directive requires '-' followed by an ASCII letter
        assert!(matches!(Request::classify("-", false), Request::Query(_)));
        assert!(matches!(Request::classify("-1", false), Request::Query(_)));
    }

    #[test]
    fn query_vs_spool() {
        assert_eq!(
            Request::classify("foo", false),
            Request::Query("foo".into())
        );
        assert_eq!(
            Request::classify("foo", true),
            Request::Spool("foo".into())
        );
    }

    #[test]
    fn directive_in_spool_state_still_routes_as_directive() {
        // RFC 2167 §3.3.9: -register off must work while spooling.
        assert_eq!(
            Request::classify("-register off", true),
            d("register", "off")
        );
    }
}
