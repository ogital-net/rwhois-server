//! `%rwhois` banner builder and parser (RFC 2167 §3.1.9).
//!
//! ABNF (RFC 2167 §3.1.9):
//! ```text
//! rwhois-banner  = "%rwhois" space version-list space host-name
//!                  [space implementation] crlf
//! version-list   = version *("," version)
//! version        = version-number [":" capability-id]
//!                / "V-1.5" ":" capability-id
//! version-number = "V-" 1*digit "." 1*digit
//! capability-id  = response-id ":" extra-id
//! response-id    = 6hex-digit
//! extra-id       = 2hex-digit
//! implementation = 1*any-char
//! ```

use std::fmt;

/// One protocol version listed in the banner, with optional capability id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// Major version number (the integer between `V-` and `.`).
    pub major: u32,
    /// Minor version number (the integer after `.`).
    pub minor: u32,
    /// Optional capability identifier (`response-id:extra-id`).
    ///
    /// V-1.5 *must* carry a capability id per RFC §3.1.9; older versions may
    /// omit it.
    pub capability: Option<Capability>,
}

impl Version {
    /// Convenience constructor.
    #[must_use] 
    pub const fn new(major: u32, minor: u32, capability: Option<Capability>) -> Self {
        Self { major, minor, capability }
    }

    /// Parse one `version` token (e.g. `V-1.5:00ffff:00`).
    #[must_use] 
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix("V-")?;
        let (verpart, cappart) = match rest.split_once(':') {
            Some((v, c)) => (v, Some(c)),
            None => (rest, None),
        };
        let (maj, min) = verpart.split_once('.')?;
        let major: u32 = maj.parse().ok()?;
        let minor: u32 = min.parse().ok()?;
        let capability = match cappart {
            Some(c) => Some(Capability::parse(c)?),
            None => None,
        };
        Some(Self { major, minor, capability })
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "V-{}.{}", self.major, self.minor)?;
        if let Some(c) = self.capability {
            write!(f, ":{c}")?;
        }
        Ok(())
    }
}

/// Capability identifier: 6 hex digits + 2 hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// Response capability bitmask (24 bits).
    pub response_id: u32,
    /// Extra/reserved capability bits (8 bits).
    pub extra_id: u8,
}

impl Capability {
    /// Build from raw fields.
    #[must_use] 
    pub const fn new(response_id: u32, extra_id: u8) -> Self {
        Self { response_id, extra_id }
    }

    /// Parse `<6hex>:<2hex>`.
    #[must_use] 
    pub fn parse(s: &str) -> Option<Self> {
        let (r, e) = s.split_once(':')?;
        if r.len() != 6 || e.len() != 2 {
            return None;
        }
        let response_id = u32::from_str_radix(r, 16).ok()?;
        let extra_id = u8::from_str_radix(e, 16).ok()?;
        Some(Self { response_id, extra_id })
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:06x}:{:02x}", self.response_id & 0x00ff_ffff, self.extra_id)
    }
}

/// `%rwhois` greeting / `-rwhois` directive response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Banner {
    /// Versions advertised by the server. Must be non-empty; if more than
    /// one is present the lowest must come first (RFC §3.1.9).
    pub versions: Vec<Version>,
    /// Server host name (free-form per ABNF).
    pub hostname: String,
    /// Optional implementation string (free-form trailing text).
    pub implementation: Option<String>,
}

impl Banner {
    /// Convenience: a single-version banner with capability bits.
    pub fn single(
        major: u32,
        minor: u32,
        capability: Capability,
        hostname: impl Into<String>,
        implementation: Option<String>,
    ) -> Self {
        Self {
            versions: vec![Version::new(major, minor, Some(capability))],
            hostname: hostname.into(),
            implementation,
        }
    }

    /// Render to the wire form **without** the trailing CRLF.
    /// Encoders are responsible for terminator handling.
    pub fn to_line(&self) -> String {
        let versions = self
            .versions
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",");
        match &self.implementation {
            Some(impl_) => format!("%rwhois {versions} {hn} {impl_}", hn = self.hostname),
            None => format!("%rwhois {versions} {hn}", hn = self.hostname),
        }
    }

    /// Parse a banner line (without its terminator).
    pub fn parse(line: &str) -> Option<Self> {
        let body = line.strip_prefix("%rwhois ")?;
        // First whitespace-separated token is the comma-separated version list,
        // the second is the hostname, and the optional remainder is impl.
        let mut iter = body.splitn(3, ' ');
        let version_list = iter.next()?;
        let hostname = iter.next()?;
        let implementation = iter.next().map(str::to_owned).filter(|s| !s.is_empty());

        let mut versions = Vec::new();
        for v in version_list.split(',') {
            versions.push(Version::parse(v)?);
        }
        if versions.is_empty() {
            return None;
        }
        Some(Self {
            versions,
            hostname: hostname.to_owned(),
            implementation,
        })
    }
}

impl fmt::Display for Banner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_line())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_matches_rfc_example() {
        // RFC 2167 §3.1.7
        let b = Banner::single(
            1,
            5,
            Capability::new(0x00ffff, 0x00),
            "master.rwhois.net",
            Some("(Network Solutions V-1.5)".into()),
        );
        assert_eq!(
            b.to_line(),
            "%rwhois V-1.5:00ffff:00 master.rwhois.net (Network Solutions V-1.5)"
        );
    }

    #[test]
    fn parse_single_version_banner_matches_rfc() {
        let parsed = Banner::parse(
            "%rwhois V-1.5:00ffff:00 master.rwhois.net (Network Solutions V-1.5)",
        )
        .unwrap();
        assert_eq!(parsed.versions.len(), 1);
        assert_eq!(parsed.versions[0].major, 1);
        assert_eq!(parsed.versions[0].minor, 5);
        assert_eq!(
            parsed.versions[0].capability,
            Some(Capability::new(0x00ffff, 0x00))
        );
        assert_eq!(parsed.hostname, "master.rwhois.net");
        assert_eq!(
            parsed.implementation.as_deref(),
            Some("(Network Solutions V-1.5)")
        );
    }

    #[test]
    fn parse_multi_version_banner_matches_rfc() {
        // RFC 2167 §3.2.1 example: two versions.
        let line = "%rwhois V-1.0,V-1.5:00ffff:00 rs.internic.net (NSI Server 1.5.4)";
        let b = Banner::parse(line).unwrap();
        assert_eq!(b.versions.len(), 2);
        assert_eq!(b.versions[0], Version::new(1, 0, None));
        assert_eq!(
            b.versions[1],
            Version::new(1, 5, Some(Capability::new(0x00ffff, 0x00)))
        );
        assert_eq!(b.hostname, "rs.internic.net");
    }

    #[test]
    fn roundtrip() {
        let line = "%rwhois V-1.0,V-1.5:00ffff:00 rs.internic.net (NSI Server 1.5.4)";
        let b = Banner::parse(line).unwrap();
        assert_eq!(b.to_line(), line);
    }

    #[test]
    fn rejects_non_banner_line() {
        assert!(Banner::parse("%ok").is_none());
        assert!(Banner::parse("%rwhois ").is_none());
    }

    #[test]
    fn rejects_malformed_capability() {
        assert!(Version::parse("V-1.5:zzzzzz:00").is_none());
        assert!(Version::parse("V-1.5:00ff:00").is_none()); // wrong response_id len
        assert!(Version::parse("V-1.5:00ffff:0").is_none()); // wrong extra_id len
    }

    #[test]
    fn capability_displays_zero_padded() {
        assert_eq!(Capability::new(0x1, 0x0).to_string(), "000001:00");
        assert_eq!(Capability::new(0xffffff, 0xff).to_string(), "ffffff:ff");
    }
}
