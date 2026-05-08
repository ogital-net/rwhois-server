//! Outbound response builders **and** inbound response-line parser.
//!
//! Together with [`super::banner`] and [`crate::codec`] this is the complete
//! RFC 2167 wire layer for both halves of a session: handlers append lines
//! using [`ResponseWriter`], and clients (or tests) parse a flow of lines
//! using [`ResponseLine::parse`].
//!
//! ABNF references: RFC 2167 §3.1.2 (response), §3.1.5 (info), §3.4
//! (`%referral`, untagged record lines, type-char), §3.3.x (per-directive
//! tagged blocks).

use bytes::{BufMut, BytesMut};

use crate::codec::CRLF;
use crate::wire::code::ResponseCode;

/// Tag prefixing a tagged response block (RFC 2167 §3.1.2 et al.).
///
/// Mirrors the table in `ref/rwhoisd/common/client_msgs.c`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    /// Banner / capability advertisement (`%rwhois`).
    Rwhois,
    /// `%referral` (RFC §3.4).
    Referral,
    /// `%class` (RFC §3.3.1).
    Class,
    /// `%see-also` — referenced object pointer.
    SeeAlso,
    /// `%load` — server load info.
    Load,
    /// `%soa` (RFC §3.3.12).
    Soa,
    /// `%status` (RFC §3.3.13).
    Status,
    /// `%xfer` (RFC §3.3.14).
    Xfer,
    /// `%schema` (RFC §3.3.10).
    Schema,
    /// `%directive` (RFC §3.3.2).
    Directive,
    /// `%info` (RFC §3.1.5).
    Info,
    /// `%X-` extension prefix (RFC §3.3.15). The `as_str()` form is the
    /// literal `%X-` token; use [`ResponseWriter::x_ext`] to emit a
    /// concrete extension line and inspect [`ResponseLine::UnknownTagged`]
    /// (filter on a `%X-` prefix) to consume one.
    XExt,
    /// `%register` (RFC §3.3.9).
    Register,
    /// `%display` (RFC §3.3.3).
    Display,
}

impl Tag {
    /// Wire token including the leading `%`.
    #[must_use] 
    pub const fn as_str(self) -> &'static str {
        match self {
            Tag::Rwhois => "%rwhois",
            Tag::Referral => "%referral",
            Tag::Class => "%class",
            Tag::SeeAlso => "%see-also",
            Tag::Load => "%load",
            Tag::Soa => "%soa",
            Tag::Status => "%status",
            Tag::Xfer => "%xfer",
            Tag::Schema => "%schema",
            Tag::Directive => "%directive",
            Tag::Info => "%info",
            Tag::XExt => "%X-",
            Tag::Register => "%register",
            Tag::Display => "%display",
        }
    }

    /// Parse a leading `%tag` token (no body) back into a [`Tag`].
    #[must_use] 
    pub fn from_token(s: &str) -> Option<Self> {
        Some(match s {
            "%rwhois" => Tag::Rwhois,
            "%referral" => Tag::Referral,
            "%class" => Tag::Class,
            "%see-also" => Tag::SeeAlso,
            "%load" => Tag::Load,
            "%soa" => Tag::Soa,
            "%status" => Tag::Status,
            "%xfer" => Tag::Xfer,
            "%schema" => Tag::Schema,
            "%directive" => Tag::Directive,
            "%info" => Tag::Info,
            "%X-" => Tag::XExt,
            "%register" => Tag::Register,
            "%display" => Tag::Display,
            _ => return None,
        })
    }
}

/// Type character for a typed record value (RFC 2167 §3.4).
///
/// In the dump format `class:attr;<type>:value`, the type character signals
/// to the client how to render the value. Defaults to `Text` when omitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeChar {
    /// `T` — plain text (default; the wire form usually omits this).
    Text,
    /// `I` — globally unique object identifier; clients may follow.
    Id,
    /// `S` — see-also reference.
    SeeAlso,
}

impl TypeChar {
    /// The single character used on the wire.
    #[must_use] 
    pub const fn as_char(self) -> char {
        match self {
            TypeChar::Text => 'T',
            TypeChar::Id => 'I',
            TypeChar::SeeAlso => 'S',
        }
    }

    /// Parse a single character.
    #[must_use] 
    pub fn from_char(c: char) -> Option<Self> {
        match c {
            'T' | 't' => Some(TypeChar::Text),
            'I' | 'i' => Some(TypeChar::Id),
            'S' | 's' => Some(TypeChar::SeeAlso),
            _ => None,
        }
    }
}

/// Buffer writer handed to handlers for emitting response lines.
///
/// All methods append CRLF-terminated lines to an internal `BytesMut`. The
/// session is responsible for flushing the buffer and appending the final
/// `%ok` / `%error` terminator.
#[derive(Debug, Default)]
pub struct ResponseWriter {
    buf: BytesMut,
}

impl ResponseWriter {
    /// Create an empty writer.
    #[must_use] 
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrow the accumulated bytes (without consuming).
    #[must_use] 
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Take the accumulated bytes, leaving the writer empty.
    pub fn take(&mut self) -> BytesMut {
        std::mem::take(&mut self.buf)
    }

    /// True iff nothing has been written yet.
    #[must_use] 
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Append a raw, untagged line (e.g. a `class:attr:value` record line).
    pub fn raw_line(&mut self, line: &str) {
        self.buf.reserve(line.len() + CRLF.len());
        self.buf.put_slice(line.as_bytes());
        self.buf.put_slice(CRLF);
    }

    /// Blank line — used as a record separator inside a result set
    /// (RFC 2167 §3.4: `query-record = 1*query-line crlf`).
    pub fn blank_line(&mut self) {
        self.buf.put_slice(CRLF);
    }

    /// Append a tagged line: `<tag> <body>` (or just `<tag>` if body empty).
    /// A tag-with-empty-body terminates a tagged record block.
    pub fn tagged(&mut self, tag: Tag, body: &str) {
        let prefix = tag.as_str();
        self.buf
            .reserve(prefix.len() + 1 + body.len() + CRLF.len());
        self.buf.put_slice(prefix.as_bytes());
        if !body.is_empty() {
            self.buf.put_u8(b' ');
            self.buf.put_slice(body.as_bytes());
        }
        self.buf.put_slice(CRLF);
    }

    /// Terminate the current tagged block (`%foo\r\n`).
    pub fn end_block(&mut self, tag: Tag) {
        self.tagged(tag, "");
    }

    /// `%referral rwhois://host:port/auth-area=<area>` (RFC §3.4).
    pub fn referral(&mut self, host: &str, port: u16, auth_area: &str) {
        self.tagged(
            Tag::Referral,
            &format!("rwhois://{host}:{port}/auth-area={auth_area}"),
        );
    }

    /// Pre-formatted referral URL.
    pub fn referral_url(&mut self, url: &str) {
        self.tagged(Tag::Referral, url);
    }

    /// Append an untagged record attribute line in the dump format
    /// `<class>:<attr>:<value>` (RFC §3.4).
    pub fn record_attr(&mut self, class: &str, attr: &str, value: &str) {
        self.record_typed(class, attr, None, value);
    }

    /// Append a typed record attribute line: `<class>:<attr>;<T>:<value>`.
    pub fn record_typed(
        &mut self,
        class: &str,
        attr: &str,
        ty: Option<TypeChar>,
        value: &str,
    ) {
        let mut needed = class.len() + attr.len() + value.len() + 2 + CRLF.len();
        if ty.is_some() {
            needed += 2; // ';X'
        }
        self.buf.reserve(needed);
        self.buf.put_slice(class.as_bytes());
        self.buf.put_u8(b':');
        self.buf.put_slice(attr.as_bytes());
        if let Some(t) = ty {
            self.buf.put_u8(b';');
            self.buf.put_u8(t.as_char() as u8);
        }
        self.buf.put_u8(b':');
        self.buf.put_slice(value.as_bytes());
        self.buf.put_slice(CRLF);
    }

    /// `%info on` block opener (RFC §3.1.5).
    pub fn info_on(&mut self) {
        self.tagged(Tag::Info, "on");
    }

    /// `%info off` block closer (RFC §3.1.5).
    pub fn info_off(&mut self) {
        self.tagged(Tag::Info, "off");
    }

    /// Emit a `%X-<name> <body>` extension line (RFC 2167 §3.3.15).
    ///
    /// A blank `body` produces `%X-<name>` (the conventional end-of-block
    /// terminator for an extension). The `name` is written verbatim.
    pub fn x_ext(&mut self, name: &str, body: &str) {
        self.buf
            .reserve(3 + name.len() + 1 + body.len() + CRLF.len());
        self.buf.put_slice(b"%X-");
        self.buf.put_slice(name.as_bytes());
        if !body.is_empty() {
            self.buf.put_u8(b' ');
            self.buf.put_slice(body.as_bytes());
        }
        self.buf.put_slice(CRLF);
    }
}

/// Format a `%error <code> <message>[: <extra>]` line into `out`.
///
/// RFC 2167 §3.1.9: `error-response = "%error" space error-code space
/// error-text`. `error-code` is rendered as a 3-digit zero-padded decimal.
pub fn write_error(out: &mut BytesMut, code: ResponseCode, extra: Option<&str>) {
    let header = format!("%error {:03} {}", code.code, code.message);
    out.reserve(header.len() + CRLF.len() + extra.map_or(0, |e| e.len() + 2));
    out.put_slice(header.as_bytes());
    if let Some(extra) = extra.filter(|s| !s.is_empty()) {
        out.put_slice(b": ");
        out.put_slice(extra.as_bytes());
    }
    out.put_slice(CRLF);
}

/// Append `%ok\r\n` to `out`.
pub fn write_ok(out: &mut BytesMut) {
    out.reserve(3 + CRLF.len());
    out.put_slice(b"%ok");
    out.put_slice(CRLF);
}

// --------------------------------------------------------------------------
// Parsing side: ResponseLine
// --------------------------------------------------------------------------

/// One parsed line of a server response stream.
///
/// Use [`ResponseLine::parse`] on a single trimmed line to classify it. A
/// stream of these forms a complete response per RFC 2167 §3.1.2 / §3.4.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResponseLine {
    /// `%ok`.
    Ok,
    /// `%error <code> <text>[: <extra>]`.
    Error {
        /// Numeric code.
        code: u16,
        /// Canonical message text (everything after the code, up to optional
        /// `": <extra>"`).
        text: String,
        /// Optional implementation-specific detail after `": "`.
        extra: Option<String>,
    },
    /// `%info on` / `%info off`.
    InfoMarker(InfoMarker),
    /// A tagged line with a non-empty body, e.g. `%schema map:attribute:Name`.
    Tagged {
        /// Which tag.
        tag: Tag,
        /// Body following the single space after the tag.
        body: String,
    },
    /// A blank-bodied tagged line such as `%schema` — end-of-record terminator.
    TaggedEnd(Tag),
    /// `%referral <url>` (parsed for convenience).
    Referral(ReferralUrl),
    /// An untagged record line `class:attr[;type]:value` (RFC §3.4).
    Record(RecordLine),
    /// Blank line — record separator.
    Blank,
    /// Any other tagged line whose tag we don't recognise.
    UnknownTagged {
        /// Raw `%tag` token.
        tag: String,
        /// Body, or empty.
        body: String,
    },
    /// A free-form (untagged, non-record) line — e.g. a `-X-*` directive's
    /// program output (RFC §3.3.15).
    FreeForm(String),
}

/// `%info on` / `%info off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InfoMarker {
    /// Block start.
    On,
    /// Block end.
    Off,
}

/// Parsed `%referral rwhois://host:port/auth-area=<area>` URL (RFC §3.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferralUrl {
    /// Host name or IP address.
    pub host: String,
    /// TCP port.
    pub port: u16,
    /// Authority area name (`.` for the root).
    pub auth_area: String,
}

impl ReferralUrl {
    /// Parse a referral URL of the form `rwhois://host:port/auth-area=AREA`.
    #[must_use] 
    pub fn parse(s: &str) -> Option<Self> {
        let rest = s.strip_prefix("rwhois://")?;
        let (hostport, rest) = rest.split_once('/')?;
        let (host, port) = hostport.rsplit_once(':')?;
        let port: u16 = port.parse().ok()?;
        let auth_area = rest.strip_prefix("auth-area=")?;
        Some(Self {
            host: host.to_owned(),
            port,
            auth_area: auth_area.to_owned(),
        })
    }
}

/// Parsed untagged record line (`class:attr[;type]:value`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordLine {
    /// Class name.
    pub class: String,
    /// Attribute name.
    pub attribute: String,
    /// Optional type character (`T`/`I`/`S`).
    pub ty: Option<TypeChar>,
    /// Attribute value (everything after the second `:`).
    pub value: String,
}

impl RecordLine {
    /// Parse a single record line. Returns `None` if the line doesn't match
    /// the dump format (i.e. it isn't `class:attr[;type]:value`).
    #[must_use] 
    pub fn parse(line: &str) -> Option<Self> {
        if line.starts_with('%') || line.is_empty() {
            return None;
        }
        let (class, rest) = line.split_once(':')?;
        let (attr_with_type, value) = rest.split_once(':')?;
        if class.is_empty() || attr_with_type.is_empty() {
            return None;
        }
        let (attribute, ty) = if let Some((a, t)) = attr_with_type.split_once(';') {
            let mut chars = t.chars();
            let c = chars.next()?;
            if chars.next().is_some() {
                return None;
            }
            (a.to_owned(), Some(TypeChar::from_char(c)?))
        } else {
            (attr_with_type.to_owned(), None)
        };
        Some(Self {
            class: class.to_owned(),
            attribute,
            ty,
            value: value.to_owned(),
        })
    }
}

impl ResponseLine {
    /// Parse one trimmed line. The line must NOT include any line
    /// terminator (the codec strips it).
    pub fn parse(line: &str) -> Self {
        if line.is_empty() {
            return ResponseLine::Blank;
        }
        if !line.starts_with('%') {
            return RecordLine::parse(line)
                .map_or_else(|| ResponseLine::FreeForm(line.to_owned()), ResponseLine::Record);
        }
        // Tagged line. Split off the tag token.
        let (tag_tok, body) = match line.find(' ') {
            Some(i) => (&line[..i], line[i + 1..].trim_start_matches(' ')),
            None => (line, ""),
        };

        // %ok / %error short-circuits.
        if tag_tok == "%ok" {
            return ResponseLine::Ok;
        }
        if tag_tok == "%error" {
            return parse_error_body(body);
        }

        if tag_tok == "%info" {
            return match body {
                "on" => ResponseLine::InfoMarker(InfoMarker::On),
                "off" => ResponseLine::InfoMarker(InfoMarker::Off),
                _ => ResponseLine::Tagged {
                    tag: Tag::Info,
                    body: body.to_owned(),
                },
            };
        }

        if tag_tok == "%referral" {
            if let Some(u) = ReferralUrl::parse(body) {
                return ResponseLine::Referral(u);
            }
            return ResponseLine::Tagged {
                tag: Tag::Referral,
                body: body.to_owned(),
            };
        }

        if let Some(tag) = Tag::from_token(tag_tok) {
            if body.is_empty() {
                ResponseLine::TaggedEnd(tag)
            } else {
                ResponseLine::Tagged {
                    tag,
                    body: body.to_owned(),
                }
            }
        } else {
            // Anything else (including `%X-foo` extension lines per RFC
            // §3.3.15) surfaces as `UnknownTagged` with the raw `%tag` token
            // intact so consumers can route on prefix.
            ResponseLine::UnknownTagged {
                tag: tag_tok.to_owned(),
                body: body.to_owned(),
            }
        }
    }
}

fn parse_error_body(body: &str) -> ResponseLine {
    let (code_str, rest) = body.split_once(' ').unwrap_or((body, ""));
    let code = code_str.parse::<u16>().unwrap_or(0);
    let (text, extra) = match rest.find(": ") {
        Some(i) => (rest[..i].to_owned(), Some(rest[i + 2..].to_owned())),
        None => (rest.to_owned(), None),
    };
    ResponseLine::Error { code, text, extra }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out_string(buf: &BytesMut) -> &str {
        std::str::from_utf8(buf).unwrap()
    }

    // ---- writer ----

    #[test]
    fn record_attr_format_matches_rfc() {
        // RFC 2167 §3.1.7 example: domain:Auth-Area:rwhois.net
        let mut w = ResponseWriter::new();
        w.record_attr("domain", "Auth-Area", "rwhois.net");
        assert_eq!(w.as_bytes(), b"domain:Auth-Area:rwhois.net\r\n");
    }

    #[test]
    fn typed_record_id_matches_rfc() {
        // RFC 2167 §3.1.7: domain:Server;I:hst-1.rwhois.net
        let mut w = ResponseWriter::new();
        w.record_typed(
            "domain",
            "Server",
            Some(TypeChar::Id),
            "hst-1.rwhois.net",
        );
        assert_eq!(w.as_bytes(), b"domain:Server;I:hst-1.rwhois.net\r\n");
    }

    #[test]
    fn typed_record_seealso() {
        let mut w = ResponseWriter::new();
        w.record_typed("network", "Tech-Contact", Some(TypeChar::SeeAlso), "MG305.COM");
        assert_eq!(w.as_bytes(), b"network:Tech-Contact;S:MG305.COM\r\n");
    }

    #[test]
    fn referral_format_matches_rfc() {
        // RFC 2167 §3.1.7
        let mut w = ResponseWriter::new();
        w.referral("master.b.rwhois.net", 4321, "b.rwhois.net");
        assert_eq!(
            w.as_bytes(),
            b"%referral rwhois://master.b.rwhois.net:4321/auth-area=b.rwhois.net\r\n"
        );
    }

    #[test]
    fn end_block_emits_blank_tagged_line() {
        // RFC 2167 §3.3.1: "Every class record must end with an empty %class line."
        let mut w = ResponseWriter::new();
        w.tagged(Tag::Class, "domain:description:Domain information");
        w.tagged(Tag::Class, "domain:version:19970103101232000");
        w.end_block(Tag::Class);
        assert_eq!(
            out_string(&w.as_bytes().into()),
            "%class domain:description:Domain information\r\n\
             %class domain:version:19970103101232000\r\n\
             %class\r\n"
        );
    }

    #[test]
    fn info_block_format() {
        // RFC 2167 §3.1.5
        let mut w = ResponseWriter::new();
        w.info_on();
        w.raw_line("Welcome");
        w.info_off();
        assert_eq!(w.as_bytes(), b"%info on\r\nWelcome\r\n%info off\r\n");
    }

    #[test]
    fn x_ext_writer_emits_prefix_and_body() {
        // RFC 2167 §3.3.15
        let mut w = ResponseWriter::new();
        w.x_ext("date", "2026-01-01");
        w.x_ext("date", "");
        assert_eq!(w.as_bytes(), b"%X-date 2026-01-01\r\n%X-date\r\n");
    }

    #[test]
    fn ok_and_error_writers() {
        let mut buf = BytesMut::new();
        write_ok(&mut buf);
        assert_eq!(&buf[..], b"%ok\r\n");

        let mut buf = BytesMut::new();
        write_error(&mut buf, ResponseCode::NO_OBJECTS_FOUND, None);
        assert_eq!(&buf[..], b"%error 230 No Objects Found\r\n");

        let mut buf = BytesMut::new();
        write_error(
            &mut buf,
            ResponseCode::INVALID_QUERY_SYNTAX,
            Some("bad token"),
        );
        assert_eq!(
            &buf[..],
            b"%error 350 Invalid Query Syntax: bad token\r\n"
        );
    }

    #[test]
    fn error_code_is_three_digit_zero_padded() {
        // Even though no code we ship is < 100, the formatter must guarantee
        // three digits per RFC 2167 §3.1.9: error-code = 3digit.
        let mut buf = BytesMut::new();
        write_error(&mut buf, ResponseCode::new(7, "Test"), None);
        assert_eq!(&buf[..], b"%error 007 Test\r\n");
    }

    // ---- parser ----

    #[test]
    fn parse_ok_and_blank() {
        assert_eq!(ResponseLine::parse("%ok"), ResponseLine::Ok);
        assert_eq!(ResponseLine::parse(""), ResponseLine::Blank);
    }

    #[test]
    fn parse_error_with_and_without_extra() {
        assert_eq!(
            ResponseLine::parse("%error 230 No objects found"),
            ResponseLine::Error {
                code: 230,
                text: "No objects found".into(),
                extra: None,
            }
        );
        assert_eq!(
            ResponseLine::parse("%error 350 Invalid Query Syntax: foo"),
            ResponseLine::Error {
                code: 350,
                text: "Invalid Query Syntax".into(),
                extra: Some("foo".into()),
            }
        );
    }

    #[test]
    fn parse_info_markers() {
        assert_eq!(
            ResponseLine::parse("%info on"),
            ResponseLine::InfoMarker(InfoMarker::On)
        );
        assert_eq!(
            ResponseLine::parse("%info off"),
            ResponseLine::InfoMarker(InfoMarker::Off)
        );
    }

    #[test]
    fn parse_tagged_and_end() {
        assert_eq!(
            ResponseLine::parse("%schema map:attribute:Class-Name"),
            ResponseLine::Tagged {
                tag: Tag::Schema,
                body: "map:attribute:Class-Name".into(),
            }
        );
        assert_eq!(
            ResponseLine::parse("%schema"),
            ResponseLine::TaggedEnd(Tag::Schema)
        );
    }

    #[test]
    fn parse_referral() {
        let line = "%referral rwhois://master.b.rwhois.net:4321/auth-area=b.rwhois.net";
        assert_eq!(
            ResponseLine::parse(line),
            ResponseLine::Referral(ReferralUrl {
                host: "master.b.rwhois.net".into(),
                port: 4321,
                auth_area: "b.rwhois.net".into(),
            })
        );
    }

    #[test]
    fn parse_referral_to_root() {
        let line = "%referral rwhois://rs.internic.net:4321/auth-area=.";
        let parsed = ResponseLine::parse(line);
        match parsed {
            ResponseLine::Referral(u) => assert_eq!(u.auth_area, "."),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_record_line_with_and_without_type() {
        assert_eq!(
            ResponseLine::parse("domain:Auth-Area:rwhois.net"),
            ResponseLine::Record(RecordLine {
                class: "domain".into(),
                attribute: "Auth-Area".into(),
                ty: None,
                value: "rwhois.net".into(),
            })
        );
        assert_eq!(
            ResponseLine::parse("domain:Server;I:hst-1.rwhois.net"),
            ResponseLine::Record(RecordLine {
                class: "domain".into(),
                attribute: "Server".into(),
                ty: Some(TypeChar::Id),
                value: "hst-1.rwhois.net".into(),
            })
        );
    }

    #[test]
    fn parse_unknown_tag_keeps_token() {
        match ResponseLine::parse("%made-up something") {
            ResponseLine::UnknownTagged { tag, body } => {
                assert_eq!(tag, "%made-up");
                assert_eq!(body, "something");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn parse_freeform_for_x_directive_output() {
        // RFC 2167 §3.3.15: -X-* output is `*any-char crlf` — anything that
        // is neither a tagged line nor a record line falls through here.
        match ResponseLine::parse("hello world") {
            ResponseLine::FreeForm(s) => assert_eq!(s, "hello world"),
            other => panic!("unexpected {other:?}"),
        }
    }

    // ---- round trip ----

    #[test]
    fn roundtrip_full_query_response_from_rfc() {
        // RFC 2167 §3.1.7 first example, query response only.
        let mut w = ResponseWriter::new();
        w.record_typed("domain", "ID", None, "dom-1.rwhois.net");
        w.record_attr("domain", "Auth-Area", "rwhois.net");
        w.record_attr("domain", "Class-Name", "domain");
        w.record_attr("domain", "Updated", "19970107201111000");
        w.record_attr("domain", "Domain", "rwhois.net");
        w.record_typed("domain", "Server", Some(TypeChar::Id), "hst-1.rwhois.net");
        w.record_typed("domain", "Server", Some(TypeChar::Id), "hst-2.rwhois.net");
        w.blank_line();
        let mut buf = w.take();
        write_ok(&mut buf);

        let text = std::str::from_utf8(&buf).unwrap();
        let parsed: Vec<ResponseLine> = text
            .split_terminator("\r\n")
            .map(ResponseLine::parse)
            .collect();

        assert_eq!(parsed.last(), Some(&ResponseLine::Ok));
        assert!(matches!(parsed[0], ResponseLine::Record(_)));
        assert!(matches!(parsed[parsed.len() - 2], ResponseLine::Blank));
        assert_eq!(
            parsed.iter().filter(|l| matches!(l, ResponseLine::Record(_))).count(),
            7
        );
    }
}
