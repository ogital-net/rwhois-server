//! Line-oriented codec for the `RWhois` wire protocol (RFC 2167 §3.1.9).
//!
//! ## Inbound (decoder)
//!
//! Tolerant by design — accepts either bare `LF` or `CRLF` line terminators
//! and strips ASCII control bytes from the payload to mirror the reference
//! server's `strip_control` + `trim` pre-processing
//! (`ref/rwhoisd/common/misc.c`). RFC 2167 §3.1.9 defines `any-char` as ASCII
//! 1..255 except `LF` and `CR`, so any control byte appearing inside a line
//! is discarded rather than rejected.
//!
//! ## Outbound (encoder)
//!
//! Always writes RFC 2167 §3.1.9 compliant `CRLF` terminators (the C
//! reference emits bare `LF`; we follow the RFC).
//!
//! ## Limits
//!
//! Lines are capped at [`crate::MAX_LINE`] bytes including the terminator.

use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use crate::{Error, MAX_LINE};

/// CRLF terminator written by the encoder (RFC 2167 §3.1.9).
pub const CRLF: &[u8] = b"\r\n";

/// `tokio-util` codec splitting an inbound byte stream into trimmed text
/// lines and writing outbound lines with CRLF terminators.
#[derive(Debug, Clone)]
pub struct RwhoisCodec {
    max_line: usize,
    next_index: usize,
}

impl RwhoisCodec {
    /// Build a codec capped at [`crate::MAX_LINE`] bytes per line.
    #[must_use] 
    pub fn new() -> Self {
        Self::with_max_line(MAX_LINE)
    }

    /// Build a codec with a custom maximum line length (bytes).
    #[must_use] 
    pub fn with_max_line(max_line: usize) -> Self {
        Self {
            max_line,
            next_index: 0,
        }
    }

    /// Configured max line length (bytes), including the CRLF terminator.
    #[must_use] 
    pub fn max_line(&self) -> usize {
        self.max_line
    }
}

impl Default for RwhoisCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for RwhoisCodec {
    type Item = String;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<String>, Error> {
        if let Some(rel) = src[self.next_index..].iter().position(|b| *b == b'\n') {
            let newline_pos = self.next_index + rel;
            if newline_pos + 1 > self.max_line {
                return Err(Error::LineTooLong { max: self.max_line });
            }
            let line_end = if newline_pos > 0 && src[newline_pos - 1] == b'\r' {
                newline_pos - 1
            } else {
                newline_pos
            };
            let raw = src.split_to(newline_pos + 1);
            self.next_index = 0;

            // Strip control characters (matches strip_control in the C ref).
            // RFC 2167 §3.1.9 defines `any-char` as ASCII 1..127; any non-ASCII
            // byte is a protocol error rather than something to silently
            // re-encode, so reject 0x80..=0xff to keep the resulting `String`
            // a faithful 1:1 representation of the line on the wire.
            let mut out = String::with_capacity(line_end);
            for &b in &raw[..line_end] {
                if b >= 0x80 {
                    return Err(Error::protocol(
                        crate::ResponseCode::INVALID_QUERY_SYNTAX,
                        "non-ASCII byte in line",
                    ));
                }
                if b == b'\t' || b >= 0x20 {
                    out.push(b as char);
                }
            }
            let trimmed = out
                .trim_matches(|c: char| c == ' ' || c == '\t')
                .to_owned();
            Ok(Some(trimmed))
        } else if src.len() > self.max_line {
            Err(Error::LineTooLong { max: self.max_line })
        } else {
            self.next_index = src.len();
            Ok(None)
        }
    }
}

impl Encoder<&[u8]> for RwhoisCodec {
    type Error = Error;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> Result<(), Error> {
        if item.len() + CRLF.len() > self.max_line {
            return Err(Error::LineTooLong { max: self.max_line });
        }
        if item.iter().any(|&b| b == b'\r' || b == b'\n') {
            return Err(Error::protocol(
                crate::ResponseCode::UNIDENTIFIED_ERROR,
                "line contains embedded CR or LF",
            ));
        }
        dst.reserve(item.len() + CRLF.len());
        dst.put_slice(item);
        dst.put_slice(CRLF);
        Ok(())
    }
}

impl Encoder<String> for RwhoisCodec {
    type Error = Error;

    fn encode(&mut self, item: String, dst: &mut BytesMut) -> Result<(), Error> {
        <Self as Encoder<&[u8]>>::encode(self, item.as_bytes(), dst)
    }
}

impl Encoder<&str> for RwhoisCodec {
    type Error = Error;

    fn encode(&mut self, item: &str, dst: &mut BytesMut) -> Result<(), Error> {
        <Self as Encoder<&[u8]>>::encode(self, item.as_bytes(), dst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(input: &[u8]) -> Vec<String> {
        let mut codec = RwhoisCodec::new();
        let mut buf = BytesMut::from(input);
        let mut out = Vec::new();
        while let Some(line) = codec.decode(&mut buf).unwrap() {
            out.push(line);
        }
        out
    }

    #[test]
    fn decodes_lf_line() {
        assert_eq!(dec(b"-quit\n"), vec!["-quit"]);
    }

    #[test]
    fn decodes_crlf_line() {
        assert_eq!(dec(b"-quit\r\n"), vec!["-quit"]);
    }

    #[test]
    fn decodes_multiple_lines_in_one_buffer() {
        assert_eq!(
            dec(b"-rwhois V-1.5\r\n-holdconnect on\r\n-quit\r\n"),
            vec!["-rwhois V-1.5", "-holdconnect on", "-quit"]
        );
    }

    #[test]
    fn empty_line_decodes_to_empty_string() {
        assert_eq!(dec(b"\r\n"), vec![""]);
    }

    #[test]
    fn strips_embedded_control_bytes_keeps_tab() {
        // BEL (0x07) and NUL (0x00) are stripped; tab survives.
        let mut codec = RwhoisCodec::new();
        let mut buf = BytesMut::from(&b"foo\x07\tbar\x00baz\n"[..]);
        let line = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(line, "foo\tbarbaz");
    }

    #[test]
    fn trims_surrounding_whitespace() {
        let mut codec = RwhoisCodec::new();
        let mut buf = BytesMut::from(&b"   -quit   \r\n"[..]);
        let line = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(line, "-quit");
    }

    #[test]
    fn partial_line_returns_none_then_completes() {
        let mut codec = RwhoisCodec::new();
        let mut buf = BytesMut::from(&b"-quit"[..]);
        assert!(codec.decode(&mut buf).unwrap().is_none());
        buf.extend_from_slice(b"\r\n");
        let line = codec.decode(&mut buf).unwrap().unwrap();
        assert_eq!(line, "-quit");
    }

    #[test]
    fn rejects_line_longer_than_max() {
        let mut codec = RwhoisCodec::with_max_line(16);
        let mut buf = BytesMut::from(&b"this-is-a-very-long-line\r\n"[..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(Error::LineTooLong { max: 16 })
        ));
    }

    #[test]
    fn rejects_non_ascii_byte() {
        let mut codec = RwhoisCodec::new();
        let mut buf = BytesMut::from(&b"foo\xc3\xa9bar\r\n"[..]);
        assert!(matches!(
            codec.decode(&mut buf),
            Err(Error::Protocol { .. })
        ));
    }

    #[test]
    fn encodes_crlf() {
        let mut codec = RwhoisCodec::new();
        let mut buf = BytesMut::new();
        codec.encode("%ok".to_string(), &mut buf).unwrap();
        assert_eq!(&buf[..], b"%ok\r\n");
    }

    #[test]
    fn encoder_rejects_embedded_newline() {
        let mut codec = RwhoisCodec::new();
        let mut buf = BytesMut::new();
        assert!(codec.encode("foo\nbar", &mut buf).is_err());
        assert!(codec.encode("foo\rbar", &mut buf).is_err());
    }

    #[test]
    fn encoder_rejects_oversize() {
        let mut codec = RwhoisCodec::with_max_line(8);
        let mut buf = BytesMut::new();
        assert!(matches!(
            codec.encode("0123456789", &mut buf),
            Err(Error::LineTooLong { max: 8 })
        ));
    }
}
