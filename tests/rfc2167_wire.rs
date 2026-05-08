//! Full end-to-end RFC 2167 transcript tests for the wire layer.
//!
//! Each test feeds a verbatim transcript from RFC 2167 §3 through the codec
//! and the response/banner parsers, asserting that every line classifies as
//! the RFC expects.

use bytes::BytesMut;
use rwhois::codec::RwhoisCodec;
use rwhois::query::{Expr, Query, Term, Value, ValueKind};
use rwhois::wire::{
    Banner, Capability, InfoMarker, RecordLine, ReferralUrl, ResponseLine, Tag, TypeChar,
};
use tokio_util::codec::Decoder;

/// Decode a CRLF-terminated transcript into a sequence of trimmed lines.
fn decode_all(input: &[u8]) -> Vec<String> {
    let mut codec = RwhoisCodec::new();
    let mut buf = BytesMut::from(input);
    let mut out = Vec::new();
    while let Some(line) = codec.decode(&mut buf).unwrap() {
        out.push(line);
    }
    out
}

#[test]
fn rfc_3_1_7_successful_query_transcript() {
    // RFC 2167 §3.1.7 first example.
    let transcript = b"\
%rwhois V-1.5:00ffff:00 master.rwhois.net (Network Solutions V-1.5)\r\n\
domain:ID:dom-1.rwhois.net\r\n\
domain:Auth-Area:rwhois.net\r\n\
domain:Class-Name:domain\r\n\
domain:Updated:19970107201111000\r\n\
domain:Domain:rwhois.net\r\n\
domain:Server;I:hst-1.rwhois.net\r\n\
domain:Server;I:hst-2.rwhois.net\r\n\
\r\n\
%ok\r\n";

    let lines = decode_all(transcript);

    // 1st line is the banner.
    let banner = Banner::parse(&lines[0]).unwrap();
    assert_eq!(banner.hostname, "master.rwhois.net");
    assert_eq!(banner.versions.len(), 1);
    assert_eq!(
        banner.versions[0].capability,
        Some(Capability::new(0x00ffff, 0x00))
    );

    // Lines 1..=7 are records.
    for (i, expected) in [
        ("ID", None, "dom-1.rwhois.net"),
        ("Auth-Area", None, "rwhois.net"),
        ("Class-Name", None, "domain"),
        ("Updated", None, "19970107201111000"),
        ("Domain", None, "rwhois.net"),
        ("Server", Some(TypeChar::Id), "hst-1.rwhois.net"),
        ("Server", Some(TypeChar::Id), "hst-2.rwhois.net"),
    ]
    .iter()
    .enumerate()
    {
        let parsed = ResponseLine::parse(&lines[i + 1]);
        assert_eq!(
            parsed,
            ResponseLine::Record(RecordLine {
                class: "domain".into(),
                attribute: expected.0.into(),
                ty: expected.1,
                value: expected.2.into(),
            })
        );
    }

    // Blank record terminator then %ok.
    assert_eq!(ResponseLine::parse(&lines[8]), ResponseLine::Blank);
    assert_eq!(ResponseLine::parse(&lines[9]), ResponseLine::Ok);
}

#[test]
fn rfc_3_1_7_referral_transcript() {
    // RFC 2167 §3.1.7 second example: link + punt referrals interleaved
    // with -holdconnect and -quit directives.
    let transcript = b"\
%rwhois V-1.5:00ffff:00 master.rwhois.net (Network Solutions V-1.5)\r\n\
%ok\r\n\
%referral rwhois://master.b.rwhois.net:4321/auth-area=b.rwhois.net\r\n\
%ok\r\n\
%referral rwhois://rs.internic.net:4321/auth-area=.\r\n\
%ok\r\n\
%ok\r\n";

    let lines = decode_all(transcript);
    assert!(Banner::parse(&lines[0]).is_some());
    assert_eq!(ResponseLine::parse(&lines[1]), ResponseLine::Ok);
    assert_eq!(
        ResponseLine::parse(&lines[2]),
        ResponseLine::Referral(ReferralUrl {
            host: "master.b.rwhois.net".into(),
            port: 4321,
            auth_area: "b.rwhois.net".into(),
        })
    );
    assert_eq!(ResponseLine::parse(&lines[3]), ResponseLine::Ok);
    assert_eq!(
        ResponseLine::parse(&lines[4]),
        ResponseLine::Referral(ReferralUrl {
            host: "rs.internic.net".into(),
            port: 4321,
            auth_area: ".".into(),
        })
    );
    assert_eq!(ResponseLine::parse(&lines[5]), ResponseLine::Ok);
    assert_eq!(ResponseLine::parse(&lines[6]), ResponseLine::Ok);
}

#[test]
fn rfc_3_1_7_error_transcript() {
    // RFC 2167 §3.1.7 third example: 230 No objects found.
    let lines = decode_all(
        b"\
%rwhois V-1.5:00ffff:00 master.rwhois.net (Network Solutions V-1.5)\r\n\
%error 230 No objects found\r\n",
    );
    assert!(Banner::parse(&lines[0]).is_some());
    assert_eq!(
        ResponseLine::parse(&lines[1]),
        ResponseLine::Error {
            code: 230,
            text: "No objects found".into(),
            extra: None,
        }
    );
}

#[test]
fn rfc_3_3_1_class_response_blocks() {
    // RFC 2167 §3.3.1 example: two %class records terminated by blank %class,
    // followed by %ok.
    let lines = decode_all(
        b"\
%class domain:description:Domain information\r\n\
%class domain:version:19970103101232000\r\n\
%class\r\n\
%class host:description:Host information\r\n\
%class host:version:19970214213241000\r\n\
%class\r\n\
%ok\r\n",
    );
    assert_eq!(
        ResponseLine::parse(&lines[0]),
        ResponseLine::Tagged {
            tag: Tag::Class,
            body: "domain:description:Domain information".into(),
        }
    );
    assert_eq!(
        ResponseLine::parse(&lines[2]),
        ResponseLine::TaggedEnd(Tag::Class)
    );
    assert_eq!(
        ResponseLine::parse(&lines[5]),
        ResponseLine::TaggedEnd(Tag::Class)
    );
    assert_eq!(ResponseLine::parse(&lines[6]), ResponseLine::Ok);
}

#[test]
fn rfc_3_1_5_info_block() {
    let lines = decode_all(b"%info on\r\nWelcome to rwhois\r\n%info off\r\n");
    assert_eq!(
        ResponseLine::parse(&lines[0]),
        ResponseLine::InfoMarker(InfoMarker::On)
    );
    assert_eq!(
        ResponseLine::parse(&lines[1]),
        ResponseLine::FreeForm("Welcome to rwhois".into())
    );
    assert_eq!(
        ResponseLine::parse(&lines[2]),
        ResponseLine::InfoMarker(InfoMarker::Off)
    );
}

#[test]
fn rfc_3_4_query_examples_parse_correctly() {
    // RFC 2167 §3.4: `ibm and jubliana*`.
    let q = Query::parse("ibm and jubliana*").unwrap();
    assert_eq!(
        q.expr,
        Expr::And(
            Box::new(Expr::Term(Term::Value(Value {
                text: "ibm".into(),
                kind: ValueKind::Exact,
            }))),
            Box::new(Expr::Term(Term::Value(Value {
                text: "jubliana".into(),
                kind: ValueKind::Prefix,
            }))),
        )
    );

    // RFC 2167 §3.4: attribute query example.
    let q = Query::parse("Domain-Name=konabo.com").unwrap();
    assert_eq!(
        q.expr,
        Expr::Term(Term::AttrEq {
            attr: "Domain-Name".into(),
            value: Value {
                text: "konabo.com".into(),
                kind: ValueKind::Exact,
            },
        })
    );

    // RFC 2167 §3.3.7: contact Last-Name="Beeblebrox" — implicit AND of
    // class token and attribute query (until a class predicate lifts it).
    let q = Query::parse(r#"contact Last-Name="Beeblebrox""#).unwrap();
    match &q.expr {
        Expr::And(_, r) => {
            assert!(matches!(r.as_ref(), Expr::Term(Term::AttrEq { .. })));
        }
        _ => panic!("expected implicit AND tree"),
    }
    let lifted = q.with_class_if(|t| t == "contact");
    assert_eq!(lifted.class.as_deref(), Some("contact"));
    assert!(matches!(lifted.expr, Expr::Term(Term::AttrEq { .. })));
}
