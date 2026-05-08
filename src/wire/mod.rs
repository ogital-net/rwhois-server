//! Wire-level types: parsed inbound messages, response code table, response
//! builders/parsers, and the `%rwhois` banner.

pub mod banner;
pub mod code;
pub mod request;
pub mod response;

pub use banner::{Banner, Capability, Version};
pub use code::ResponseCode;
pub use request::Request;
pub use response::{
    write_error, write_ok, InfoMarker, RecordLine, ReferralUrl, ResponseLine, ResponseWriter,
    Tag, TypeChar,
};
