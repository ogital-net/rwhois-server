//! `RWhois` response codes.
//!
//! Mirrors the table in `ref/rwhoisd/common/client_msgs.c`.

/// Numeric response code accompanied by its canonical message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseCode {
    /// Three-digit code as transmitted on the wire.
    pub code: u16,
    /// Default message text; overridable per-call.
    pub message: &'static str,
}

impl ResponseCode {
    /// Construct an arbitrary response code.
    #[must_use] 
    pub const fn new(code: u16, message: &'static str) -> Self {
        Self { code, message }
    }
}

macro_rules! codes {
    ($($name:ident = ($code:expr, $msg:expr);)*) => {
        impl ResponseCode {
            $(
                #[allow(missing_docs)]
                pub const $name: ResponseCode = ResponseCode::new($code, $msg);
            )*
        }
    };
}

codes! {
    REGISTRATION_DEFERRED      = (120, "Registration Deferred");
    OBJECT_NOT_AUTHORITATIVE   = (130, "Object not authoritative");
    NO_OBJECTS_FOUND           = (230, "No Objects Found");
    NOT_COMPATIBLE_VERSION     = (300, "Not Compatible With Version");
    INVALID_ATTRIBUTE          = (320, "Invalid Attribute");
    INVALID_ATTRIBUTE_SYNTAX   = (321, "Invalid Attribute Syntax");
    REQUIRED_ATTRIBUTE_MISSING = (322, "Required Attribute Missing");
    OBJECT_REF_NOT_FOUND       = (323, "Object Reference Not Found");
    PRIMARY_KEY_NOT_UNIQUE     = (324, "Primary Key Not Unique");
    OUTDATED_OBJECT            = (325, "Failed to Update Outdated Object");
    EXCEEDED_MAX_OBJECTS       = (330, "Exceeded Max Objects Limit");
    INVALID_LIMIT              = (331, "Invalid Limit");
    NOTHING_TO_TRANSFER        = (332, "Nothing To Transfer");
    NOT_MASTER                 = (333, "Not Master for Authority Area");
    INVALID_DIRECTIVE_SYNTAX   = (338, "Invalid Directive Syntax");
    INVALID_AUTH_AREA          = (340, "Invalid Authority Area");
    INVALID_CLASS              = (341, "Invalid Class");
    INVALID_HOST_PORT          = (342, "Invalid Host/Port");
    INVALID_QUERY_SYNTAX       = (350, "Invalid Query Syntax");
    QUERY_TOO_COMPLEX          = (351, "Query Too Complex");
    INVALID_SECURITY_METHOD    = (352, "Invalid Security Method");
    AUTHENTICATION_FAILED      = (353, "Authentication Failed");
    ENCRYPTION_FAILED          = (354, "Encryption Failed");
    CORRUPT_DATA               = (360, "Corrupt Data. Keyadd Failed");
    DIRECTIVE_NOT_AVAILABLE    = (400, "Directive Not Available");
    NOT_AUTHORIZED             = (401, "Not Authorized for Directive");
    UNIDENTIFIED_ERROR         = (402, "Unidentified Error");
    REGISTRATION_NOT_AUTHORIZED= (420, "Registration Not Authorized");
    INVALID_DISPLAY_FORMAT     = (436, "Invalid Display Format");
    MEMORY_ALLOCATION          = (500, "Memory Allocation Problem");
    SERVICE_NOT_AVAILABLE      = (501, "Service Not Available");
    UNRECOVERABLE_ERROR        = (502, "Unrecoverable Error");
    IDLE_TIME_EXCEEDED         = (503, "Idle Time Exceeded");
    MISC_DIAGNOSTIC            = (560, "");
}
