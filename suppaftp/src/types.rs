//! # Types
//!
//! The set of valid values for FTP commands

use super::Status;
use std::convert::From;
use std::fmt;
use std::string::FromUtf8Error;
use thiserror::Error;

/// A shorthand for a Result whose error type is always an FtpError.
pub type FtpResult<T> = std::result::Result<T, FtpError>;

/// `FtpError` is a library-global error type to describe the different kinds of
/// errors that might occur while using FTP.
#[derive(Debug, Error)]
pub enum FtpError {
    /// Connection error
    #[error("Connection error: {0}")]
    ConnectionError(std::io::Error),
    /// There was an error with the secure stream
    #[error("Secure error: {0}")]
    SecureError(String),
    /// Unexpected response from remote. The command expected a certain response, but got another one.
    /// This means the ftp server refused to perform your request or there was an error while processing it.
    /// Contains the response data.
    #[error("Invalid response: {0}")]
    UnexpectedResponse(Response),
    /// The response syntax is invalid
    #[error("Response contains an invalid syntax")]
    BadResponse,
    /// The address provided was invalid
    #[error("Invalid address: {0}")]
    InvalidAddress(std::net::AddrParseError),
}

/// Defines a response from the ftp server
#[derive(Clone, Error)]
pub struct Response {
    pub status: Status,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Response");
        d.field("status", &self.status);
        if let Ok(s) = std::str::from_utf8(&self.body) {
            d.field("body", &s);
        }
        else {
            struct Hex<'a>(&'a [u8]);

            impl std::fmt::Debug for Hex<'_> {
                fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                    write!(f,"{:X?}", &self.0)
                }
            }

            d.field("body", &Hex(&self.body));
        }

        d.finish()
    }
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}",
            self.status.code(),
            self.as_string().ok().unwrap_or_default()
        )
    }
}

impl Response {
    /// Instantiates a new `Response`
    pub fn new(status: Status, body: Vec<u8>) -> Self {
        Self { status, body }
    }

    /// Get response as string
    pub fn as_string(&self) -> Result<String, FromUtf8Error> {
        String::from_utf8(self.body.clone()).map(|x| x.trim_end().to_string())
    }
}

/// Text Format Control used in `TYPE` command
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FormatControl {
    /// Default text format control (is NonPrint)
    Default,
    /// Non-print (not destined for printing)
    NonPrint,
    /// Telnet format control (\<CR\>, \<FF\>, etc.)
    Telnet,
    /// ASA (Fortran) Carriage Control
    Asa,
}

impl std::fmt::Display for FormatControl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatControl::Default | FormatControl::NonPrint => f.pad("N"),
            FormatControl::Telnet => f.pad("T"),
            FormatControl::Asa => f.pad("C"),
        }
    }
}

/// File Type used in `TYPE` command
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum FileType {
    /// ASCII text (the argument is the text format control)
    Ascii(FormatControl),
    /// EBCDIC text (the argument is the text format control)
    Ebcdic(FormatControl),
    /// Image,
    Image,
    /// Binary (the synonym to Image)
    Binary,
    /// Local format (the argument is the number of bits in one byte on local machine)
    Local(u8),
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileType::Ascii(fc) => write!(f, "A {}", fc),
            FileType::Ebcdic(fc) => write!(f, "E {}", fc),
            FileType::Image | FileType::Binary => write!(f, "I"),
            FileType::Local(bits) => write!(f, "L {bits}"),
        }
    }
}

/// Connection mode for data channel
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Active,
    Passive,
}


#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn fmt_error() {
        assert_eq!(
            FtpError::ConnectionError(std::io::Error::new(std::io::ErrorKind::NotFound, "omar"))
                .to_string()
                .as_str(),
            "Connection error: omar"
        );
        #[cfg(feature = "secure")]
        assert_eq!(
            FtpError::SecureError("omar".to_string())
                .to_string()
                .as_str(),
            "Secure error: omar"
        );
        assert_eq!(
            FtpError::UnexpectedResponse(Response::new(
                Status::ExceededStorage,
                "error".as_bytes().to_vec()
            ))
            .to_string()
            .as_str(),
            "Invalid response: [552] error"
        );
        assert_eq!(
            FtpError::BadResponse.to_string().as_str(),
            "Response contains an invalid syntax"
        );
    }

    #[test]
    fn response() {
        let response: Response = Response::new(Status::AboutToSend, "error".as_bytes().to_vec());
        assert_eq!(response.status, Status::AboutToSend);
        assert_eq!(response.as_string().unwrap(), "error");
    }

    #[test]
    fn fmt_response() {
        let response: Response = Response::new(
            Status::FileUnavailable,
            "Can't create directory: File exists".as_bytes().to_vec(),
        );
        assert_eq!(
            response.to_string().as_str(),
            "[550] Can't create directory: File exists"
        );
    }

    #[test]
    fn fmt_format_control() {
        assert_eq!(FormatControl::Asa.to_string().as_str(), "C");
        assert_eq!(FormatControl::Telnet.to_string().as_str(), "T");
        assert_eq!(FormatControl::Default.to_string().as_str(), "N");
        assert_eq!(FormatControl::NonPrint.to_string().as_str(), "N");
    }

    #[test]
    fn fmt_file_type() {
        assert_eq!(
            FileType::Ascii(FormatControl::Telnet).to_string().as_str(),
            "A T"
        );
        assert_eq!(FileType::Binary.to_string().as_str(), "I");
        assert_eq!(FileType::Image.to_string().as_str(), "I");
        assert_eq!(
            FileType::Ebcdic(FormatControl::Telnet).to_string().as_str(),
            "E T"
        );
        assert_eq!(FileType::Local(2).to_string().as_str(), "L 2");
    }
}
