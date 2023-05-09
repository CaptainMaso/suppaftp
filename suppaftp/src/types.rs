//! # Types
//!
//! The set of valid values for FTP commands

use super::Status;
use std::fmt;
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
    UnexpectedResponse(CompleteResponse),
    /// The response syntax is invalid
    #[error("Response contains an invalid syntax")]
    BadResponse,
    /// The address provided was invalid
    #[error("Invalid address: {0}")]
    InvalidAddress(std::net::AddrParseError),
}

impl From<std::io::Error> for FtpError {
    fn from(value: std::io::Error) -> Self {
        Self::ConnectionError(value)
    }
}

#[derive(Debug,Clone)]
pub struct CompleteResponse {
    pub command : Option<super::command::Command<'static>>,
    pub status : Status,
    pub lines : Vec<String>
}

impl fmt::Display for CompleteResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(&format!("Status: {}\n", self.status))?;

        for l in &self.lines {
            f.pad(l.trim_end())?;
        }

        Ok(())
    }
}

impl CompleteResponse {
    pub fn lines(&self) -> impl Iterator<Item = &str> {
        self.lines.iter().map(|s| &**s)
    }

    pub fn body(&self) -> String {
        self.lines.join("\n")
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
            FtpError::BadResponse.to_string().as_str(),
            "Response contains an invalid syntax"
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
