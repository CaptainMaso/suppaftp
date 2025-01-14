//! # Command
//!
//! The set of FTP commands

use crate::types::FileType;

use std::{net::SocketAddr, borrow::Cow};

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(unused)]
/// Protection level; argument for `Prot` command
pub enum ProtectionLevel {
    Clear,
    Private,
}

impl std::fmt::Display for ProtectionLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtectionLevel::Clear => f.pad("C"),
            ProtectionLevel::Private => f.pad("P"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Ftp commands with their arguments
pub enum Command<'a> {
    /// Abort an active file transfer
    Abor,
    /// Append to file
    Appe(Cow<'a,str>),
    /// Set auth to TLS
    Auth,
    /// Ask server not to encrypt command channel
    ClearCommandChannel,
    /// Change directory to parent directory
    Cdup,
    /// Change working directory
    Cwd(Cow<'a,str>),
    /// Remove file at specified path
    Dele(Cow<'a,str>),
    /// Allows specification for protocol and address for data connections
    Eprt(SocketAddr),
    /// Extended passive mode <https://www.rfc-editor.org/rfc/rfc2428#section-3>
    Epsv,
    /// List entries at specified path. If path is not provided list entries at current working directory
    List(Option<Cow<'a,str>>),
    /// Get modification time for file at specified path
    Mdtm(Cow<'a,str>),
    /// Make directory
    Mkd(Cow<'a,str>),
    /// Get the list of file names at specified path. If path is not provided list entries at current working directory
    Nlst(Option<Cow<'a,str>>),
    /// Ping server
    Noop,
    /// Provide login password
    Pass(Cow<'a,str>),
    /// Passive mode
    Pasv,
    /// Protection buffer size
    Pbsz(usize),
    /// Specifies an address and port to which the server should connect (active mode)
    Port(std::net::SocketAddrV4),
    /// Set protection level for protocol
    Prot(ProtectionLevel),
    /// Print working directory
    Pwd,
    /// Quit
    Quit,
    /// Select file to rename
    RenameFrom(Cow<'a,str>),
    /// Rename selected file to
    RenameTo(Cow<'a,str>),
    /// Resume transfer from offset
    Rest(usize),
    /// Retrieve file
    Retr(Cow<'a,str>),
    /// Remove directory
    Rmd(Cow<'a,str>),
    /// Get file size of specified path
    Size(Cow<'a,str>),
    /// Put file at specified path
    Store(Cow<'a,str>),
    /// Set transfer type
    Type(FileType),
    /// Provide user to login as
    User(Cow<'a,str>),
}

impl Command<'_> {
    pub fn into_static(self) -> Command<'static> {
        match self {
            Command::Abor => Command::Abor,
            Command::Appe(s) => Command::Appe(s.into_owned().into()),
            Command::Auth => Command::Auth,
            Command::ClearCommandChannel => Command::ClearCommandChannel,
            Command::Cdup => Command::Cdup,
            Command::Cwd(s) => Command::Cwd(s.into_owned().into()),
            Command::Dele(s) => Command::Dele(s.into_owned().into()),
            Command::Eprt(s) => Command::Eprt(s),
            Command::Epsv => Command::Epsv,
            Command::List(s) => Command::List(s.map(|s| s.into_owned().into())),
            Command::Mdtm(s) => Command::Mdtm(s.into_owned().into()),
            Command::Mkd(s) => Command::Mkd(s.into_owned().into()),
            Command::Nlst(s) => Command::Nlst(s.map(|s| s.into_owned().into())),
            Command::Noop => Command::Noop,
            Command::Pass(s) => Command::Pass(s.into_owned().into()),
            Command::Pasv => Command::Pasv,
            Command::Pbsz(s) => Command::Pbsz(s),
            Command::Port(s) => Command::Port(s),
            Command::Prot(s) => Command::Prot(s),
            Command::Pwd => Command::Pwd,
            Command::Quit => Command::Quit,
            Command::RenameFrom(s) => Command::RenameFrom(s.into_owned().into()),
            Command::RenameTo(s) => Command::RenameTo(s.into_owned().into()),
            Command::Rest(s) => Command::Rest(s),
            Command::Retr(s) => Command::Retr(s.into_owned().into()),
            Command::Rmd(s) => Command::Rmd(s.into_owned().into()),
            Command::Size(s) => Command::Size(s.into_owned().into()),
            Command::Store(s) => Command::Store(s.into_owned().into()),
            Command::Type(s) => Command::Type(s),
            Command::User(s) => Command::User(s.into_owned().into()),
        }
    }
}

impl std::fmt::Display for Command<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Abor => write!(f, "ABOR"),
            Self::Appe(p) => write!(f, "APPE {p}"),
            Self::Auth => write!(f,"AUTH TLS"),
            Self::Cdup => write!(f,"CDUP"),
            Self::ClearCommandChannel => write!(f,"CCC"),
            Self::Cwd(d) => write!(f, "CWD {d}"),
            Self::Dele(p) => write!(f, "DELE {p}"),
            Self::Eprt(addr) => {
                let (id,addr,port) : (usize,&dyn std::fmt::Display,u16)= match addr {
                    SocketAddr::V4(addr) => (1,addr.ip(),addr.port()),
                    SocketAddr::V6(addr) => (2,addr.ip(),addr.port()),
                };

                write!(f,"EPRT |{id}|{addr}|{port}|")
            },
            Self::Epsv => write!(f,"EPSV"),
            Self::List(Some(p)) => write!(f, "LIST {p}"),
            Self::List(None) => write!(f, "LIST"),
            Self::Mdtm(p) => write!(f, "MDTM {p}"),
            Self::Mkd(p) => write!(f, "MKD {p}"),
            Self::Nlst(Some(p)) => write!(f, "NLST {p}"),
            Self::Nlst(None) => write!(f, "NLST"),
            Self::Noop => write!(f, "NOOP"),
            Self::Pass(p) => write!(f, "PASS {p}"),
            Self::Pasv => write!(f, "PASV"),
            Self::Pbsz(sz) => write!(f, "PBSZ {sz}"),
            Self::Port(addr) => {
                let msb = addr.port() / 256;
                let lsb = addr.port() % 256;
                let oct = addr.ip().octets();

                write!(f, "PORT {},{},{},{},{},{}", oct[0],oct[1],oct[2],oct[3], msb, lsb)
            },
            Self::Prot(l) => write!(f, "PROT {l}"),
            Self::Pwd => write!(f, "PWD"),
            Self::Quit => write!(f, "QUIT"),
            Self::RenameFrom(p) => write!(f, "RNFR {p}"),
            Self::RenameTo(p) => write!(f, "RNTO {p}"),
            Self::Rest(offset) => write!(f, "REST {offset}"),
            Self::Retr(p) => write!(f, "RETR {p}"),
            Self::Rmd(p) => write!(f, "RMD {p}"),
            Self::Size(p) => write!(f, "SIZE {p}"),
            Self::Store(p) => write!(f, "STOR {p}"),
            Self::Type(t) => write!(f, "TYPE {t}"),
            Self::User(u) => write!(f, "USER {u}"),
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use pretty_assertions::assert_eq;

    #[test]
    fn should_stringify_command() {
        assert_eq!(Command::Abor.to_string().as_str(), "ABOR");
        assert_eq!(
            Command::Appe("foobar.txt".into())
                .to_string()
                .as_str(),
            "APPE foobar.txt"
        );
        assert_eq!(Command::Auth.to_string().as_str(), "AUTH TLS");
        assert_eq!(Command::ClearCommandChannel.to_string().as_str(), "CCC");
        assert_eq!(Command::Cdup.to_string().as_str(), "CDUP");
        assert_eq!(
            Command::Cwd("/tmp".into()).to_string().as_str(),
            "CWD /tmp"
        );
        assert_eq!(
            Command::Dele("a.txt".into()).to_string().as_str(),
            "DELE a.txt"
        );
        assert_eq!(
            Command::Eprt(SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(127, 0, 0, 1),
                8080
            )))
            .to_string()
            .as_str(),
            "EPRT |1|127.0.0.1|8080|"
        );
        assert_eq!(
            Command::Eprt(SocketAddr::V6(std::net::SocketAddrV6::new(
                std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                8080,
                0,
                0
            )))
            .to_string()
            .as_str(),
            "EPRT |2|2001:db8::1|8080|"
        );
        assert_eq!(Command::Epsv.to_string().as_str(), "EPSV");
        assert_eq!(
            Command::List(Some("/tmp".into()))
                .to_string()
                .as_str(),
            "LIST /tmp"
        );
        assert_eq!(Command::List(None).to_string().as_str(), "LIST");
        assert_eq!(
            Command::Mdtm("a.txt".into()).to_string().as_str(),
            "MDTM a.txt"
        );
        assert_eq!(
            Command::Mkd("/tmp".into()).to_string().as_str(),
            "MKD /tmp"
        );
        assert_eq!(
            Command::Nlst(Some("/tmp".into()))
                .to_string()
                .as_str(),
            "NLST /tmp"
        );
        assert_eq!(Command::Nlst(None).to_string().as_str(), "NLST");
        assert_eq!(Command::Noop.to_string().as_str(), "NOOP");
        assert_eq!(
            Command::Pass("qwerty123".into())
                .to_string()
                .as_str(),
            "PASS qwerty123"
        );
        assert_eq!(Command::Pasv.to_string().as_str(), "PASV");
        assert_eq!(Command::Pbsz(0).to_string().as_str(), "PBSZ 0");
        assert_eq!(
            Command::Port(std::net::SocketAddrV4::new([0,0,0,0].into(),21))
                .to_string()
                .as_str(),
            "PORT 0,0,0,0,0,21"
        );
        assert_eq!(
            Command::Port(std::net::SocketAddrV4::new([0,0,0,0].into(),10021))
                .to_string()
                .as_str(),
            "PORT 0,0,0,0,39,37"
        );
        assert_eq!(
            Command::Prot(ProtectionLevel::Clear).to_string().as_str(),
            "PROT C"
        );
        assert_eq!(Command::Pwd.to_string().as_str(), "PWD");
        assert_eq!(Command::Quit.to_string().as_str(), "QUIT");
        assert_eq!(
            Command::RenameFrom("a.txt".into())
                .to_string()
                .as_str(),
            "RNFR a.txt"
        );
        assert_eq!(
            Command::RenameTo("b.txt".into())
                .to_string()
                .as_str(),
            "RNTO b.txt"
        );
        assert_eq!(Command::Rest(123).to_string().as_str(), "REST 123");
        assert_eq!(
            Command::Retr("a.txt".into()).to_string().as_str(),
            "RETR a.txt"
        );
        assert_eq!(
            Command::Rmd("/tmp".into()).to_string().as_str(),
            "RMD /tmp"
        );
        assert_eq!(
            Command::Size("a.txt".into()).to_string().as_str(),
            "SIZE a.txt"
        );
        assert_eq!(
            Command::Store("a.txt".into()).to_string().as_str(),
            "STOR a.txt"
        );
        assert_eq!(
            Command::Type(FileType::Binary).to_string().as_str(),
            "TYPE I"
        );
        assert_eq!(
            Command::User("omar".into()).to_string().as_str(),
            "USER omar"
        );
    }

    #[test]
    fn should_stringify_protection_level() {
        assert_eq!(ProtectionLevel::Clear.to_string().as_str(), "C");
        assert_eq!(ProtectionLevel::Private.to_string().as_str(), "P");
    }
}
