//! # Data Stream
//!
//! This module exposes the data stream where bytes must be written to/read from
use std::io::{Read, Write, BufRead};
use std::net::{TcpStream, ToSocketAddrs};

use crate::{FtpResult, FtpError};

use super::lines::{Lines, ReadLine};
use super::response::Response;

/// Data Stream used for communications. It can be both of type Tcp in case of plain communication or Ssl in case of FTPS
enum CommandStreamInner {
    Tcp(TcpStream),
    #[cfg(feature="native-tls")]
    NativeTls {
        domain : String,
        connector : native_tls::TlsConnector,
        stream : native_tls::TlsStream<TcpStream>
    },
    #[cfg(feature="rustls")]
    Rustls {
        server_name : rustls::ServerName,
        config : std::sync::Arc<rustls::ClientConfig>,
        stream : Box<rustls::StreamOwned<rustls::ClientConnection,TcpStream>>
    },
}

pub struct CommandStream {
    inner : Lines<CommandStreamInner>
}

impl CommandStream {
    /// Try to connect to the remote server
    pub fn connect<A: ToSocketAddrs>(addr: A) -> FtpResult<Self> {
        trace!("Connecting to server");
        let inner = TcpStream::connect(addr)
            .map_err(FtpError::ConnectionError)
            .map(CommandStreamInner::Tcp)?;

        let inner = Lines::new(inner,std::time::Duration::from_secs(5));

        Ok(Self { inner })
    }

    /// Try to connect to the remote server but with the specified timeout
    pub fn connect_timeout<A : ToSocketAddrs>(addr: A, timeout: std::time::Duration) -> FtpResult<Self> {
        trace!("Connecting to server");
        let inner = tcp_connect_timeout(addr,timeout)
            .map_err(FtpError::ConnectionError)
            .map(CommandStreamInner::Tcp)?;

        let inner = Lines::new(inner,std::time::Duration::from_secs(5));

        Ok(Self { inner })
    }

    pub fn local_addr(&self) -> FtpResult<std::net::SocketAddr> {
        let sock = match &*self.inner {
            CommandStreamInner::Tcp(s) => s.local_addr().map_err(FtpError::ConnectionError)?,
            #[cfg(feature = "native-tls")]
            CommandStreamInner::NativeTls { stream, .. } => {
                stream.get_ref().local_addr().map_err(FtpError::ConnectionError)?
            },
            #[cfg(feature = "rustls")]
            CommandStreamInner::Rustls { stream, .. } => {
                stream.get_ref().local_addr().map_err(FtpError::ConnectionError)?
            },
        };

        Ok(sock)
    }

    pub fn is_secure(&self) -> bool {
        match &*self.inner {
            CommandStreamInner::Tcp(_) => false,
            #[cfg(feature = "native-tls")]
            CommandStreamInner::NativeTls { .. } => true,
            #[cfg(feature = "rustls")]
            CommandStreamInner::Rustls { .. } => true,
        }
    }

    pub fn peer_addr(&self) -> FtpResult<std::net::SocketAddr> {
        let sock = match &*self.inner {
            CommandStreamInner::Tcp(s) => s.peer_addr().map_err(FtpError::ConnectionError)?,
            #[cfg(feature = "native-tls")]
            CommandStreamInner::NativeTls { stream, .. } => {
                stream.get_ref().peer_addr().map_err(FtpError::ConnectionError)?
            },
            #[cfg(feature = "rustls")]
            CommandStreamInner::Rustls { stream, .. } => {
                stream.get_ref().peer_addr().map_err(FtpError::ConnectionError)?
            },
        };

        Ok(sock)
    }

    /// Switch to explicit secure mode using Rustls
    #[cfg(feature = "rustls")]
    pub fn init_rustls(
        self,
        domain: impl std::string::ToString,
        config : rustls::ClientConfig
    ) -> FtpResult<Self> {
        let domain = domain.to_string();
        let config = config.into();
        let timeout = self.inner.timeout();
        let stream = self.into_tcp_stream()?;
        let server_name = rustls::ServerName::try_from(&*domain)
            .map_err(|e| FtpError::SecureError(e.to_string()))?;

        let conn = rustls::ClientConnection::new(std::sync::Arc::clone(&config),server_name.clone())
            .map_err(|e| FtpError::SecureError(e.to_string()))?;

        let stream = Box::new(rustls::StreamOwned::new(conn,stream));

        let inner = CommandStreamInner::Rustls { server_name, config, stream };
        let inner = Lines::new(inner,timeout);

        Ok(Self { inner })
    }

    /// Switch to explicit secure mode using NativeTls
    #[cfg(feature = "native-tls")]
    pub fn init_native_tls(
        self,
        domain: impl std::string::ToString,
        connector : native_tls::TlsConnector
    ) -> FtpResult<Self> {
        let domain = domain.to_string();
        let timeout = self.inner.timeout();
        let stream = self.into_tcp_stream()?;

        let stream = connector.connect(&domain, stream)
            .map_err(|e| FtpError::SecureError(e.to_string()))?;

        let inner = CommandStreamInner::NativeTls { domain, connector, stream };

        let inner = Lines::new(inner,timeout);

        Ok(Self { inner })
    }

    pub fn into_insecure(self) -> FtpResult<Self> {
        let timeout = self.inner.timeout();
        let stream = CommandStreamInner::Tcp(self.into_tcp_stream()?);
        let inner = Lines::new(stream,timeout);
        Ok(Self{ inner })
    }

    /// Unwrap the stream into TcpStream. This method is only used in secure connection.
    pub fn into_tcp_stream(self) -> FtpResult<TcpStream> {
        match self.inner.take() {
            CommandStreamInner::Tcp(stream) => Ok(stream),
            #[cfg(feature="native-tls")]
            CommandStreamInner::NativeTls{ mut stream, .. } => {
                let s = stream.get_ref().try_clone()
                    .map_err(|e| FtpError::SecureError(e.to_string()))?;
                stream.flush()
                    .map_err(FtpError::ConnectionError)?;
                Ok(s)
            },
            #[cfg(feature="rustls")]
            CommandStreamInner::Rustls{ mut stream, .. } => {
                stream.sock.flush()
                    .map_err(FtpError::ConnectionError)?;
                Ok(stream.sock)
            }
        }
    }

    /// Returns a reference to the underlying TcpStream.
    pub fn get_stream_ref(&self) -> &TcpStream {
        match &*self.inner {
            CommandStreamInner::Tcp(stream) => stream,
            #[cfg(feature="native-tls")]
            CommandStreamInner::NativeTls{ stream, .. } => stream.get_ref(),
            #[cfg(feature="rustls")]
            CommandStreamInner::Rustls{ stream, .. } => stream.get_ref()
        }
    }

    pub fn timeout(&self) -> std::time::Duration {
        self.inner.timeout()
    }

    /// Try to connect to the remote server
    pub fn connect_data<A: ToSocketAddrs>(&self, addr: A) -> FtpResult<DataStream> {
        let data = tcp_connect_timeout(addr, self.inner.timeout()).map_err(FtpError::ConnectionError)?;
        data.set_read_timeout(Some(self.timeout()))?;
        trace!("TCP Stream to data socket opened");
        self.connect_data_from_stream(data)
    }

    pub fn connect_data_from_stream(&self, s : TcpStream) -> FtpResult<DataStream> {
        match &*self.inner {
            CommandStreamInner::Tcp(_) => Ok(DataStream::Tcp(s)),
            #[cfg(feature = "native-tls")]
            CommandStreamInner::NativeTls { domain, connector, stream  } => {
                let data_stream = connector.connect(domain,s)
                    .map_err(|e| FtpError::SecureError(format!("{e:#?}")))?;
                trace!("Native TLS Data stream opened");
                Ok(DataStream::NativeTls(data_stream))
            },
            #[cfg(feature = "rustls")]
            CommandStreamInner::Rustls { server_name: domain, config, .. } => {
                let conn = rustls::ClientConnection::new(config.clone(),domain.clone())
                    .map_err(|e| FtpError::SecureError(format!("{e:#?}")))?;
                trace!("RusTLS TLS Data stream opened");
                let stream = Box::new(rustls::StreamOwned::new(conn,s));
                Ok(DataStream::Rustls(stream))
            },
        }
    }
}

impl std::fmt::Debug for CommandStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("CommandStream");
        if let Ok(peer) = self.peer_addr() {
            d.field("peer", &peer);
        }
        if let Ok(local) = self.local_addr() {
            d.field("local", &local);
        }
        
        match &*self.inner {
            CommandStreamInner::Tcp(_) => {
                d.field("secure", &"no");
            },
            #[cfg(feature = "native-tls")]
            CommandStreamInner::NativeTls { domain, connector, .. } => {
                d.field("secure", &"native tls");
                d.field("domain", domain);
                d.field("config", connector);
            },
            #[cfg(feature="rustls")]
            CommandStreamInner::Rustls { server_name, config, .. } => {
                d.field("secure", &"native tls");
                d.field("server_name", server_name);
                d.field("config", &**config);
            }
        };

        d.finish()
    }
}

impl Read for CommandStream {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Read for CommandStreamInner {
    #[inline(always)]
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            CommandStreamInner::Tcp(stream) => stream.read(buf),
            #[cfg(feature="native-tls")]
            CommandStreamInner::NativeTls{ stream, ..} => stream.read(buf),
            #[cfg(feature="rustls")]
            CommandStreamInner::Rustls{ stream, ..} => stream.read(buf)
        }
    }
}

impl BufRead for CommandStream {
    #[inline(always)]
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    #[inline(always)]
    fn consume(&mut self, amt: usize) {
        self.inner.consume(amt)
    }
}

impl ReadLine for CommandStream {
    #[inline(always)]
    fn next_line(&mut self) -> std::io::Result<super::lines::Line> {
        self.inner.next_line()
    }
}

impl Write for CommandStream {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.write(buf)
    }

    #[inline(always)]
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

impl Write for CommandStreamInner {
    #[inline(always)]
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            CommandStreamInner::Tcp(stream) => stream.write(buf),
            #[cfg(feature="native-tls")]
            CommandStreamInner::NativeTls{ stream, ..} => stream.write(buf),
            #[cfg(feature="rustls")]
            CommandStreamInner::Rustls{ stream, ..} => stream.write(buf)
        }
    }

    #[inline(always)]
    fn flush(&mut self) -> std::io::Result<()>
    {
        match self {
            CommandStreamInner::Tcp(stream) => stream.flush(),
            #[cfg(feature="native-tls")]
            CommandStreamInner::NativeTls{ stream, ..} => stream.flush(),
            #[cfg(feature="rustls")]
            CommandStreamInner::Rustls{ stream, ..} => stream.flush()
        }
    }
}

pub enum SecureConfig {
    #[cfg(feature = "rustls")]
    Rustls(rustls::ClientConfig),
    #[cfg(feature = "native-tls")]
    NativeTls(native_tls::TlsConnector)
}

#[cfg(feature = "rustls")]
impl From<rustls::ClientConfig> for SecureConfig {
    fn from(value: rustls::ClientConfig) -> Self {
        Self::Rustls(value)
    }
}

#[cfg(feature = "native-tls")]
impl From<native_tls::TlsConnector> for SecureConfig {
    fn from(value: native_tls::TlsConnector) -> Self {
        Self::NativeTls(value)
    }
}

pub enum DataStream {
    Tcp(TcpStream),
    #[cfg(feature = "native-tls")]
    NativeTls(native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "rustls")]
    Rustls(Box<rustls::StreamOwned<rustls::ClientConnection,TcpStream>>)
}

impl std::fmt::Debug for DataStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("DataStream");
        if let Ok(peer) = self.peer_addr() {
            d.field("peer", &peer);
        }
        if let Ok(local) = self.local_addr() {
            d.field("local", &local);
        }
        
        match self {
            DataStream::Tcp(_) => d.field("secure", &"no"),
            #[cfg(feature="native-tls")]
            DataStream::NativeTls(_) => d.field("secure", &"native tls"),
            #[cfg(feature="rustls")]
            DataStream::Rustls(_) => d.field("secure", &"rust tls"),
        };

        d.finish()
    }
}

impl DataStream {
    pub fn get_tcp_ref(&self) -> &TcpStream {
        match self {
            DataStream::Tcp(s) => s,
            #[cfg(feature = "native-tls")]
            DataStream::NativeTls(s) => s.get_ref(),
            #[cfg(feature = "rustls")]
            DataStream::Rustls(s) => s.get_ref(),
        }
    }

    pub fn peer_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.get_tcp_ref().peer_addr()
    }

    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.get_tcp_ref().local_addr()
    }

    pub fn is_secure(&self) -> bool {
        match self {
            DataStream::Tcp(_) => false,
            #[cfg(feature = "native-tls")]
            DataStream::NativeTls { .. } => true,
            #[cfg(feature = "rustls")]
            DataStream::Rustls { .. } => true,
        }
    }

    pub fn set_read_timeout(&mut self, timeout : Option<std::time::Duration>) -> std::io::Result<()> {
        self.get_tcp_ref().set_read_timeout(timeout)
    }
}

impl Read for DataStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            DataStream::Tcp(stream) => stream.read(buf),
            #[cfg(feature="native-tls")]
            DataStream::NativeTls(stream) => stream.read(buf),
            #[cfg(feature="rustls")]
            DataStream::Rustls(stream) => stream.read(buf)
        }
    }
}

impl Write for DataStream
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            DataStream::Tcp(stream) => stream.write(buf),
            #[cfg(feature="native-tls")]
            DataStream::NativeTls(stream) => stream.write(buf),
            #[cfg(feature="rustls")]
            DataStream::Rustls(stream) => stream.write(buf)
        }
    }

    fn flush(&mut self) -> std::io::Result<()>
    {
        match self {
            DataStream::Tcp(stream) => stream.flush(),
            #[cfg(feature="native-tls")]
            DataStream::NativeTls(stream) => stream.flush(),
            #[cfg(feature="rustls")]
            DataStream::Rustls(stream) => stream.flush()
        }
    }
}

fn tcp_connect_timeout<A : ToSocketAddrs>(addr : A, timeout : std::time::Duration) -> Result<std::net::TcpStream,std::io::Error> {
    let addrs = addr.to_socket_addrs()?
    .map(|a| TcpStream::connect_timeout(&a, timeout));

    let mut result = std::io::Error::new(std::io::ErrorKind::InvalidInput, "could not resolve to any addresses");
    for addr in addrs {
        match addr {
            Ok(a) => return Ok(a),
            Err(e) => result = e,
        }
    }

    Err(result)
}

