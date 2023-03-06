//! # Data Stream
//!
//! This module exposes the async data stream implementation where bytes must be written to/read from

#[cfg(feature="async-std")]
mod async_prelude {
    pub use async_std::io::{Read, Write,WriteExt};
    pub use async_std::net::TcpStream;
    pub use async_std::net::ToSocketAddrs;
}

#[cfg(feature="tokio")]
mod async_prelude {
    pub use tokio::io::{AsyncRead as Read, AsyncWrite as Write, AsyncWriteExt as WriteExt};
    pub use tokio::net::TcpStream;
    pub use tokio::net::ToSocketAddrs;
}

use async_prelude::*;

use pin_project::pin_project;
use std::pin::Pin;

use crate::{FtpResult, FtpError};

/// Data Stream used for communications. It can be both of type Tcp in case of plain communication or Ssl in case of FTPS
#[pin_project(project = CommandStreamProj)]
pub enum CommandStream
{
    Tcp(#[pin] TcpStream),
    #[cfg(feature="async-native-tls")]
    NativeTls {
        domain : String,
        connector : async_native_tls::TlsConnector,
        #[pin]
        stream : async_native_tls::TlsStream<TcpStream>
    },
    // #[cfg(feature="async-rustls")]
    // Rustls {
    //     server_name : rustls::ServerName,
    //     config : std::sync::Arc<rustls::ClientConfig>,
    //     #[pin]
    //     stream : Box<rustls::StreamOwned<rustls::ClientConnection,TcpStream>>
    // },
}

impl CommandStream {
    /// Try to connect to the remote server
    pub async fn connect<A: ToSocketAddrs>(addr: A) -> FtpResult<Self> {
        trace!("Connecting to server");
        TcpStream::connect(addr).await
            .map_err(FtpError::ConnectionError)
            .map(Self::Tcp)
    }

    /// Try to connect to the remote server but with the specified timeout
    pub async fn connect_timeout<A : ToSocketAddrs>(addr: A, timeout: std::time::Duration) -> FtpResult<Self> {
        trace!("Connecting to server");
        tcp_connect_timeout(addr,timeout).await
            .map_err(FtpError::ConnectionError)
            .map(Self::Tcp)
    }

    pub fn local_addr(&self) -> FtpResult<std::net::SocketAddr> {
        let sock = match self {
            CommandStream::Tcp(s) => s.local_addr().map_err(FtpError::ConnectionError)?,
            #[cfg(feature = "async-native-tls")]
            CommandStream::NativeTls { stream, .. } => {
                stream.get_ref().local_addr().map_err(FtpError::ConnectionError)?
            },
            #[cfg(feature = "async-rustls")]
            CommandStream::Rustls { stream, .. } => {
                stream.get_ref().local_addr().map_err(FtpError::ConnectionError)?
            },
        };

        Ok(sock)
    }

    pub fn peer_addr(&self) -> FtpResult<std::net::SocketAddr> {
        let sock = match self {
            CommandStream::Tcp(s) => s.peer_addr().map_err(FtpError::ConnectionError)?,
            #[cfg(feature = "async-native-tls")]
            CommandStream::NativeTls { stream, .. } => {
                stream.get_ref().peer_addr().map_err(FtpError::ConnectionError)?
            },
            #[cfg(feature = "async-rustls")]
            CommandStream::Rustls { stream, .. } => {
                stream.get_ref().peer_addr().map_err(FtpError::ConnectionError)?
            },
        };

        Ok(sock)
    }

    // /// Switch to explicit secure mode using Rustls
    // #[cfg(feature = "async-rustls")]
    // pub fn init_rustls(
    //     self,
    //     domain: impl std::string::ToString,
    //     config : rustls::ClientConfig
    // ) -> FtpResult<Self> {
    //     let domain = domain.to_string();
    //     let config = config.into();
    //     let stream = self.into_tcp_stream()?;
    //     let server_name = rustls::ServerName::try_from(&*domain)
    //         .map_err(|e| FtpError::SecureError(e.to_string()))?;

    //     let conn = rustls::ClientConnection::new(std::sync::Arc::clone(&config),server_name.clone())
    //         .map_err(|e| FtpError::SecureError(e.to_string()))?;

    //     let stream = Box::new(rustls::StreamOwned::new(conn,stream));

    //     Ok(Self::Rustls { server_name, config, stream })
    // }

    /// Switch to explicit secure mode using NativeTls
    #[cfg(feature = "async-native-tls")]
    pub async fn init_native_tls(
        self,
        domain: impl std::string::ToString,
        connector : async_native_tls::TlsConnector
    ) -> FtpResult<Self> {
        let domain = domain.to_string();

        let stream = match self {
            CommandStream::Tcp(tcp) => tcp,
            x => return Ok(x)
        };

        let stream = connector.connect(&domain, stream).await
            .map_err(|e| FtpError::SecureError(e.to_string()))?;

        Ok(Self::NativeTls { domain, connector, stream })
    }

    pub fn is_secure(&self) -> bool {
        match self {
            CommandStream::Tcp(_) => false,
            #[cfg(feature = "async-native-tls")]
            CommandStream::NativeTls { .. } => true,
            // #[cfg(feature = "rustls")]
            // CommandStream::Rustls { .. } => true,
        }
    }

    /// Returns a reference to the underlying TcpStream.
    pub fn get_ref(&self) -> &TcpStream {
        match self {
            CommandStream::Tcp(stream) => stream,
            #[cfg(feature="async-native-tls")]
            CommandStream::NativeTls{ stream, .. } => stream.get_ref(),
            #[cfg(feature="async-rustls")]
            CommandStream::Rustls{ stream, .. } => stream.get_ref()
        }
    }

    /// Try to connect to the remote server
    pub async fn connect_data<A: ToSocketAddrs>(&self, addr: A) -> FtpResult<DataStream> {
        let data = TcpStream::connect(addr).await.map_err(FtpError::ConnectionError)?;

        self.connect_data_from_stream(data).await
    }

    /// Try to connect to the remote server
    pub async fn connect_data_timeout<A: ToSocketAddrs>(&self, addr: A, timeout : std::time::Duration) -> FtpResult<DataStream> {
        let data = tcp_connect_timeout(addr, timeout).await.map_err(FtpError::ConnectionError)?;

        self.connect_data_from_stream(data).await
    }

    pub async fn connect_data_from_stream(&self, s : TcpStream) -> FtpResult<DataStream> {
        match self {
            CommandStream::Tcp(_) => Ok(DataStream::Tcp(s)),
            #[cfg(feature = "async-native-tls")]
            CommandStream::NativeTls { domain, connector, .. } => {
                let stream = connector.connect(domain,s).await
                    .map_err(|e| FtpError::SecureError(e.to_string()))?;
                Ok(DataStream::NativeTls(stream))
            },
            // #[cfg(feature = "rustls")]
            // CommandStream::Rustls { server_name: domain, config, .. } => {
            //     let conn = rustls::ClientConnection::new(config.clone(),domain.clone())
            //         .map_err(|e| FtpError::SecureError(e.to_string()))?;
        
            //     let stream = Box::new(rustls::StreamOwned::new(conn,s));
            //     Ok(Data::Rustls(stream))
            // },
        }
    }
}

#[pin_project(project = DataStreamProj)]
pub enum DataStream {
    Tcp(#[pin] TcpStream),
    #[cfg(feature = "async-native-tls")]
    NativeTls(#[pin] async_native_tls::TlsStream<TcpStream>),
    #[cfg(feature = "async-rustls")]
    Rustls(#[pin] Box<rustls::StreamOwned<rustls::ClientConnection,TcpStream>>)
}

// -- async
#[cfg(feature="async-std")]
mod asyncstd_async_impl {
    use super::*;

    impl Read for CommandStream
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            match self.project() {
                CommandStreamProj::Tcp(stream) => stream.poll_read(cx, buf),
                CommandStreamProj::NativeTls { stream, .. } => stream.poll_read(cx, buf),
            }
        }
    }

    impl Write for CommandStream
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            match self.project() {
                CommandStreamProj::Tcp(stream) => stream.poll_write(cx, buf),
                CommandStreamProj::NativeTls { stream, .. } => stream.poll_write(cx, buf),
            }
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.project() {
                CommandStreamProj::Tcp(stream) => stream.poll_flush(cx),
                CommandStreamProj::NativeTls { stream, .. } => stream.poll_flush(cx),
            }
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.project() {
                CommandStreamProj::Tcp(stream) => stream.poll_close(cx),
                CommandStreamProj::NativeTls { stream, .. } => stream.poll_close(cx),
            }
        }
    }

    impl Read for DataStream
    {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut [u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            match self.project() {
                DataStreamProj::Tcp(stream) => stream.poll_read(cx, buf),
                DataStreamProj::NativeTls(stream) => stream.poll_read(cx, buf),
            }
        }
    }

    impl Write for DataStream
    {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            match self.project() {
                DataStreamProj::Tcp(stream) => stream.poll_write(cx, buf),
                DataStreamProj::NativeTls(stream) => stream.poll_write(cx, buf),
            }
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.project() {
                DataStreamProj::Tcp(stream) => stream.poll_flush(cx),
                DataStreamProj::NativeTls(stream) => stream.poll_flush(cx),
            }
        }

        fn poll_close(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.project() {
                DataStreamProj::Tcp(stream) => stream.poll_close(cx),
                DataStreamProj::NativeTls(stream) => stream.poll_close(cx),
            }
        }
    }
}

#[cfg(feature="tokio")]
mod tokio_async_impl {
    use super::*;

    impl Read for CommandStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            match self.project() {
                CommandStreamProj::Tcp(stream) => stream.poll_read(cx, buf),
                CommandStreamProj::NativeTls { stream, .. } => stream.poll_read(cx, buf),
            }
        }
    }

    impl Write for CommandStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            match self.project() {
                CommandStreamProj::Tcp(stream) => stream.poll_write(cx, buf),
                CommandStreamProj::NativeTls { stream, .. } => stream.poll_write(cx, buf),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
            match self.project() {
                CommandStreamProj::Tcp(stream) => stream.poll_flush(cx),
                CommandStreamProj::NativeTls { stream, .. } => stream.poll_flush(cx),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
            match self.project() {
                CommandStreamProj::Tcp(stream) => stream.poll_shutdown(cx),
                CommandStreamProj::NativeTls { stream, .. } => stream.poll_shutdown(cx),
            }
        }
    }

    impl Read for DataStream {
        fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
            match self.project() {
                DataStreamProj::Tcp(stream) => stream.poll_read(cx, buf),
                DataStreamProj::NativeTls(stream) => stream.poll_read(cx, buf),
            }
        }
    }

    impl Write for DataStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<Result<usize, std::io::Error>> {
            match self.project() {
                DataStreamProj::Tcp(stream) => stream.poll_write(cx, buf),
                DataStreamProj::NativeTls(stream) => stream.poll_write(cx, buf),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
            match self.project() {
                DataStreamProj::Tcp(stream) => stream.poll_flush(cx),
                DataStreamProj::NativeTls(stream) => stream.poll_flush(cx),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), std::io::Error>> {
            match self.project() {
                DataStreamProj::Tcp(stream) => stream.poll_shutdown(cx),
                DataStreamProj::NativeTls(stream) => stream.poll_shutdown(cx),
            }
        }
    }
}

pub enum SecureConfig {
//     #[cfg(feature = "rusttls")]
//     Rustls(rustls::ClientConfig),
    #[cfg(feature = "async-native-tls")]
    NativeTls(async_native_tls::TlsConnector)
}

#[cfg(feature = "rusttls")]
impl From<rustls::ClientConfig> for SecureConfig {
    fn from(value: rustls::ClientConfig) -> Self {
        Self::Rustls(value)
    }
}

#[cfg(feature = "async-native-tls")]
impl From<async_native_tls::TlsConnector> for SecureConfig {
    fn from(value: async_native_tls::TlsConnector) -> Self {
        Self::NativeTls(value)
    }
}



async fn tcp_connect_timeout<A : ToSocketAddrs>(addr : A, timeout : std::time::Duration) -> Result<TcpStream,std::io::Error> {
    #[cfg(feature="tokio")]
    let addrs = {
        tokio::net::lookup_host(addr).await?
            .map(|a| tokio::time::timeout(timeout, TcpStream::connect(a)))
    };
    #[cfg(feature="async-std")]
    let addrs = {
        addr.to_socket_addrs().await?
            .map(|a| async_std::future::timeout(timeout, TcpStream::connect(a)))
    };

    let mut result = std::io::Error::new(std::io::ErrorKind::InvalidInput, "could not resolve to any addresses");
    for addr in addrs {
        match addr.await {
            Ok(Ok(a)) => return Ok(a),
            Ok(Err(e)) => result = e,
            Err(_e) => result = std::io::Error::new(std::io::ErrorKind::TimedOut,"Connecting to tcp socket timed out"),
        }
    }

    Err(result)
}