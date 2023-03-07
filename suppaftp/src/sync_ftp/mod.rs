//! # Sync
//!
//! This module contains the definition for all Sync implementation of suppaftp

mod file;
mod lines;
mod response;
mod stream;
#[cfg(test)]
mod test;

use self::lines::Lines;
use self::response::ResponseReader;

use super::regex::{EPSV_PORT_RE, MDTM_RE, PASV_PORT_RE, SIZE_RE};
use super::types::{FileType, FtpError, FtpResult, Mode};
use super::Status;
use crate::command::{ProtectionLevel, Command};

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use std::borrow::Cow;
use std::collections::VecDeque;
use std::io::{copy, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};

// export
use stream::CommandStream;
use stream::DataStream;
use response::Response;

/// Stream to interface with the FTP server. This interface is only for the command stream.
#[derive(Debug)]
pub struct FtpStream {
    mode: Mode,
    nat_workaround: bool,
    welcome_msg: Option<String>,
    cmd : CommandStream,
    state : FtpStreamState
}

impl FtpStream {
    /// Try to connect to the remote server
    pub fn connect<A: ToSocketAddrs>(addr: A) -> FtpResult<Self> {
        let stream = CommandStream::connect(addr)?;
        let mut this = Self {
            cmd : stream,
            state : FtpStreamState::Pending,
            mode : Mode::Passive,
            nat_workaround: false,
            welcome_msg: None,
        };
        this.initialise_stream()?;
        Ok(this)
    }

    /// Try to connect to the remote server but with the specified timeout
    pub fn connect_timeout<A: ToSocketAddrs>(addr: A, timeout: std::time::Duration) -> FtpResult<Self> {
        let stream = CommandStream::connect_timeout(addr,timeout)?;
        let mut this = Self {
            cmd : stream,
            state : FtpStreamState::Pending,
            mode: Mode::Passive,
            nat_workaround: false,
            welcome_msg: None,
        };
        this.initialise_stream()?;
        Ok(this)
    }

    fn initialise_stream(&mut self) -> FtpResult<()> {
        trace!("Reading server response...");
        let resp = self.response([Status::Ready])?;
        let welcome_msg = resp.as_string().ok();
        trace!("Server READY; response: {:?}", welcome_msg);
        self.welcome_msg = welcome_msg;
        Ok(())
    }

    /// Enable active mode for data channel
    pub fn active_mode(mut self) -> Self {
        self.mode = Mode::Active;
        self
    }

    /// Set the data channel transfer mode
    pub fn set_mode(&mut self, mode: Mode) {
        trace!("Changed mode to {:?}", mode);
        self.mode = mode;
    }

    /// Set NAT workaround for passive mode
    pub fn set_passive_nat_workaround(&mut self, nat_workaround: bool) {
        self.nat_workaround = nat_workaround;
    }

    /// Switch to explicit secure mode if possible (FTPS), using a provided SSL configuration.
    /// This method does nothing if the connect is already secured.
    ///
    /// ## Example
    ///
    /// ```rust,no_run
    /// use suppaftp::native_tls::TlsConnector;
    /// use suppaftp::FtpStream;
    /// use std::path::Path;
    ///
    /// // Create a TlsConnector
    /// // NOTE: For custom options see <https://docs.rs/native-tls/0.2.6/native_tls/struct.TlsConnectorBuilder.html>
    /// let mut ctx = TlsConnector::new().unwrap();
    /// let mut ftp_stream = FtpStream::connect("localhost:21").await.unwrap();
    /// let mut ftp_stream = ftp_stream.secure_with("localhost", ctx).await.unwrap();
    /// ```
    #[cfg(any(feature = "native-tls",feature="rustls"))]
    pub fn secure_with(
        mut self,
        domain: &str,
        config : impl Into<stream::SecureConfig>
    ) -> FtpResult<Self> {

        // Ask the server to start securing data.
        trace!("Initializing TLS auth");
        self.command(Command::Auth)?;
        self.response([Status::AuthOk])?;

        trace!("TLS OK; initializing ssl stream");

        let stream = self.cmd_stream.into_insecure()?;

        let stream = match config.into() {
            #[cfg(feature = "native-tls")]
            stream::SecureConfig::NativeTls(n) => {
                stream.init_native_tls(domain, n)?
            }
            #[cfg(feature = "rustls")]
            stream::SecureConfig::Rustls(r) => {
                stream.init_rustls(domain, r)?
            }
        };

        self.cmd_stream = stream;

        // Set protection buffer size
        self.command(Command::Pbsz(0))?;
        self.response([Status::CommandOk])?;

        // Change the level of data protection to Private
        self.command(Command::Prot(ProtectionLevel::Private))?;
        self.response([Status::CommandOk])?;

        Ok(self)
    }

    /// Returns welcome message retrieved from server (if available)
    pub fn get_welcome_msg(&self) -> Option<&str> {
        self.welcome_msg.as_deref()
    }

    /// Returns a reference to the underlying TcpStream.
    ///
    /// Example:
    /// ```no_run
    /// use suppaftp::FtpStream;
    /// use std::net::TcpStream;
    /// use std::time::Duration;
    ///
    /// let stream = FtpStream::connect("127.0.0.1:21")
    ///                        .expect("Couldn't connect to the server...");
    /// stream.get_ref().set_read_timeout(Some(Duration::from_secs(10)))
    ///                 .expect("set_read_timeout call failed");
    /// ```
    pub fn get_ref(&self) -> &TcpStream {
        self.cmd_stream.get_stream_ref()
    }

    /// Log in to the FTP server.
    pub fn login<S: AsRef<str>>(&mut self, user: S, password: S) -> FtpResult<()> {
        debug!("Signin in with user '{}'", user.as_ref());
        self.command(Command::User(user.as_ref().into()))?;
        self.response([Status::LoggedIn, Status::NeedPassword])
            .and_then(|r| {
                if r.status() == Status::NeedPassword {
                    debug!("Password is required");
                    self.command(Command::Pass(password.as_ref().into()))?;
                    self.response([Status::LoggedIn])?;
                }
                debug!("Login OK");
                Ok(())
            })
    }

    /// Perform clear command channel (CCC).
    /// Once the command is performed, the command channel will be encrypted no more.
    /// The data stream will still be secure.
    fn clear_command_channel(mut self) -> FtpResult<Self> {
        // Ask the server to stop securing data
        debug!("performing clear command channel");
        self.command(Command::ClearCommandChannel)?;
        self.response([Status::CommandOk])?;
        trace!("CCC OK");
        self.cmd_stream = self.cmd_stream.into_insecure()?;
        Ok(self)
    }

    /// Change the current directory to the path specified.
    pub fn cwd<S: AsRef<str>>(&mut self, path: S) -> FtpResult<()> {
        debug!("Changing working directory to {}", path.as_ref());
        self.command(Command::Cwd(path.as_ref().into()))?;
        self.response([Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Move the current directory to the parent directory.
    pub fn cdup(&mut self) -> FtpResult<()> {
        debug!("Going to parent directory");
        self.command(Command::Cdup)?;
        self.response([Status::CommandOk, Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Gets the current directory
    pub fn pwd(&mut self) -> FtpResult<String> {
        debug!("Getting working directory");
        self.command(Command::Pwd)?;
        self.response([Status::PathCreated])
            .and_then(|response| {
                let body = response.as_string().map_err(|_| FtpError::BadResponse)?;
                let status = response.status();
                match (body.find('"'), body.rfind('"')) {
                    (Some(begin), Some(end)) if begin < end => Ok(body[begin + 1..end].to_string()),
                    _ => Err(FtpError::UnexpectedResponse(response)),
                }
            })
    }

    /// This does nothing. This is usually just used to keep the connection open.
    pub fn noop(&mut self) -> FtpResult<()> {
        debug!("Pinging server");
        self.command(Command::Noop)?;
        self.response([Status::CommandOk]).map(|_| ())
    }

    /// The EPRT command allows for the specification of an extended address
    /// for the data connection. The extended address MUST consist of the
    /// network protocol as well as the network and transport addresses
    pub fn eprt(&mut self, address: SocketAddr) -> FtpResult<()> {
        debug!("EPRT with address {address}");
        self.command(Command::Eprt(address))?;
        self.response([Status::CommandOk]).map(|_| ())
    }

    /// This creates a new directory on the server.
    pub fn mkdir<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<()> {
        debug!("Creating directory at {}", pathname.as_ref());
        self.command(Command::Mkd(pathname.as_ref().into()))?;
        self.response([Status::PathCreated]).map(|_| ())
    }

    /// Sets the type of file to be transferred. That is the implementation
    /// of `TYPE` command.
    pub fn transfer_type(&mut self, file_type: FileType) -> FtpResult<()> {
        debug!("Setting transfer type {}", file_type);
        self.command(Command::Type(file_type))?;
        self.response([Status::CommandOk]).map(|_| ())
    }

    /// Quits the current FTP session.
    pub fn quit(&mut self) -> FtpResult<()> {
        debug!("Quitting stream");
        self.command(Command::Quit)?;
        self.response([Status::Closing]).map(|_| ())
    }

    /// Renames the file from_name to to_name
    pub fn rename<S: AsRef<str>>(&mut self, from_name: S, to_name: S) -> FtpResult<()> {
        debug!(
            "Renaming '{}' to '{}'",
            from_name.as_ref(),
            to_name.as_ref()
        );
        self.command(Command::RenameFrom(from_name.as_ref().into()))?;
        self.response([Status::RequestFilePending])
            .and_then(|_| {
                self.command(Command::RenameTo(to_name.as_ref().into()))?;
                self.response([Status::RequestedFileActionOk])
                    .map(|_| ())
            })
    }

    /// Retrieves the file name specified from the server as a readable stream.
    /// This method is a more complicated way to retrieve a file.
    /// The reader returned should be dropped.
    /// Also you will have to read the response to make sure it has the correct value.
    /// Once file has been read, call `finalize_retr_stream()`
    pub fn retr_as_stream<S: AsRef<str>>(&mut self, file_name: S) -> FtpResult<DataStream> {
        debug!("Retrieving '{}'", file_name.as_ref().into());
        let data_stream = self.data_command(Command::Retr(file_name.as_ref().into()))?;
        self.response([Status::AboutToSend, Status::AlreadyOpen])?;
        Ok(data_stream)
    }

    /// Finalize retr stream; must be called once the requested file, got previously with `retr_as_stream()` has been read
    pub fn finalize_retr_stream(&mut self, stream: impl Read) -> FtpResult<()> {
        debug!("Finalizing retr stream");
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(stream);
        trace!("dropped stream");
        // Then read response
        self.response([Status::ClosingDataConnection, Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Removes the remote pathname from the server.
    pub fn rmdir<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<()> {
        debug!("Removing directory {}", pathname.as_ref().into());
        self.command(Command::Rmd(pathname.as_ref().into()))?;
        self.response([Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Remove the remote file from the server.
    pub fn rm<S: AsRef<str>>(&mut self, filename: S) -> FtpResult<()> {
        debug!("Removing file {}", filename.as_ref().into());
        self.command(Command::Dele(filename.as_ref().into()))?;
        self.response([Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// This stores a file on the server.
    /// r argument must be any struct which implemenents the Read trait.
    /// Returns amount of written bytes
    pub fn put_file<S: AsRef<str>, R: Read>(&mut self, filename: S, r: &mut R) -> FtpResult<u64> {
        // Get stream
        let mut data_stream = self.put_with_stream(filename.as_ref().into())?;
        let bytes = copy(r, &mut data_stream)?;
        self.finalize_put_stream(data_stream)?;
        Ok(bytes)
    }

    /// Send PUT command and returns a BufWriter, which references the file created on the server
    /// The returned stream must be then correctly manipulated to write the content of the source file to the remote destination
    /// The stream must be then correctly dropped.
    /// Once you've finished the write, YOU MUST CALL THIS METHOD: `finalize_put_stream`
    pub fn put_with_stream<S: AsRef<str>>(&mut self, filename: S) -> FtpResult<DataStream> {
        debug!("Put file {}", filename.as_ref().into());
        let stream = self.data_command(Command::Store(filename.as_ref().into()))?;
        self.response([Status::AlreadyOpen, Status::AboutToSend])?;
        Ok(stream)
    }

    /// Finalize put when using stream
    /// This method must be called once the file has been written and
    /// `put_with_stream` has been used to write the file
    pub fn finalize_put_stream(&mut self, stream: impl Write) -> FtpResult<()> {
        debug!("Finalizing put stream");
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(stream);
        trace!("Stream dropped");
        // Read response
        self.response([Status::ClosingDataConnection, Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Open specified file for appending data. Returns the stream to append data to specified file.
    /// Once you've finished the write, YOU MUST CALL THIS METHOD: `finalize_put_stream`
    pub fn append_with_stream<S: AsRef<str>>(&mut self, filename: S) -> FtpResult<DataStream> {
        debug!("Appending to file {}", filename.as_ref().into());
        let stream = self.data_command(Command::Appe(filename.as_ref().into()))?;
        self.response([Status::AlreadyOpen, Status::AboutToSend])?;
        Ok(stream)
    }

    /// Append data from reader to file at `filename`
    pub fn append_file<R: Read>(&mut self, filename: &str, r: &mut R) -> FtpResult<u64> {
        // Get stream
        let mut data_stream = self.append_with_stream(filename)?;
        let bytes = copy(r, &mut data_stream)?;
        self.finalize_put_stream(Box::new(data_stream))?;
        Ok(bytes)
    }

    /// abort the previous FTP service command
    pub fn abort(&mut self, data_stream: impl Read) -> FtpResult<()> {
        debug!("Aborting active file transfer");
        self.command(Command::Abor)?;
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(data_stream);
        trace!("dropped stream");
        self.response([Status::ClosingDataConnection, Status::TransferAborted])?;
        self.response([Status::ClosingDataConnection])?;
        debug!("Transfer aborted");
        Ok(())
    }

    /// Tell the server to resume the transfer from a certain offset. The offset indicates the amount of bytes to skip
    /// from the beginning of the file.
    /// the REST command does not actually initiate the transfer.
    /// After issuing a REST command, the client must send the appropriate FTP command to transfer the file
    ///
    /// It is possible to cancel the REST command, sending a REST command with offset 0
    pub fn resume_transfer(&mut self, offset: usize) -> FtpResult<()> {
        debug!("Requesting to resume transfer at offset {}", offset);
        self.command(Command::Rest(offset))?;
        self.response([Status::RequestFilePending])?;
        debug!("Resume transfer accepted");
        Ok(())
    }

    /// Execute `LIST` command which returns the detailed file listing in human readable format.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    ///
    /// ### Parse result
    ///
    /// You can parse the output of this command with
    ///
    /// ```rust
    ///
    /// use std::str::FromStr;
    /// use suppaftp::list::File;
    ///
    /// let file: File = File::from_str("-rw-rw-r-- 1 0  1  8192 Nov 5 2018 omar.txt")
    ///     
    ///     .unwrap();
    /// ```
    pub fn list(&mut self, pathname: Option<&str>) -> FtpResult<Vec<String>> {
        debug!(
            "Reading {} directory content",
            pathname.unwrap_or("working")
        );

        self.stream_lines(
            Command::List(pathname),
            Status::AboutToSend,
        )
    }

    /// Execute `NLST` command which returns the list of file names only.
    /// If `pathname` is omited then the list of files in the current directory will be
    /// returned otherwise it will the list of files on `pathname`.
    pub fn nlst(&mut self, pathname: Option<&str>) -> impl Iterator<Item = FtpResult<String>> {
        debug!(
            "Getting file names for {} directory",
            pathname.unwrap_or("working")
        );

        self.stream_lines(
            Command::Nlst(pathname),
            Status::AboutToSend,
        )
    }

    /// Retrieves the modification time of the file at `pathname` if it exists.
    pub fn mdtm<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<NaiveDateTime> {
        debug!("Getting modification time for {}", pathname.as_ref());
        self.command(Command::Mdtm(pathname.as_ref().into()))?;
        let response = self.response([Status::File])?;
        let response = response.finalise()?;
        let body = response.body();

        match MDTM_RE.captures(&body) {
            Some(caps) => {
                let (year, month, day) = (
                    caps[1].parse::<i32>().unwrap(),
                    caps[2].parse::<u32>().unwrap(),
                    caps[3].parse::<u32>().unwrap(),
                );
                let (hour, minute, second) = (
                    caps[4].parse::<u32>().unwrap(),
                    caps[5].parse::<u32>().unwrap(),
                    caps[6].parse::<u32>().unwrap(),
                );

                let date = match NaiveDate::from_ymd_opt(year, month, day) {
                    Some(d) => d,
                    None => return Err(FtpError::BadResponse),
                };

                let time = match NaiveTime::from_hms_opt(hour, minute, second) {
                    Some(t) => t,
                    None => return Err(FtpError::BadResponse),
                };

                Ok(NaiveDateTime::new(date, time))
            }
            None => Err(FtpError::BadResponse),
        }
    }

    /// Retrieves the size of the file in bytes at `pathname` if it exists.
    pub fn size<'a>(&mut self, pathname: impl Into<Cow<'a,str>>) -> FtpResult<usize> {
        let pathname = pathname.into();

        debug!("Getting file size for {}", pathname);
        let resp = self.command(Command::Size(pathname),[Status::File])?;

        let response = response.finalise()?;
        let body = response.body();

        match SIZE_RE.captures(&body) {
            Some(caps) => Ok(caps[1].parse().unwrap()),
            None => Err(FtpError::BadResponse),
        }
    }

    // -- private
    fn clear_pending(&mut self) -> FtpResult<()> {
        let state = std::mem::replace(&mut self.state,FtpStreamState::Pending);
        match state {
            FtpStreamState::Pending => (),
            FtpStreamState::CommandStream(r) => {
                let resp = r.finalise(&mut self.cmd)?;

                trace!("{resp}");                
            }
            FtpStreamState::DataStream { response , data_stream, final_response } => {
                drop(data_stream);

                let resp = response.finalise(&mut self.cmd)?;

                trace!("{resp}");

                let resp = Response::new(&mut self.cmd)?;

                let unexpected_resp = !final_response.contains(&resp.status());

                let final_resp = response.finalise(&mut self.cmd)?;
                
                trace!("{final_resp}");

                if unexpected_resp {
                    return Err(FtpError::UnexpectedResponse(final_resp));
                }
            },
        }

        Ok(())        
    }

    pub fn command(&mut self, command : Command<'_>, expected_resp : impl IntoIterator<Item = Status>) -> FtpResult<ResponseReader<'_,CommandStream>> {
        self.clear_pending()?;
        
        write!(&mut self.cmd, "{command}\r\n")?;

        let resp =  Response::new(&mut self.cmd)?;

        if !expected_resp.into_iter().any(|e| e == resp.status()) {
            let final_resp = resp.finalise(&mut self.cmd)?;
                
            trace!("{final_resp}");
            return Err(FtpError::UnexpectedResponse(final_resp));
        }

        self.state = FtpStreamState::CommandStream(resp);

        let FtpStreamState::CommandStream(resp_hdl) = &mut self.state else { unreachable!() };

        Ok(ResponseReader::new(&mut self.cmd,resp_hdl))
    }

    pub fn data_command(&mut self, command : Command<'_>, initial_resp : impl IntoIterator<Item = Status>, final_resp : impl IntoIterator<Item = Status>) -> FtpResult<&mut DataStream> {
        let stream = match self.mode {
            Mode::Active => {
                let listener = self.active()?;
                
                write!(&mut self.cmd, "{command}\r\n")?;

                let response =  Response::new(&mut self.cmd)?;

                if !initial_resp.into_iter().any(|e| e == response.status()) {
                    let final_resp = response.finalise(&mut self.cmd)?;
                        
                    trace!("{final_resp}");
                    return Err(FtpError::UnexpectedResponse(final_resp));
                }
                
                let (stream,_addr) = listener.accept().map_err(FtpError::ConnectionError)?;

                let data_stream = stream::DataStream::Tcp(stream);

                self.state = FtpStreamState::DataStream { response, data_stream, final_response: final_resp.into_iter().collect() };
            },
            Mode::Passive => {
                let peer_addr = self.cmd.peer_addr()?;

                let sock = if peer_addr.is_ipv4() {
                    trace!("Sending PASV");
                    self.pasv()?
                }
                else {
                    self.epsv()?
                };

                let data_stream = self.cmd.connect_data(sock)?;

                write!(&mut self.cmd, "{command}\r\n")?;

                let response =  Response::new(&mut self.cmd)?;

                if !initial_resp.into_iter().any(|e| e == response.status()) {
                    let final_resp = response.finalise(&mut self.cmd)?;
                        
                    trace!("{final_resp}");
                    return Err(FtpError::UnexpectedResponse(final_resp));
                }

                self.state = FtpStreamState::DataStream { response, data_stream, final_response: final_resp.into_iter().collect() };
            },
        };

        let FtpStreamState::DataStream { data_stream, .. } = &mut self.state else { panic!() };

        Ok(data_stream)
    }

    /// Create a new tcp listener and send a PORT command for it
    fn active(&mut self) -> FtpResult<TcpListener> {
        debug!("Starting local tcp listener...");
        let conn = TcpListener::bind("0.0.0.0:0").map_err(FtpError::ConnectionError)?;

        let addr = conn.local_addr().map_err(FtpError::ConnectionError)?;
        trace!("Local address is {}", addr);

        let ip = self.cmd.local_addr()?.ip();
        let ext_sock = SocketAddr::new(ip, addr.port());

        match ext_sock {
            SocketAddr::V4(sock) => {
                debug!("Running PORT command");
                write!(self.cmd, "{}", Command::Port(sock))?;

                debug!("Active mode, listening on {}", sock);
            },
            SocketAddr::V6(sock) => {
                debug!("Running EPRT command");
                write!(self.cmd, "{}", Command::Eprt(ext_sock))?;

                debug!("Active mode, listening on {}:{}", ip, addr.port());
            },
        }

        let response =  Response::new(&mut self.cmd)?;

        if Status::CommandOk != response.status() {
            let final_resp = response.finalise(&mut self.cmd)?;
                
            trace!("{final_resp}");
            return Err(FtpError::UnexpectedResponse(final_resp));
        }

        Ok(conn)
    }

    /// Runs the EPSV to enter Extended passive mode.
    fn epsv(&mut self) -> FtpResult<SocketAddr> {
        debug!("EPSV command");
        
        write!(self.cmd, "{}", Command::Epsv)?;

        let response =  Response::new(&mut self.cmd)?;

        if Status::ExtendedPassiveMode != response.status() {
            let final_resp = response.finalise(&mut self.cmd)?;
                
            trace!("{final_resp}");
            return Err(FtpError::UnexpectedResponse(final_resp));
        }
        
        // PASV response format : 229 Entering Extended Passive Mode (|||PORT|)

        let response = response.finalise(&mut self.cmd)?;
        let response_str = response.lines()
            .collect::<Vec<_>>()
            .join("\n");

        let caps = EPSV_PORT_RE
            .captures(&response_str)
            .ok_or_else(|| FtpError::UnexpectedResponse(response))?;

        let new_port = caps[1].parse::<u16>().unwrap();

        trace!("Got port number from EPSV: {}", new_port);

        let mut remote = self
            .cmd
            .peer_addr()?;

        remote.set_port(new_port);

        trace!("Remote address for extended passive mode is {}", remote);

        Ok(remote)
    }

    /// Runs the PASV command  to enter passive mode.
    fn pasv(&mut self) -> FtpResult<SocketAddr> {
        debug!("PASV command");
        
        write!(self.cmd, "{}", Command::Epsv)?;

        let response =  Response::new(&mut self.cmd)?;

        if Status::ExtendedPassiveMode != response.status() {
            let final_resp = response.finalise(&mut self.cmd)?;
                
            trace!("{final_resp}");
            return Err(FtpError::UnexpectedResponse(final_resp));
        }

        // PASV response format : 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).

        let response = response.finalise(&mut self.cmd)?;
        let response_str = response.lines()
            .collect::<Vec<_>>()
            .join("\n");

        let caps = PASV_PORT_RE
            .captures(&response_str)
            .ok_or_else(|| FtpError::UnexpectedResponse(response.clone()))?;

        // If the regex matches we can be sure groups contains numbers
        let (oct1, oct2, oct3, oct4) = (
            caps[1].parse::<u8>().unwrap(),
            caps[2].parse::<u8>().unwrap(),
            caps[3].parse::<u8>().unwrap(),
            caps[4].parse::<u8>().unwrap(),
        );
        let (msb, lsb) = (
            caps[5].parse::<u8>().unwrap(),
            caps[6].parse::<u8>().unwrap(),
        );

        let ip = Ipv4Addr::new(oct1, oct2, oct3, oct4);
        let port = (u16::from(msb) << 8) | u16::from(lsb);
        let addr = SocketAddr::new(ip.into(), port);
        trace!("Passive address: {}", addr);

        if self.nat_workaround && ip.is_private() {
            let mut remote = self
                .cmd
                .peer_addr()?;

            remote.set_port(port);

            trace!("Replacing site local address {} with {}", addr, remote);

            Ok(remote)
        } else {
            Ok(addr)
        }
    }
}

#[derive(Debug)]
pub enum FtpStreamState {
    Pending,
    CommandStream(Response),
    DataStream {
        response : Response,
        data_stream : DataStream,
        final_response : Vec<Status>
    },
}

    