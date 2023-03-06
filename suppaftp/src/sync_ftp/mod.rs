//! # Sync
//!
//! This module contains the definition for all Sync implementation of suppaftp

mod file;
mod stream;
#[cfg(test)]
mod test;

use super::regex::{EPSV_PORT_RE, MDTM_RE, PASV_PORT_RE, SIZE_RE};
use super::types::{FileType, FtpError, FtpResult, Mode, Response};
use super::Status;
use crate::command::Command;
use crate::command::ProtectionLevel;

use chrono::{NaiveDate, NaiveDateTime, NaiveTime};
use std::io::{copy, BufRead, BufReader, Cursor, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};

// export
use stream::CommandStream;
use stream::DataStream;

/// Stream to interface with the FTP server. This interface is only for the command stream.
#[derive(Debug)]
pub struct FtpStream {
    timeout : Option<std::time::Duration>,
    cmd_stream: BufReader<CommandStream>,
    mode: Mode,
    nat_workaround: bool,
    welcome_msg: Option<String>,
}

impl FtpStream {
    /// Try to connect to the remote server
    pub fn connect<A: ToSocketAddrs>(addr: A) -> FtpResult<Self> {
        let stream = CommandStream::connect(addr)?;
        let mut this = Self {
            timeout : None,
            cmd_stream: BufReader::new(stream),
            mode: Mode::Passive,
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
            timeout : Some(timeout),
            cmd_stream: BufReader::new(stream),
            mode: Mode::Passive,
            nat_workaround: false,
            welcome_msg: None,
        };
        this.initialise_stream()?;
        Ok(this)
    }

    fn initialise_stream(&mut self) -> FtpResult<()> {
        trace!("Reading server response...");
        let resp = self.read_response(Status::Ready)?;
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
        self.perform(Command::Auth)?;
        self.read_response(Status::AuthOk)?;

        trace!("TLS OK; initializing ssl stream");

        let stream = self.cmd_stream.into_inner();

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

        self.cmd_stream = std::io::BufReader::new(stream);

        // Set protection buffer size
        self.perform(Command::Pbsz(0))?;
        self.read_response(Status::CommandOk)?;

        // Change the level of data protection to Private
        self.perform(Command::Prot(ProtectionLevel::Private))?;
        self.read_response(Status::CommandOk)?;

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
        self.cmd_stream.get_ref().get_stream_ref()
    }

    /// Log in to the FTP server.
    pub fn login<S: AsRef<str>>(&mut self, user: S, password: S) -> FtpResult<()> {
        debug!("Signin in with user '{}'", user.as_ref());
        self.perform(Command::User(user.as_ref()))?;
        self.read_response_in(&[Status::LoggedIn, Status::NeedPassword])
            .and_then(|Response { status, body: _ }| {
                if status == Status::NeedPassword {
                    debug!("Password is required");
                    self.perform(Command::Pass(password.as_ref()))?;
                    self.read_response(Status::LoggedIn)?;
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
        self.perform(Command::ClearCommandChannel)?;
        self.read_response(Status::CommandOk)?;
        trace!("CCC OK");
        self.cmd_stream = BufReader::new(self.cmd_stream.into_inner().into_insecure()?);
        Ok(self)
    }

    /// Change the current directory to the path specified.
    pub fn cwd<S: AsRef<str>>(&mut self, path: S) -> FtpResult<()> {
        debug!("Changing working directory to {}", path.as_ref());
        self.perform(Command::Cwd(path.as_ref()))?;
        self.read_response(Status::RequestedFileActionOk)
            .map(|_| ())
    }

    /// Move the current directory to the parent directory.
    pub fn cdup(&mut self) -> FtpResult<()> {
        debug!("Going to parent directory");
        self.perform(Command::Cdup)?;
        self.read_response_in(&[Status::CommandOk, Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Gets the current directory
    pub fn pwd(&mut self) -> FtpResult<String> {
        debug!("Getting working directory");
        self.perform(Command::Pwd)?;
        self.read_response(Status::PathCreated)
            .and_then(|response| {
                let body = response.as_string().map_err(|_| FtpError::BadResponse)?;
                let status = response.status;
                match (body.find('"'), body.rfind('"')) {
                    (Some(begin), Some(end)) if begin < end => Ok(body[begin + 1..end].to_string()),
                    _ => Err(FtpError::UnexpectedResponse(Response::new(
                        status,
                        response.body,
                    ))),
                }
            })
    }

    /// This does nothing. This is usually just used to keep the connection open.
    pub fn noop(&mut self) -> FtpResult<()> {
        debug!("Pinging server");
        self.perform(Command::Noop)?;
        self.read_response(Status::CommandOk).map(|_| ())
    }

    /// The EPRT command allows for the specification of an extended address
    /// for the data connection. The extended address MUST consist of the
    /// network protocol as well as the network and transport addresses
    pub fn eprt(&mut self, address: SocketAddr) -> FtpResult<()> {
        debug!("EPRT with address {address}");
        self.perform(Command::Eprt(address))?;
        self.read_response(Status::CommandOk).map(|_| ())
    }

    /// This creates a new directory on the server.
    pub fn mkdir<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<()> {
        debug!("Creating directory at {}", pathname.as_ref());
        self.perform(Command::Mkd(pathname.as_ref()))?;
        self.read_response(Status::PathCreated).map(|_| ())
    }

    /// Sets the type of file to be transferred. That is the implementation
    /// of `TYPE` command.
    pub fn transfer_type(&mut self, file_type: FileType) -> FtpResult<()> {
        debug!("Setting transfer type {}", file_type);
        self.perform(Command::Type(file_type))?;
        self.read_response(Status::CommandOk).map(|_| ())
    }

    /// Quits the current FTP session.
    pub fn quit(&mut self) -> FtpResult<()> {
        debug!("Quitting stream");
        self.perform(Command::Quit)?;
        self.read_response(Status::Closing).map(|_| ())
    }

    /// Renames the file from_name to to_name
    pub fn rename<S: AsRef<str>>(&mut self, from_name: S, to_name: S) -> FtpResult<()> {
        debug!(
            "Renaming '{}' to '{}'",
            from_name.as_ref(),
            to_name.as_ref()
        );
        self.perform(Command::RenameFrom(from_name.as_ref()))?;
        self.read_response(Status::RequestFilePending)
            .and_then(|_| {
                self.perform(Command::RenameTo(to_name.as_ref()))?;
                self.read_response(Status::RequestedFileActionOk)
                    .map(|_| ())
            })
    }

    /// The implementation of `RETR` command where `filename` is the name of the file
    /// to download from FTP and `reader` is the function which operates with the
    /// data stream opened.
    ///
    /// ```
    /// # use suppaftp::{FtpStream, FtpError};
    /// # use std::io::Cursor;
    /// # let mut conn = FtpStream::connect("127.0.0.1:10021").unwrap();
    /// # conn.login("test", "test").and_then(|_| {
    /// #     let mut reader = Cursor::new("hello, world!".as_bytes());
    /// #     conn.put_file("retr.txt", &mut reader)
    /// # }).unwrap();
    /// assert!(conn.retr("retr.txt", |stream| {
    ///     let mut buf = Vec::new();
    ///     stream.read_to_end(&mut buf).map(|_|
    ///         assert_eq!(buf, "hello, world!".as_bytes())
    ///     ).map_err(|e| FtpError::ConnectionError(e))
    /// }).is_ok());
    /// # assert!(conn.rm("retr.txt").is_ok());
    /// ```
    pub fn retr<F, D>(&mut self, file_name: &str, mut reader: F) -> FtpResult<D>
    where
        F: FnMut(&mut dyn Read) -> FtpResult<D>,
    {
        match self.retr_as_stream(file_name) {
            Ok(mut stream) => {
                let result = reader(&mut stream)?;
                self.finalize_retr_stream(stream)?;
                Ok(result)
            }
            Err(err) => Err(err),
        }
    }

    /// Simple way to retr a file from the server. This stores the file in a buffer in memory.
    ///
    /// ```
    /// # use suppaftp::{FtpStream, FtpError};
    /// # use std::io::Cursor;
    /// # let mut conn = FtpStream::connect("127.0.0.1:10021").unwrap();
    /// # conn.login("test", "test").and_then(|_| {
    /// #     let mut reader = Cursor::new("hello, world!".as_bytes());
    /// #     conn.put_file("simple_retr.txt", &mut reader)
    /// # }).unwrap();
    /// let cursor = conn.retr_as_buffer("simple_retr.txt").unwrap();
    /// // do something with bytes
    /// assert_eq!(cursor.into_inner(), "hello, world!".as_bytes());
    /// # assert!(conn.rm("simple_retr.txt").is_ok());
    /// ```
    pub fn retr_as_buffer(&mut self, file_name: &str) -> FtpResult<Cursor<Vec<u8>>> {
        self.retr(file_name, |reader| {
            let mut buffer = Vec::new();
            reader
                .read_to_end(&mut buffer)
                .map(|_| buffer)
                .map_err(FtpError::ConnectionError)
        })
        .map(Cursor::new)
    }

    /// Retrieves the file name specified from the server as a readable stream.
    /// This method is a more complicated way to retrieve a file.
    /// The reader returned should be dropped.
    /// Also you will have to read the response to make sure it has the correct value.
    /// Once file has been read, call `finalize_retr_stream()`
    pub fn retr_as_stream<S: AsRef<str>>(&mut self, file_name: S) -> FtpResult<DataStream> {
        debug!("Retrieving '{}'", file_name.as_ref());
        let data_stream = self.data_command(Command::Retr(file_name.as_ref()))?;
        self.read_response_in(&[Status::AboutToSend, Status::AlreadyOpen])?;
        Ok(data_stream)
    }

    /// Finalize retr stream; must be called once the requested file, got previously with `retr_as_stream()` has been read
    pub fn finalize_retr_stream(&mut self, stream: impl Read) -> FtpResult<()> {
        debug!("Finalizing retr stream");
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(stream);
        trace!("dropped stream");
        // Then read response
        self.read_response_in(&[Status::ClosingDataConnection, Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Removes the remote pathname from the server.
    pub fn rmdir<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<()> {
        debug!("Removing directory {}", pathname.as_ref());
        self.perform(Command::Rmd(pathname.as_ref()))?;
        self.read_response(Status::RequestedFileActionOk)
            .map(|_| ())
    }

    /// Remove the remote file from the server.
    pub fn rm<S: AsRef<str>>(&mut self, filename: S) -> FtpResult<()> {
        debug!("Removing file {}", filename.as_ref());
        self.perform(Command::Dele(filename.as_ref()))?;
        self.read_response(Status::RequestedFileActionOk)
            .map(|_| ())
    }

    /// This stores a file on the server.
    /// r argument must be any struct which implemenents the Read trait.
    /// Returns amount of written bytes
    pub fn put_file<S: AsRef<str>, R: Read>(&mut self, filename: S, r: &mut R) -> FtpResult<u64> {
        // Get stream
        let mut data_stream = self.put_with_stream(filename.as_ref())?;
        let bytes = copy(r, &mut data_stream).map_err(FtpError::ConnectionError)?;
        self.finalize_put_stream(data_stream)?;
        Ok(bytes)
    }

    /// Send PUT command and returns a BufWriter, which references the file created on the server
    /// The returned stream must be then correctly manipulated to write the content of the source file to the remote destination
    /// The stream must be then correctly dropped.
    /// Once you've finished the write, YOU MUST CALL THIS METHOD: `finalize_put_stream`
    pub fn put_with_stream<S: AsRef<str>>(&mut self, filename: S) -> FtpResult<DataStream> {
        debug!("Put file {}", filename.as_ref());
        let stream = self.data_command(Command::Store(filename.as_ref()))?;
        self.read_response_in(&[Status::AlreadyOpen, Status::AboutToSend])?;
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
        self.read_response_in(&[Status::ClosingDataConnection, Status::RequestedFileActionOk])
            .map(|_| ())
    }

    /// Open specified file for appending data. Returns the stream to append data to specified file.
    /// Once you've finished the write, YOU MUST CALL THIS METHOD: `finalize_put_stream`
    pub fn append_with_stream<S: AsRef<str>>(&mut self, filename: S) -> FtpResult<DataStream> {
        debug!("Appending to file {}", filename.as_ref());
        let stream = self.data_command(Command::Appe(filename.as_ref()))?;
        self.read_response_in(&[Status::AlreadyOpen, Status::AboutToSend])?;
        Ok(stream)
    }

    /// Append data from reader to file at `filename`
    pub fn append_file<R: Read>(&mut self, filename: &str, r: &mut R) -> FtpResult<u64> {
        // Get stream
        let mut data_stream = self.append_with_stream(filename)?;
        let bytes = copy(r, &mut data_stream).map_err(FtpError::ConnectionError)?;
        self.finalize_put_stream(Box::new(data_stream))?;
        Ok(bytes)
    }

    /// abort the previous FTP service command
    pub fn abort(&mut self, data_stream: impl Read) -> FtpResult<()> {
        debug!("Aborting active file transfer");
        self.perform(Command::Abor)?;
        // Drop stream NOTE: must be done first, otherwise server won't return any response
        drop(data_stream);
        trace!("dropped stream");
        self.read_response_in(&[Status::ClosingDataConnection, Status::TransferAborted])?;
        self.read_response(Status::ClosingDataConnection)?;
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
        self.perform(Command::Rest(offset))?;
        self.read_response(Status::RequestFilePending)?;
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
    pub fn nlst(&mut self, pathname: Option<&str>) -> FtpResult<Vec<String>> {
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
        self.perform(Command::Mdtm(pathname.as_ref()))?;
        let response: Response = self.read_response(Status::File)?;
        let body = response.as_string().map_err(|_| FtpError::BadResponse)?;

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
    pub fn size<S: AsRef<str>>(&mut self, pathname: S) -> FtpResult<usize> {
        debug!("Getting file size for {}", pathname.as_ref());
        self.perform(Command::Size(pathname.as_ref()))?;
        let response: Response = self.read_response(Status::File)?;
        let body = response.as_string().map_err(|_| FtpError::BadResponse)?;

        match SIZE_RE.captures(&body) {
            Some(caps) => Ok(caps[1].parse().unwrap()),
            None => Err(FtpError::BadResponse),
        }
    }

    // -- private

    /// Retrieve stream "message"
    fn get_lines_from_stream(stream: &mut BufReader<impl std::io::Read>) -> FtpResult<Vec<String>> {
        let mut lines: Vec<String> = Vec::new();

        loop {
            let mut line = String::new();
            match stream.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if line.ends_with('\n') {
                        line.pop();
                        if line.ends_with('\r') {
                            line.pop();
                        }
                    }
                    if line.is_empty() {
                        continue;
                    }
                    lines.push(line);
                }
                Err(_) => return Err(FtpError::BadResponse),
            }
        }
        trace!("Lines from stream {:?}", lines);

        Ok(lines)
    }

    /// Read response from stream
    fn read_response(&mut self, expected_code: Status) -> FtpResult<Response> {
        self.read_response_in(&[expected_code])
    }

    /// Retrieve single line response
    fn read_response_in(&mut self, expected_code: &[Status]) -> FtpResult<Response> {
        let mut line = Vec::new();
        self.read_line(&mut line)?;

        trace!("CC IN: {:?}", line);

        if line.len() < 5 {
            return Err(FtpError::BadResponse);
        }

        let code_word: u32 = self.code_from_buffer(&line, 3)?;
        let code = Status::from(code_word);

        trace!("Code parsed from response: {} ({})", code, code_word);

        // multiple line reply
        // loop while the line does not begin with the code and a space
        let expected = [line[0], line[1], line[2], 0x20];
        while line.len() < 5 || line[0..4] != expected {
            line.clear();
            self.read_line(&mut line)?;
            if let Ok(line) = std::str::from_utf8(&line) {
                trace!("CC IN: {:?}", line);
            }
            else {
                trace!("CC IN: {:?}", line);
            }
        }

        let response: Response = Response::new(code, line);
        // Return Ok or error with response
        if expected_code.iter().any(|ec| code == *ec) {
            Ok(response)
        } else {
            Err(FtpError::UnexpectedResponse(response))
        }
    }

    /// Read bytes from reader until 0x0A or EOF is found
    fn read_line(&mut self, line: &mut Vec<u8>) -> FtpResult<usize> {
        self.cmd_stream
            .read_until(0x0A, line.as_mut())
            .map_err(FtpError::ConnectionError)?;
        Ok(line.len())
    }

    /// Get code from buffer
    fn code_from_buffer(&self, buf: &[u8], len: usize) -> Result<u32, FtpError> {
        if buf.len() < len {
            return Err(FtpError::BadResponse);
        }
        let buffer = buf[0..len].to_vec();
        let as_string = String::from_utf8(buffer).map_err(|_| FtpError::BadResponse)?;
        as_string.parse::<u32>().map_err(|_| FtpError::BadResponse)
    }

    /// Write data to stream with command to perform
    fn perform(&mut self, command: Command) -> FtpResult<()> {
        trace!("CC OUT: {command}");

        let stream = self.cmd_stream.get_mut();
        write!(stream,"{command}\r\n").map_err(FtpError::ConnectionError)
    }

    /// Execute command which send data back in a separate stream
    fn data_command(&mut self, cmd: Command) -> FtpResult<stream::DataStream> {
        let stream = match self.mode {
            Mode::Active => {
                let listener = self.active()?;
                self.perform(cmd)?;
                let (stream,_addr) = listener.accept().map_err(FtpError::ConnectionError)?;
                stream::DataStream::Tcp(stream)
            },
            Mode::Passive => {
                let peer_addr = self.cmd_stream.get_ref().peer_addr()?;

                let sock = if peer_addr.is_ipv4() {
                    self.pasv()?
                }
                else {
                    self.epsv()?
                };

                let stream = if let Some(timeout) = self.timeout {
                    self.cmd_stream.get_ref().connect_data_timeout(sock, timeout)?
                }
                else {
                    self.cmd_stream.get_ref().connect_data(sock)?
                };

                self.perform(cmd)?;

                stream
            },
        };

        Ok(stream)
    }

    /// Create a new tcp listener and send a PORT command for it
    fn active(&mut self) -> FtpResult<TcpListener> {
        debug!("Starting local tcp listener...");
        let conn = TcpListener::bind("0.0.0.0:0").map_err(FtpError::ConnectionError)?;

        let addr = conn.local_addr().map_err(FtpError::ConnectionError)?;
        trace!("Local address is {}", addr);

        let ip = self.cmd_stream.get_ref().local_addr()?.ip();
        let ext_sock = SocketAddr::new(ip, addr.port());

        match ext_sock {
            SocketAddr::V4(sock) => {
                debug!("Running PORT command");
                self.perform(Command::Port(sock))?;

                debug!("Active mode, listening on {}", sock);
            },
            SocketAddr::V6(_) => {
                debug!("Running EPRT command");
                self.perform(Command::Eprt(ext_sock))?;

                debug!("Active mode, listening on {}:{}", ip, addr.port());
            },
        }
        self.read_response(Status::CommandOk)?;

        Ok(conn)
    }

    /// Runs the EPSV to enter Extended passive mode.
    fn epsv(&mut self) -> FtpResult<SocketAddr> {
        debug!("EPSV command");
        self.perform(Command::Epsv)?;
        // PASV response format : 229 Entering Extended Passive Mode (|||PORT|)
        let response: Response = self.read_response(Status::ExtendedPassiveMode)?;
        let response_str = response.as_string().map_err(|_| FtpError::BadResponse)?;
        let caps = EPSV_PORT_RE
            .captures(&response_str)
            .ok_or_else(|| FtpError::UnexpectedResponse(response.clone()))?;
        let new_port = caps[1].parse::<u16>().unwrap();
        trace!("Got port number from EPSV: {}", new_port);
        let mut remote = self
            .cmd_stream
            .get_ref()
            .get_stream_ref()
            .peer_addr()
            .map_err(FtpError::ConnectionError)?;
        remote.set_port(new_port);
        trace!("Remote address for extended passive mode is {}", remote);
        Ok(remote)
    }

    /// Runs the PASV command  to enter passive mode.
    fn pasv(&mut self) -> FtpResult<SocketAddr> {
        debug!("PASV command");
        self.perform(Command::Pasv)?;
        // PASV response format : 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
        let response: Response = self.read_response(Status::PassiveMode)?;
        let response_str = response.as_string().map_err(|_| FtpError::BadResponse)?;
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
                .cmd_stream
                .get_ref()
                .get_stream_ref()
                .peer_addr()
                .map_err(FtpError::ConnectionError)?;
            remote.set_port(port);
            trace!("Replacing site local address {} with {}", addr, remote);
            Ok(remote)
        } else {
            Ok(addr)
        }
    }

    /// Execute a command which returns list of strings in a separate stream
    fn stream_lines(&mut self, cmd: Command, open_code: Status) -> FtpResult<Vec<String>> {
        let mut data_stream = BufReader::new(self.data_command(cmd)?);
        self.read_response_in(&[open_code, Status::AlreadyOpen])?;
        let lines = Self::get_lines_from_stream(&mut data_stream);
        self.finalize_retr_stream(data_stream)?;
        lines
    }
}
