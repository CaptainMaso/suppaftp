

use super::*;
use crate::FtpStream;

use crate::types::FormatControl;

#[cfg(feature = "native-tls")]
use native_tls::TlsConnector;
#[cfg(feature = "with-containers")]
use pretty_assertions::assert_eq;
#[cfg(feature = "with-containers")]
use rand::{distributions::Alphanumeric, thread_rng, Rng};
#[cfg(feature = "rustls")]
use rustls::ClientConfig;
use serial_test::serial;

#[test]
#[cfg(feature = "with-containers")]
fn connect() {
    crate::log_init();
    let stream: FtpStream = setup_stream();
    finalize_stream(stream);
}


#[test]
#[serial]
fn should_connect_raw() {
    crate::log_init();
    use std::time::Duration;
    let mut ftp_stream = crate::FtpStream::connect("test.rebex.net:21").unwrap();
    
    // Set timeout (to test ref to ssl)
    assert!(ftp_stream
        .set_read_timeout(Duration::from_secs(10))
        .is_ok());
    // Login
    assert!(ftp_stream.login("demo", "password").is_ok());
    // PWD
    assert_eq!(ftp_stream.pwd().unwrap().as_str(), "/");
    println!("DIR: {:#?}", ftp_stream.list(None).unwrap().collect::<Result<Vec<_>,_>>().unwrap());
    // Quit
    assert!(ftp_stream.quit().is_ok());
}

#[test]
#[serial]
#[cfg(feature = "native-tls")]
fn should_connect_ssl_native_tls() {
    crate::log_init();
    use std::time::Duration;
    let ftp_stream = crate::FtpStream::connect("test.rebex.net:21").unwrap();
    let mut ftp_stream = ftp_stream
        .secure_with(
            "test.rebex.net",
            TlsConnector::new().unwrap(),
        )
        .unwrap();
    
    // Set timeout (to test ref to ssl)
    assert!(ftp_stream
        .set_read_timeout(Duration::from_secs(10))
        .is_ok());
    // Login
    assert!(ftp_stream.login("demo", "password").is_ok());
    // PWD
    assert_eq!(ftp_stream.pwd().unwrap().as_str(), "/");
    println!("DIR: {:#?}", ftp_stream.list(None).unwrap().collect::<Result<Vec<_>,_>>().unwrap());
    // Quit
    assert!(ftp_stream.quit().is_ok());
}

#[test]
#[serial]
#[cfg(feature = "native-tls")]
fn should_work_after_clear_command_channel_native_tls() {
    crate::log_init();
    let mut ftp_stream = crate::FtpStream::connect("test.rebex.net:21")
        .unwrap();
    ftp_stream.set_read_timeout(std::time::Duration::from_secs(5))
        .unwrap();

    let mut ftp_stream = ftp_stream.secure_with(
            "test.rebex.net",
            TlsConnector::new().unwrap(),
        )
        .unwrap()
        .into_insecure()
        .unwrap();
    // Login
    ftp_stream.login("demo", "password").unwrap();
    // CCC
    println!("PWD: {}", ftp_stream.pwd().unwrap());
    // PWD
    assert_eq!(ftp_stream.pwd().unwrap().as_str(), "/");
    println!("DIR: {:#?}", ftp_stream.list(None).unwrap().collect::<Result<Vec<_>,_>>().unwrap());
    ftp_stream.quit().unwrap();
}

#[test]
#[serial]
#[cfg(feature = "rustls")]
fn should_connect_ssl_rustls() {

    crate::log_init();
    let config = rustls_config();

    let mut ftp_stream = crate::FtpStream::connect("test.rebex.net:21").unwrap()
        .secure_with(
            "test.rebex.net",
            config,
        )
        .unwrap();

    // Set timeout (to test ref to ssl)
    assert!(ftp_stream
        .set_read_timeout(std::time::Duration::from_secs(10))
        .is_ok());
    // Login
    assert!(ftp_stream.login("demo", "password").is_ok());
    // PWD
    assert_eq!(ftp_stream.pwd().unwrap().as_str(), "/");
    println!("DIR: {:#?}", ftp_stream.list(None).unwrap().collect::<Result<Vec<_>,_>>().unwrap());
    // Quit
    assert!(ftp_stream.quit().is_ok());
}

#[test]
#[serial]
fn should_change_mode() {
    crate::log_init();
    let mut ftp_stream = FtpStream::connect("test.rebex.net:21")
        .map(|x| x.active_mode())
        .unwrap();
    assert_eq!(ftp_stream.mode, Mode::Active);
    ftp_stream.set_mode(Mode::Passive);
    assert_eq!(ftp_stream.mode, Mode::Passive);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn should_connect_with_timeout() {
    crate::log_init();
    let addr: SocketAddr = "127.0.0.1:10021".parse().expect("invalid hostname");
    let mut stream = FtpStream::connect_timeout(addr, std::time::Duration::from_secs(15)).unwrap();
    assert!(stream.login("test", "test").is_ok());
    assert_eq!(
        stream.get_welcome_msg().unwrap(),
        "220 You will be disconnected after 15 minutes of inactivity."
    );
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn welcome_message() {
    crate::log_init();
    let stream: FtpStream = setup_stream();
    assert_eq!(
        stream.get_welcome_msg().unwrap(),
        "220 You will be disconnected after 15 minutes of inactivity."
    );
    finalize_stream(stream);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn should_set_passive_nat_workaround() {
    crate::log_init();
    let mut stream: FtpStream = setup_stream();
    stream.set_passive_nat_workaround(true);
    assert!(stream.nat_workaround);
    finalize_stream(stream);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn get_ref() {
    use std::time::Duration;
    crate::log_init();
    let stream: FtpStream = setup_stream();
    assert!(stream
        .get_ref()
        .set_read_timeout(Some(Duration::from_secs(10)))
        .is_ok());
    finalize_stream(stream);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn change_wrkdir() {
    crate::log_init();
    let mut stream: FtpStream = setup_stream();
    let wrkdir: String = stream.pwd().unwrap();
    assert!(stream.cwd("/").is_ok());
    assert_eq!(stream.pwd().unwrap().as_str(), "/");
    assert!(stream.cwd(wrkdir.as_str()).is_ok());
    finalize_stream(stream);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn cd_up() {
    crate::log_init();
    let mut stream: FtpStream = setup_stream();
    let wrkdir: String = stream.pwd().unwrap();
    assert!(stream.cdup().is_ok());
    assert_eq!(stream.pwd().unwrap().as_str(), "/");
    assert!(stream.cwd(wrkdir.as_str()).is_ok());
    finalize_stream(stream);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn noop() {
    crate::log_init();
    let mut stream: FtpStream = setup_stream();
    assert!(stream.noop().is_ok());
    finalize_stream(stream);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn make_and_remove_dir() {
    crate::log_init();
    let mut stream: FtpStream = setup_stream();
    // Make directory
    assert!(stream.mkdir("omar").is_ok());
    // It shouldn't allow me to re-create the directory; should return error code 550
    match stream.mkdir("omar").err().unwrap() {
        FtpError::UnexpectedResponse(Response { status, body: _ }) => {
            assert_eq!(status, Status::FileUnavailable)
        }
        err => panic!("Expected UnexpectedResponse, got {}", err),
    }
    // Remove directory
    assert!(stream.rmdir("omar").is_ok());
    finalize_stream(stream);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn set_transfer_type() {
    crate::log_init();
    let mut stream: FtpStream = setup_stream();
    assert!(stream.transfer_type(FileType::Binary).is_ok());
    assert!(stream
        .transfer_type(FileType::Ascii(FormatControl::Default))
        .is_ok());
    finalize_stream(stream);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn should_transfer_file() {
    crate::log_init();
    let mut stream: FtpStream = setup_stream();
    // Set transfer type to Binary
    assert!(stream.transfer_type(FileType::Binary).is_ok());
    // Write file
    let file_data = "test data\n";
    let mut reader = Cursor::new(file_data.as_bytes());
    assert!(stream.put_file("test.txt", &mut reader).is_ok());
    // Read file
    assert_eq!(
        stream
            .retr_as_buffer("test.txt")
            .map(|bytes| bytes.into_inner())
            .unwrap(),
        file_data.as_bytes()
    );
    // Get size
    assert_eq!(stream.size("test.txt").unwrap(), 10);
    // Size of non-existing file
    assert!(stream.size("omarone.txt").is_err());
    // List directory
    assert_eq!(stream.list(None).unwrap().len(), 1);
    // list names
    assert_eq!(stream.nlst(None).unwrap().as_slice(), &["test.txt"]);
    // modification time
    assert!(stream.mdtm("test.txt").is_ok());
    // Remove file
    assert!(stream.rm("test.txt").is_ok());
    assert!(stream.mdtm("test.txt").is_err());
    // Write file, rename and get
    let file_data = "test data\n";
    let mut reader = Cursor::new(file_data.as_bytes());
    assert!(stream.put_file("test.txt", &mut reader).is_ok());
    // Append file
    let mut reader = Cursor::new(file_data.as_bytes());
    assert!(stream.append_file("test.txt", &mut reader).is_ok());
    // Read file
    let mut reader = stream.retr_as_stream("test.txt").unwrap();
    let mut buffer = Vec::new();
    assert!(reader.read_to_end(&mut buffer).is_ok());
    // Finalize
    assert!(stream.finalize_retr_stream(Box::new(reader)).is_ok());
    // Verify file matches
    assert_eq!(buffer.as_slice(), "test data\ntest data\n".as_bytes());
    // Rename
    assert!(stream.rename("test.txt", "toast.txt").is_ok());
    assert!(stream.rm("toast.txt").is_ok());
    // List directory again
    assert_eq!(stream.list(None).unwrap().len(), 0);
    finalize_stream(stream);
}

#[test]
#[cfg(feature = "with-containers")]
#[serial]
fn should_abort_transfer() {
    crate::log_init();
    let mut stream: FtpStream = setup_stream();
    // Set transfer type to Binary
    assert!(stream.transfer_type(FileType::Binary).is_ok());
    // put as stream
    let mut transfer_stream = stream.put_with_stream("test.bin").unwrap();
    assert_eq!(
        transfer_stream
            .write(&[0x00, 0x01, 0x02, 0x03, 0x04])
            .unwrap(),
        5
    );
    // Abort
    assert!(stream.abort(transfer_stream).is_ok());
    // Check whether other commands still work after transfer
    assert!(stream.rm("test.bin").is_ok());
    // Check whether data channel still works
    assert!(stream.list(None).is_ok());
    finalize_stream(stream);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn should_resume_transfer() {
    crate::log_init();
    let mut stream: FtpStream = setup_stream();
    // Set transfer type to Binary
    assert!(stream.transfer_type(FileType::Binary).is_ok());
    // get dir
    let wrkdir = stream.pwd().unwrap();
    // put as stream
    let mut transfer_stream = stream.put_with_stream("test.bin").unwrap();
    assert_eq!(
        transfer_stream
            .write(&[0x00, 0x01, 0x02, 0x03, 0x04])
            .unwrap(),
        5
    );
    // Drop stream on purpose to simulate a failed connection
    drop(stream);
    drop(transfer_stream);
    // Re-connect to server
    let mut stream = FtpStream::connect("127.0.0.1:10021").unwrap();
    assert!(stream.login("test", "test").is_ok());
    // Go back to previous dir
    assert!(stream.cwd(wrkdir).is_ok());
    // Set transfer type to Binary
    assert!(stream.transfer_type(FileType::Binary).is_ok());
    // Resume transfer
    assert!(stream.resume_transfer(5).is_ok());
    // Reopen stream
    let mut transfer_stream = stream.put_with_stream("test.bin").unwrap();
    assert_eq!(
        transfer_stream
            .write(&[0x05, 0x06, 0x07, 0x08, 0x09, 0x0a])
            .unwrap(),
        6
    );
    // Finalize
    assert!(stream.finalize_put_stream(transfer_stream).is_ok());
    // Get size
    assert_eq!(stream.size("test.bin").unwrap(), 11);
    // Remove file
    assert!(stream.rm("test.bin").is_ok());
    // Drop stream
    finalize_stream(stream);
}

#[test]
#[serial]
#[cfg(feature = "with-containers")]
fn should_transfer_file_with_extended_passive_mode() {
    crate::log_init();
    let mut stream: FtpStream = setup_stream();
    // Set transfer type to Binary
    assert!(stream.transfer_type(FileType::Binary).is_ok());
    // Write file
    let file_data = "test data\n";
    let mut reader = Cursor::new(file_data.as_bytes());
    assert!(stream.put_file("test.txt", &mut reader).is_ok());
    // Remove file
    assert!(stream.rm("test.txt").is_ok());
    finalize_stream(stream);
}

// -- test utils

#[cfg(feature = "with-containers")]
fn setup_stream() -> FtpStream {
    let mut ftp_stream = FtpStream::connect("127.0.0.1:10021").unwrap();
    assert!(ftp_stream.login("test", "test").is_ok());
    // Create wrkdir
    let tempdir: String = generate_tempdir();
    assert!(ftp_stream.mkdir(tempdir.as_str()).is_ok());
    // Change directory
    assert!(ftp_stream.cwd(tempdir.as_str()).is_ok());
    ftp_stream
}

#[cfg(feature = "with-containers")]
fn finalize_stream(mut stream: FtpStream) {
    // Get working directory
    let wrkdir: String = stream.pwd().unwrap();
    // Remove directory
    assert!(stream.rmdir(wrkdir.as_str()).is_ok());
    assert!(stream.quit().is_ok());
}

#[cfg(feature = "with-containers")]
fn generate_tempdir() -> String {
    let mut rng = thread_rng();
    let name: String = std::iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(5)
        .collect();
    format!("temp_{}", name)
}

#[cfg(feature = "rustls")]
fn rustls_config() -> ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_server_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.0.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));
    ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth()
}