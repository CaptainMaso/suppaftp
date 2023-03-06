pub mod asynchronous;

#[derive(Debug,Default)]
pub struct FtpBuilder {
    
}

impl FtpBuilder {
    pub fn into_async() -> asynchronous::AsyncFtpBuilder {
        asynchronous::AsyncFtpBuilder::default()
    }
}