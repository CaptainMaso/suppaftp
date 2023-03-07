use crate::{FtpStream, FtpResult};

#[derive(Debug)]
#[must_use = "The file upload must be terminated with `FileUpload::finish()`"]
pub struct FileUpload<'a> {
    cmd_stream : &'a mut FtpStream,
    data_stream : std::io::BufWriter<super::DataStream>,
}

impl FileUpload<'_> {
    pub fn finish(self) -> FtpResult<()> {
        self.cmd_stream.finalize_put_stream(self.data_stream)
    }
}

impl std::io::Write for FileUpload<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.data_stream.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.data_stream.flush()
    }
}

#[derive(Debug)]
#[must_use = "The file download must be terminated with `FileUpload::finish()`"]
pub struct FileDownload<'a> {
    cmd_stream : &'a mut FtpStream,
    data_stream : std::io::BufReader<super::DataStream>,
}

impl FileDownload<'_> {
    pub fn finish(self) -> FtpResult<()> {
        self.cmd_stream.finalize_retr_stream(self.data_stream)
    }
}

impl std::io::Read for FileDownload<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.data_stream.read(buf)
    }
}

impl std::io::BufRead for FileDownload<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        self.data_stream.fill_buf()
    }

    fn consume(&mut self, amt: usize) {
        self.data_stream.consume(amt)
    }
}



#[cfg(test)]
mod test {
    pub fn test_file_download() {

    }
}