use crate::Status;

use super::lines::ReadLine;

pub struct ResponseReader<'a,R> {
    reader : &'a mut R,
    response : &'a mut Response
}

impl<R : ReadLine> ResponseReader<'_,R> {
    #[inline(always)]
    pub fn new(reader : &mut R, response : &mut Response) -> Self {
        ResponseReader { reader, response }
    }

    pub fn status(&self) -> Status {
        self.response.status
    }
    #[inline(always)]
    pub fn next_line(&mut self) -> std::io::Result<Option<&str>> {
        self.response.next_line(self.reader)
    }

    #[inline(always)]
    pub fn body(&mut self) -> impl Iterator<Item = std::io::Result<String>> + '_ {
        self.response.lines.clone()
            .into_iter()
            .map(Ok)
            .chain(
                std::iter::from_fn(|| 
                    Some(
                        self.response.next_line(&mut self.reader)
                            .transpose()?
                            .map(ToString::to_string)
                    )
                )
            )
    }

    #[inline(always)]
    pub fn finalise(mut self) -> std::io::Result<crate::types::CompleteResponse> {
        let resp = self.response.finalise(&mut self.reader);
        (self.reader,resp)
    }
}



/// Defines a response from the ftp server
pub struct Response {
    status: Status,
    lines : Vec<String>,
    finished : bool,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Response");
        d.field("status", &self.status);
        d.finish()
    }
}

impl Response {
    pub fn status(&self) -> Status {
        self.status
    }

    pub fn new<R : ReadLine>(reader : R) -> std::io::Result<Self> {
        let first_line = reader.next_line()?
            .timeout_error()?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "FTP Stream closed without response"))?;

        let Some((code_str,text)) = first_line.split_once([' ','-']) else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "FTP Response did not contain response code"));
        };

        let finished = first_line.chars().nth(code_str.len()) == Some('-');

        let code : u32 = code_str.parse().map_err(
            |e|
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("FTP Response did not contain response code\n{e:?}"))
        )?;

        let status = Status::from(code);

        Ok(
            Self {
                status,
                finished,
                lines: vec![first_line],
            }
        )
    }

    pub fn next_line<R : ReadLine>(&mut self, reader : R) -> std::io::Result<Option<&str>> {
        if self.finished { return Ok(None); }

        let Some(line) = self.reader.next_line()
            .and_then(|l| l.timeout_error())?
            else {
                self.finished = true;
                return Ok(None);
            };

        if line.chars().nth(4) != Some('-') {
            self.finished = true;
        }

        let data = line.split_once(['-',' '])
            .ok_or_else(||
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Expected response line to start with "
                )
            )?
            .1
            .trim_end()
            .to_string();

        self.lines.push(data);

        Ok(Some(self.lines.last().unwrap()))
    }

    pub fn body<R : ReadLine>(&mut self, reader : R) -> impl Iterator<Item = std::io::Result<String>> + '_ {
        self.lines.clone()
            .into_iter()
            .map(Ok)
            .chain(
                std::iter::from_fn(|| 
                    Some(
                        self.next_line(&mut reader)
                            .transpose()?
                            .map(ToString::to_string)
                    )
                )
            )
    }

    pub fn finalise<R : ReadLine>(mut self, reader : R) -> std::io::Result<crate::types::CompleteResponse> {
        while let Some(_) = self.next_line(&mut reader)? {

        }

        Ok(
            crate::types::CompleteResponse { status: self.status, lines : self.lines }
        )
    }
}