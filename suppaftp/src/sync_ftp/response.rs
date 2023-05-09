use crate::Status;

use super::lines::ReadLine;

pub(crate) struct ResponseReader<'a,R> {
    reader : &'a mut R,
    response : &'a mut Response
}

impl<'r, R : ReadLine> ResponseReader<'r,R> {
    #[inline(always)]
    pub fn new(reader : &'r mut R, response : &'r mut Response) -> Self {
        ResponseReader { reader, response }
    }

    pub fn status(&self) -> Status {
        self.response.status
    }

    #[inline(always)]
    pub fn next_line(&mut self) -> std::io::Result<Option<&str>> {
        self.response.next_line(&mut self.reader)
    }

    #[inline(always)]
    pub fn body(self) -> impl Iterator<Item = std::io::Result<String>> + 'r {
        self.response.body(self.reader)
    }

    #[inline(always)]
    pub fn finalise(self) -> std::io::Result<crate::types::CompleteResponse> {
        self.response.finalise(self.reader)
    }
}



/// Defines a response from the ftp server
pub(crate) struct Response {
    command : Option<crate::command::Command<'static>>,
    status: Status,
    lines : Vec<String>,
    finished : bool,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut d = f.debug_struct("Response");
        if let Some(cmd) = &self.command {
            d.field("command", cmd);
        }
        d.field("status", &self.status);
        d.field("finished", &self.finished);
        d.field("body", &self.lines.concat());
        d.finish()
    }
}

impl Response {
    pub fn status(&self) -> Status {
        self.status
    }

    pub fn new<R : ReadLine>(mut reader : R, command : Option<crate::command::Command<'static>>) -> std::io::Result<Self> {
        let first_line = reader.next_line()?
            .timeout_error()?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "FTP Stream closed without response"))?;

        let Some((code_str,text)) = first_line.split_once([' ','-']) else {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "FTP Response did not contain response code"));
        };

        let finished = first_line.chars().nth(code_str.len()) == Some(' ');

        let code : u32 = code_str.parse().map_err(
            |e|
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("FTP Response did not contain response code\n{e:?}"))
        )?;

        let status = Status::from(code);

        trace!("Response: {status} ({}) is {} from:\n   '{}'", text.trim(), if finished { "finished" } else { "not finished" }, first_line.escape_default());

        Ok(
            Self {
                command,
                status,
                finished,
                lines: vec![first_line],
            }
        )
    }

    pub fn next_line<R : ReadLine>(&mut self, mut reader : R) -> std::io::Result<Option<&str>> {
        if self.finished { return Ok(None); }

        let Some(line) = reader.next_line()
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

    pub fn body<'b, R : ReadLine + 'b>(&'b mut self, mut reader : &'b mut R) -> impl Iterator<Item = std::io::Result<String>> + 'b {
        self.lines.clone()
            .into_iter()
            .map(Ok)
            .chain(
                std::iter::from_fn(move || 
                    Some(
                        self.next_line(&mut reader)
                            .transpose()?
                            .map(ToString::to_string)
                    )
                )
            )
    }

    pub fn finalise<R : ReadLine>(&mut self, mut reader : R) -> std::io::Result<crate::types::CompleteResponse> {
        trace!("Finalising response");
        while let Some(l) = self.next_line(&mut reader)? {
            
        }

        Ok(
            crate::types::CompleteResponse { command : self.command.clone(), status: self.status, lines : std::mem::take(&mut self.lines) }
        )
    }
}