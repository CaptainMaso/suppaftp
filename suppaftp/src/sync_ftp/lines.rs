use std::io::{Write, BufRead};

pub trait ReadLine: Sized {
    fn next_line(&mut self) -> std::io::Result<Line>;
    fn iter(&mut self) -> ReadLineIter<&mut Self> {
        ReadLineIter { reader: self }
    }
}

impl<'a,L : ReadLine> ReadLine for &'a mut L {
    fn next_line(&mut self) -> std::io::Result<Line> {
        L::next_line(self)
    }
}

pub struct ReadLineIter<R : ?Sized + ReadLine> {
    reader : R
}

impl<R : ReadLine + ?Sized> std::iter::Iterator for ReadLineIter<R> {
    type Item = std::io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        self.reader.next_line()
            .and_then(|l| l.timeout_error())
            .transpose()
    }
}

pub enum Line {
    /// The next line including the end of line marker (\r\n or \n)
    Line(String),
    /// The next and last line that the iterator will return. May or may
    /// not have the end of line markers.
    /// 
    /// This is just the line that was received before the EOF.
    LastLine(String),
    /// The iterator timed out. The iterator will continue to accumulate
    /// the line if polled again, but the remaining data can be accessed via
    /// the `LineIter::finish`
    Timeout(std::time::Duration),
    /// End of data stream
    EOF
}

impl Line {
    pub fn timeout_error(self) -> Result<Option<String>,std::io::Error> {
        match self {
            Line::Line(s) |
            Line::LastLine(s) => Ok(Some(s)),
            Line::Timeout(t) => return Err(
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("Response timed out after {:.3}s", t.as_secs_f32())
                )
            ),
            Line::EOF => Ok(None)
        }
    }
}

impl<R : std::io::Read> ReadLine for Lines<R> {
    fn next_line(&mut self) -> std::io::Result<Line> {
        let mut read = 0;
        let t_start = std::time::Instant::now();
        while t_start.elapsed() < self.timeout {
            let pre_len = self.buffer_len();
            let available = match self.fill_buf() {
                Ok(data) => data,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };

            let eof = self.buffer_len() == pre_len;

            let found = available.iter()
                .skip(pre_len)
                .position(|b| *b == b'\n');
            
            let (line,into_line_fn) : (_,&dyn Fn(String) -> Line) = if let Some(nl_pos) = found {
                (&available[..nl_pos], &Line::Line)
            }
            else if eof {
                if self.buffer_empty() {
                    return Ok(Line::EOF);
                }
                (self.buffer(), &Line::LastLine)
            }
            else {
                continue;
            };

            self.consume(line.len());

            return std::str::from_utf8(line)
                .map(ToString::to_string)
                .map(into_line_fn)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData,e));
        }

        return Ok(Line::Timeout(self.timeout))
    }
}

/// This iterator iterates over the lines from a reader, but returns
/// timeouts inline to the iterator.
/// 
/// When the iterator returns None, that means the file has reached EOF.
pub struct Lines<R> {
    reader : R,
    timeout : std::time::Duration,
    buffer : Box<[u8]>,
    buffer_cursor : usize,
    buffer_end : usize,
}

impl<R> Lines<R> {
    pub fn new(reader : R, timeout : std::time::Duration) -> Self {
        Self { timeout, buffer: vec![0;1024].into(), buffer_cursor : 0, buffer_end : 0, reader }
    }
}

impl<R : std::io::Read> Lines<R> {
    pub fn first_line(&mut self) -> std::io::Result<String> {
        self.next_line()?
            .timeout_error()?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof,"Did not get any response from server"))
    }

    pub fn buffer_empty(&self) -> bool {
        self.buffer_cursor == self.buffer_end
    }

    pub fn buffer_len(&self) -> usize {
        self.buffer_end - self.buffer_cursor
    }

    pub fn buffer_full(&self) -> bool {
        self.buffer_end == self.buffer.len()
    }

    pub fn grow_buffer(&mut self) {
        let buffer_len = self.buffer_len();
        let new_cap = self.buffer.len() * 2;
        let mut new = Vec::with_capacity(new_cap);
        new.extend_from_slice(self.buffer());
        new.resize(new_cap, 0);
        self.buffer = new.into();
        self.buffer_cursor = 0;
        self.buffer_end = buffer_len;
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer[self.buffer_cursor..self.buffer_end]
    }

    pub fn timeout(&self) -> std::time::Duration {
        self.timeout
    }

    pub fn take(self) -> R {
        self.reader
    }
}

impl<R : std::io::Read> std::io::Read for Lines<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let int_buf = if self.buffer_empty() {
                self.fill_buf()?
            }
            else {
                self.buffer()
            };
            
        let len = int_buf.len().min(buf.len());
        (&mut buf[..len]).copy_from_slice(&int_buf[..len]);
        self.consume(len);
        Ok(len)
    }
}

impl<R : std::io::Read> BufRead for Lines<R> {
    fn consume(&mut self, consume : usize) {
        self.buffer_cursor += consume;
        self.buffer_cursor = self.buffer_cursor.min(self.buffer_end);
    }

    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.buffer_full() {
            self.grow_buffer();
        }

        if self.buffer_empty() {
            // Reset buffer if our cursor has caught the loaded data
            self.buffer_cursor = 0;
            self.buffer_end = 0;
        }

        let new_data = self.reader.read(&mut self.buffer[self.buffer_end..])?;

        self.buffer_end += new_data;

        Ok(self.buffer())
    }
}

impl<R : std::io::Write> std::io::Write for Lines<R> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush()
    }

    fn write_vectored(&mut self, bufs: &[std::io::IoSlice<'_>]) -> std::io::Result<usize> {
        self.write_vectored(bufs)
    }

    fn write_all(&mut self, mut buf: &[u8]) -> std::io::Result<()> {
        self.write_all(buf)
    }

    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> std::io::Result<()> {
        self.write_fmt(fmt)
    }
}

impl<R> std::ops::Deref for Lines<R> {
    type Target = R;

    fn deref(&self) -> &Self::Target {
        &self.reader
    }
}

impl<R> std::ops::DerefMut for Lines<R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.reader
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const SINGLE_LINE : &str = "THIS IS A SINGLE LINE";
    const SINGLE_LINE_NL_END : &str = "THIS IS A SINGLE LINE\n";
    const TWO_LINE : &str = "THIS IS A SINGLE LINE\nWITH AN EXTRA LINE TOO";
    const TWO_LINE_NL_END : &str = "THIS IS A SINGLE LINE\nWITH AN EXTRA LINE TOO WITH A NEW LINE\n";

    #[test]
    fn test_function() {
        let reader = Lines::new(LOREM_IPSUM.as_bytes(),std::time::Duration::from_secs(1));

        for l in reader.iter() {
            let l = l.unwrap();
            println!("{l}")
        }
    }

    const LOREM_IPSUM : &str = r##"
Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. 
Malesuada proin libero nunc consequat interdum varius. 
Tincidunt id aliquet risus feugiat in ante metus dictum. 
Dis parturient montes nascetur ridiculus mus mauris vitae. 
Eu augue ut lectus arcu. 
Eget duis at tellus at urna condimentum mattis pellentesque id. 
Amet consectetur adipiscing elit duis tristique sollicitudin. 
Eleifend quam adipiscing vitae proin sagittis nisl rhoncus mattis rhoncus. 
Dolor morbi non arcu risus quis varius quam. Sit amet risus nullam eget felis. 
Vulputate sapien nec sagittis aliquam malesuada bibendum. Vel pharetra vel turpis nunc. 
Justo eget magna fermentum iaculis eu. In aliquam sem fringilla ut morbi tincidunt augue interdum. 
Massa id neque aliquam vestibulum morbi. Tempus egestas sed sed risus pretium. Laoreet sit amet cursus sit. 
Bibendum ut tristique et egestas quis ipsum suspendisse ultrices. 
Molestie ac feugiat sed lectus vestibulum mattis ullamcorper.
"##;
}