use std::io::{Cursor, Read, Write};

pub struct LengthEncodedReader {
    cursor: Cursor<Vec<u8>>,
}

impl LengthEncodedReader {
    pub fn new(cursor: Vec<u8>) -> Self {
        Self { cursor: Cursor::new(cursor) }
    }

    pub fn read_length_encoded(&mut self) -> std::io::Result<Vec<u8>> {
        let mut len = [0u8; 4];
        self.cursor.read_exact(&mut len)?;
        let len = u32::from_be_bytes(len) as usize;
        let mut buf = vec![0u8; len];
        self.cursor.read_exact(&mut buf)?;
        Ok(buf)
    }
}

pub struct LengthEncodedWriter {
    cursor: Cursor<Vec<u8>>,
}

impl LengthEncodedWriter {
    pub fn new() -> Self {
        Self { cursor: Cursor::new(Vec::new()) }
    }

    pub fn write_length_encoded(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let len = buf.len() as u32;
        self.cursor.write_all(&len.to_be_bytes())?;
        self.cursor.write_all(buf)?;
        Ok(())
    }

    pub fn take(self) -> Vec<u8> {
        self.cursor.into_inner()
    }
}
