use std::error::Error;
use std::fs::File;
use std::io::{BufReader, Read};
use std::marker::PhantomData;

pub type DiskStorageReader<T> = BincodeIterator<T, BufReader<File>>;

/// Lazy iterator for bincode-encoded, length-prefixed data
pub struct BincodeIterator<T, R: Read> {
    reader: R,
    _phantom: PhantomData<T>,
}

impl<T> BincodeIterator<T, BufReader<File>>
where
    T: bincode::Decode<()>,
{
    /// Create a new iterator from a file path
    pub fn from_path(file_path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = File::open(file_path)?;
        let reader = BufReader::new(file);
        Ok(Self {
            reader,
            _phantom: PhantomData,
        })
    }

    pub fn from_file(file: std::fs::File) -> Self {
        Self {
            reader: BufReader::new(file),
            _phantom: PhantomData,
        }
    }
}

impl<T, R: Read> BincodeIterator<T, R>
where
    T: bincode::Decode<()>,
{
    /// Create a new iterator from any reader
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            _phantom: PhantomData,
        }
    }
}

impl<T, R: Read> BincodeIterator<T, R> {
    /// Read the next length-prefixed record as raw bytes, WITHOUT decoding it.
    ///
    /// Decoding (bincode) is CPU-heavy; reading the raw blob here (cheap I/O)
    /// lets the caller push the decode work onto worker threads instead of
    /// paying for it single-threaded on the reader thread.
    pub fn next_raw(&mut self) -> Option<std::io::Result<Vec<u8>>> {
        let mut len_bytes = [0u8; 4];
        match self.reader.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(e)),
        }

        let len = u32::from_le_bytes(len_bytes) as usize;

        let mut data = vec![0u8; len];
        if let Err(e) = self.reader.read_exact(&mut data) {
            return Some(Err(e));
        }

        Some(Ok(data))
    }
}

impl<T, R: Read> Iterator for BincodeIterator<T, R>
where
    T: bincode::Decode<()>,
{
    type Item = Result<T, Box<dyn Error>>;

    fn next(&mut self) -> Option<Self::Item> {
        // Try to read length prefix
        let mut len_bytes = [0u8; 4];
        match self.reader.read_exact(&mut len_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Clean EOF - no more records
                return None;
            }
            Err(e) => return Some(Err(e.into())),
        }

        let len = u32::from_le_bytes(len_bytes) as usize;

        // Validate length to prevent excessive allocation
        // if len > 100_000_000 {
        //     // 100MB limit, adjust as needed
        //     return Some(Err(format!(
        //         "Item length {len} exceeds maximum allowed size"
        //     )
        //     .into()));
        // }

        // Read the exact amount of data for this item
        let mut data = vec![0u8; len];
        if let Err(e) = self.reader.read_exact(&mut data) {
            return Some(Err(format!("Failed to read {len} bytes: {e}").into()));
        }

        // Decode the item
        match bincode::decode_from_slice::<T, _>(&data, bincode::config::standard()) {
            Ok((item, _)) => Some(Ok(item)),
            Err(e) => Some(Err(format!("Failed to decode item: {e:?}").into())),
        }
    }
}
