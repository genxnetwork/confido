//! Tee Confido's attestation trace to stderr and an optional private run file.
use std::{
    fs::File,
    io::{self, Write},
    sync::{Mutex, OnceLock},
};
#[cfg(feature = "python")]
use std::{fs::OpenOptions, os::unix::fs::OpenOptionsExt, path::Path};
static LOG: OnceLock<Mutex<Option<File>>> = OnceLock::new();
pub(crate) struct Sink;
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        io::stderr().write_all(bytes)?;
        if let Ok(mut log) = LOG.get_or_init(|| Mutex::new(None)).lock() {
            if let Some(file) = log.as_mut() {
                file.write_all(bytes)?;
            }
        }
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        io::stderr().flush()
    }
}
#[cfg(feature = "python")]
pub(crate) struct Guard;
#[cfg(feature = "python")]
impl Guard {
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let mut log = LOG
            .get_or_init(|| Mutex::new(None))
            .lock()
            .map_err(|_| io::Error::other("Run logger unavailable"))?;
        if log.is_some() {
            return Err(io::Error::other("Another logged appraisal is active"));
        }
        *log = Some(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)?,
        );
        Ok(Self)
    }
}
#[cfg(feature = "python")]
impl Drop for Guard {
    fn drop(&mut self) {
        if let Ok(mut log) = LOG.get_or_init(|| Mutex::new(None)).lock() {
            *log = None;
        }
    }
}
