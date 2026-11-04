use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;

const MAX_BYTES: usize = 1024 * 1024;
const MAX_READS: usize = 4096;
const RECORD_BUFFER_BYTES: usize = 64 * 1024;
const UNAVAILABLE: &str = "no dmesg available";
const TRUNCATED: &str = "dmesg truncated: collection limit reached";

/// Read available /dev/kmsg records without clearing the ring buffer or waiting
/// for new messages. Preserve the kernel's priority, sequence and time metadata.
pub fn read() -> Vec<String> {
    let result = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open("/dev/kmsg")
        .and_then(|mut device| collect(&mut device, MAX_BYTES, MAX_READS));

    available_or_placeholder(result)
}

fn available_or_placeholder(result: io::Result<Vec<String>>) -> Vec<String> {
    match result {
        Ok(records) if !records.is_empty() => records,
        _ => vec![UNAVAILABLE.to_string()],
    }
}

fn collect(reader: &mut impl Read, max_bytes: usize, max_reads: usize) -> io::Result<Vec<String>> {
    // kmsg reads return whole records; BufRead::lines() is unsuitable because
    // a short buffer can fail a read and one record can contain multiple lines.
    let mut buffer = vec![0; RECORD_BUFFER_BYTES];
    let mut records = Vec::new();
    let mut bytes = 0;

    for _ in 0..max_reads {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(records),
            Ok(size) => {
                if size > max_bytes - bytes {
                    records.push(TRUNCATED.to_string());
                    return Ok(records);
                }
                bytes += size;
                records.push(
                    String::from_utf8_lossy(&buffer[..size])
                        .trim_end_matches('\n')
                        .to_string(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(records),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                // The kernel advances the cursor when records were overwritten.
                records.push("dmesg records lost: kernel ring buffer overwritten".to_string());
            }
            Err(error) => return Err(error),
        }
    }

    // Also bound attempts so continuous writes or overruns cannot hold a request.
    records.push(TRUNCATED.to_string());
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    struct Device(VecDeque<io::Result<Vec<u8>>>);

    impl Read for Device {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            match self
                .0
                .pop_front()
                .unwrap_or_else(|| Err(io::ErrorKind::WouldBlock.into()))
            {
                Ok(record) => {
                    assert!(record.len() <= buffer.len());
                    buffer[..record.len()].copy_from_slice(&record);
                    Ok(record.len())
                }
                Err(error) => Err(error),
            }
        }
    }

    #[test]
    fn preserves_record_metadata_and_multiline_context_then_stops_at_would_block() {
        let record = "6,339,5140900,-;NET: Registered protocol family 10\n SUBSYSTEM=net\n";
        let mut device = Device(VecDeque::from([Ok(record.as_bytes().to_vec())]));
        assert_eq!(
            collect(&mut device, MAX_BYTES, MAX_READS).unwrap(),
            vec![record.trim_end()]
        );
    }

    #[test]
    fn retries_interrupts_and_reports_overwritten_records() {
        let mut device = Device(VecDeque::from([
            Err(io::ErrorKind::Interrupted.into()),
            Err(io::ErrorKind::BrokenPipe.into()),
            Ok(b"6,340,5140901,-;next\n".to_vec()),
        ]));
        let records = collect(&mut device, MAX_BYTES, MAX_READS).unwrap();
        assert!(records[0].contains("records lost"));
        assert_eq!(records[1], "6,340,5140901,-;next");
    }

    #[test]
    fn limits_bytes_without_cutting_records() {
        let mut device = Device(VecDeque::from([
            Ok(b"abc\n".to_vec()),
            Ok(b"def\n".to_vec()),
        ]));
        assert_eq!(
            collect(&mut device, 5, MAX_READS).unwrap(),
            vec!["abc", TRUNCATED]
        );
    }

    #[test]
    fn bounds_attempts_even_when_reads_keep_getting_interrupted() {
        let mut device = Device(VecDeque::from([
            Err(io::ErrorKind::Interrupted.into()),
            Err(io::ErrorKind::Interrupted.into()),
        ]));
        assert_eq!(collect(&mut device, MAX_BYTES, 2).unwrap(), vec![TRUNCATED]);
    }

    #[test]
    fn propagates_device_errors_for_unavailable_fallback() {
        let mut device = Device(VecDeque::from([
            Err(io::ErrorKind::PermissionDenied.into()),
        ]));
        assert_eq!(
            collect(&mut device, MAX_BYTES, MAX_READS)
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn empty_buffer_returns_without_waiting() {
        let mut device = Device(VecDeque::new());
        assert!(collect(&mut device, MAX_BYTES, MAX_READS)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn missing_denied_and_empty_devices_have_a_diagnostic_placeholder() {
        for kind in [io::ErrorKind::NotFound, io::ErrorKind::PermissionDenied] {
            assert_eq!(
                available_or_placeholder(Err(kind.into())),
                vec![UNAVAILABLE]
            );
        }
        assert_eq!(available_or_placeholder(Ok(Vec::new())), vec![UNAVAILABLE]);
    }
}
