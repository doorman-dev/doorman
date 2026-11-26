//! AWS event-stream framing (`application/vnd.amazon.eventstream`).

use bytes::{Buf, Bytes};

use crate::ai::sse::SseEvent;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub headers: Vec<(String, String)>,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    PreludeCrc,
    MessageCrc,
    TooLarge(usize),
    Malformed(&'static str),
}

const PRELUDE_LEN: usize = 12;
const OVERHEAD: usize = PRELUDE_LEN + 4;

pub struct Decoder {
    max_frame: usize,
    buffer: Vec<u8>,
    lengths: Option<(usize, usize)>,
    stopped: bool,
}

impl Decoder {
    /// True when a frame is half-received or decoding stopped on bad framing.
    pub fn has_partial(&self) -> bool {
        self.stopped || self.lengths.is_some() || !self.buffer.is_empty()
    }

    pub fn new(max_frame: usize) -> Self {
        Self {
            max_frame,
            buffer: Vec::new(),
            lengths: None,
            stopped: false,
        }
    }

    /// Frames completed by this chunk. An invalid prelude ends decoding because
    /// there is no reliable framing boundary from which to resume.
    pub fn push(&mut self, mut chunk: &[u8]) -> Vec<Result<Frame, DecodeError>> {
        let mut frames = Vec::new();
        while !chunk.is_empty() && !self.stopped {
            if self.lengths.is_none() {
                self.fill(&mut chunk, PRELUDE_LEN);
                if self.buffer.len() < PRELUDE_LEN {
                    break;
                }
                match self.prelude() {
                    Ok(lengths) => self.lengths = Some(lengths),
                    Err(error) => {
                        frames.push(Err(error));
                        self.buffer.clear();
                        self.stopped = true;
                        break;
                    }
                }
            }
            let (total, headers) = self.lengths.expect("validated prelude");
            self.fill(&mut chunk, total);
            if self.buffer.len() == total {
                frames.push(decode_frame(&self.buffer, headers));
                self.buffer.clear();
                self.lengths = None;
            }
        }
        frames
    }

    fn fill(&mut self, chunk: &mut &[u8], target: usize) {
        let len = chunk.len().min(target - self.buffer.len());
        self.buffer.extend_from_slice(&chunk[..len]);
        *chunk = &chunk[len..];
    }

    fn prelude(&self) -> Result<(usize, usize), DecodeError> {
        let mut bytes = self.buffer.as_slice();
        let total = bytes.get_u32() as usize;
        let headers = bytes.get_u32() as usize;
        if crc32fast::hash(&self.buffer[..8]) != bytes.get_u32() {
            return Err(DecodeError::PreludeCrc);
        }
        if total > self.max_frame {
            return Err(DecodeError::TooLarge(total));
        }
        if total < OVERHEAD || headers > total - OVERHEAD {
            return Err(DecodeError::Malformed("invalid frame lengths"));
        }
        Ok((total, headers))
    }
}

fn decode_frame(bytes: &[u8], headers_len: usize) -> Result<Frame, DecodeError> {
    let (message, mut checksum) = bytes.split_at(bytes.len() - 4);
    if crc32fast::hash(message) != checksum.get_u32() {
        return Err(DecodeError::MessageCrc);
    }
    let (mut raw_headers, payload) = message[PRELUDE_LEN..].split_at(headers_len);
    let mut headers = Vec::new();
    while !raw_headers.is_empty() {
        let len = raw_headers.get_u8() as usize;
        let name = std::str::from_utf8(take(&mut raw_headers, len)?)
            .map_err(|_| DecodeError::Malformed("invalid UTF-8 header name"))?;
        let [kind] = *take(&mut raw_headers, 1)? else {
            unreachable!("take returns the requested length")
        };
        let value = match kind {
            0 => "true".into(),
            1 => "false".into(),
            2 => take(&mut raw_headers, 1)?.get_i8().to_string(),
            3 => take(&mut raw_headers, 2)?.get_i16().to_string(),
            4 => take(&mut raw_headers, 4)?.get_i32().to_string(),
            5 | 8 => take(&mut raw_headers, 8)?.get_i64().to_string(),
            6 | 7 => {
                let len = take(&mut raw_headers, 2)?.get_u16() as usize;
                let value = take(&mut raw_headers, len)?;
                if kind == 6 {
                    hex_text(value)
                } else {
                    std::str::from_utf8(value)
                        .map_err(|_| DecodeError::Malformed("invalid UTF-8 header value"))?
                        .to_owned()
                }
            }
            9 => {
                let bytes = hex_text(take(&mut raw_headers, 16)?);
                format!(
                    "{}-{}-{}-{}-{}",
                    &bytes[..8],
                    &bytes[8..12],
                    &bytes[12..16],
                    &bytes[16..20],
                    &bytes[20..]
                )
            }
            _ => return Err(DecodeError::Malformed("unknown header type")),
        };
        headers.push((name.to_owned(), value));
    }
    Ok(Frame {
        headers,
        payload: Bytes::copy_from_slice(payload),
    })
}

fn take<'a>(bytes: &mut &'a [u8], len: usize) -> Result<&'a [u8], DecodeError> {
    if len > bytes.len() {
        return Err(DecodeError::Malformed("truncated header"));
    }
    let (prefix, rest) = bytes.split_at(len);
    *bytes = rest;
    Ok(prefix)
}

fn hex_text(bytes: &[u8]) -> String {
    use std::fmt::Write;

    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("writing to String");
    }
    text
}

/// One frame with string headers (tests and the demo mock).
pub fn encode(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let mut raw_headers = Vec::new();
    for (name, value) in headers {
        raw_headers.push(u8::try_from(name.len()).expect("header name fits in one byte"));
        raw_headers.extend_from_slice(name.as_bytes());
        raw_headers.push(7);
        raw_headers.extend_from_slice(
            &u16::try_from(value.len())
                .expect("header value fits in two bytes")
                .to_be_bytes(),
        );
        raw_headers.extend_from_slice(value.as_bytes());
    }
    encode_message(&raw_headers, payload)
}

fn encode_message(headers: &[u8], payload: &[u8]) -> Vec<u8> {
    let len = OVERHEAD + headers.len() + payload.len();
    let mut message = Vec::with_capacity(len);
    message.extend_from_slice(
        &u32::try_from(len)
            .expect("frame fits in four bytes")
            .to_be_bytes(),
    );
    message.extend_from_slice(&(headers.len() as u32).to_be_bytes());
    message.extend_from_slice(&crc32fast::hash(&message).to_be_bytes());
    message.extend_from_slice(headers);
    message.extend_from_slice(payload);
    message.extend_from_slice(&crc32fast::hash(&message).to_be_bytes());
    message
}

impl Frame {
    /// AWS exception or error frame, by its `:message-type` header.
    pub fn is_error(&self) -> bool {
        self.headers.iter().any(|(name, value)| {
            name == ":message-type" && matches!(value.as_str(), "exception" | "error")
        })
    }

    pub fn to_sse_event(&self) -> SseEvent {
        let header = |name: &str| {
            self.headers
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value)
        };
        let event = match header(":message-type").map(String::as_str) {
            Some("exception") => header(":exception-type"),
            Some("error") => header(":error-code"),
            _ => header(":event-type"),
        };
        SseEvent {
            event: event.cloned(),
            data: String::from_utf8_lossy(&self.payload).into_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_frames_and_error_frames_are_reported() {
        let frame = encode(
            &[
                (":message-type", "exception"),
                (":exception-type", "throttlingException"),
            ],
            b"{}",
        );
        let mut decoder = Decoder::new(1 << 20);
        let frames = decoder.push(&frame);
        assert!(frames[0].as_ref().unwrap().is_error());
        assert!(!decoder.has_partial());
        decoder.push(&frame[..5]);
        assert!(decoder.has_partial());
    }

    #[test]
    fn round_trip_and_one_byte_chunks() {
        let headers = [(":message-type", "event"), (":event-type", "metadata")];
        let bytes = encode(&headers, b"{}");
        let mut decoder = Decoder::new(1024);
        let frames: Vec<_> = bytes
            .iter()
            .chain(&bytes)
            .flat_map(|byte| decoder.push(&[*byte]))
            .collect();
        let expected = Frame {
            headers: headers
                .map(|(key, value)| (key.to_owned(), value.to_owned()))
                .into(),
            payload: Bytes::from_static(b"{}"),
        };
        assert_eq!(frames, [Ok(expected.clone()), Ok(expected)]);
    }

    #[test]
    fn rejects_bad_crc_and_oversize() {
        let valid = encode(&[], b"{}");
        let mut invalid_prelude = valid.clone();
        invalid_prelude[8] ^= 1;
        assert_eq!(
            Decoder::new(1024).push(&invalid_prelude),
            [Err(DecodeError::PreludeCrc)]
        );

        let mut invalid_message = valid.clone();
        invalid_message[12] ^= 1;
        invalid_message.extend_from_slice(&valid);
        let frames = Decoder::new(1024).push(&invalid_message);
        assert_eq!(frames[0], Err(DecodeError::MessageCrc));
        assert!(frames[1].is_ok());
        assert_eq!(
            Decoder::new(16).push(&valid),
            [Err(DecodeError::TooLarge(valid.len()))]
        );
    }

    #[test]
    fn decodes_header_types_and_error_events() {
        let values: [&[u8]; 10] = [
            &[],
            &[],
            &[254],
            &(-3_i16).to_be_bytes(),
            &(-4_i32).to_be_bytes(),
            &(-5_i64).to_be_bytes(),
            &[0, 2, 0xfe, 0xff],
            b"\x00\x02ok",
            &123_i64.to_be_bytes(),
            &[0xff; 16],
        ];
        let mut headers = Vec::new();
        for (kind, value) in values.iter().enumerate() {
            headers.extend_from_slice(&[1, b'a' + kind as u8, kind as u8]);
            headers.extend_from_slice(value);
        }
        let frame = Decoder::new(1024)
            .push(&encode_message(&headers, &[]))
            .remove(0)
            .unwrap();
        assert_eq!(
            frame
                .headers
                .iter()
                .map(|(_, value)| value.as_str())
                .collect::<Vec<_>>(),
            [
                "true",
                "false",
                "-2",
                "-3",
                "-4",
                "-5",
                "feff",
                "ok",
                "123",
                "ffffffff-ffff-ffff-ffff-ffffffffffff"
            ]
        );
        for (kind, label) in [("exception", ":exception-type"), ("error", ":error-code")] {
            let bytes = encode(&[(":message-type", kind), (label, "exampleError")], b"{}");
            let frame = Decoder::new(1024).push(&bytes).remove(0).unwrap();
            let event = frame.to_sse_event();
            assert_eq!(event.event.as_deref(), Some("exampleError"));
            assert_eq!(event.data, "{}");
        }
    }
}
