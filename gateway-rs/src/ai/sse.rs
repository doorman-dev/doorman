//! Bounded incremental SSE parsing. Forwarded upstream bytes are never modified.

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

pub struct SseParser {
    max_event_bytes: usize,
    overflowed: bool,
    frame: Vec<u8>,
    dropping: bool,
    line_has_content: bool,
    /// An OpenAI-style `data: [DONE]` frame arrived (not returned as an event).
    done: bool,
}

impl SseParser {
    pub fn new(max_event_bytes: usize) -> Self {
        Self {
            max_event_bytes,
            overflowed: false,
            frame: Vec::new(),
            dropping: false,
            line_has_content: false,
            done: false,
        }
    }

    pub fn push(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        let mut events = Vec::new();
        for &byte in chunk {
            if !self.dropping {
                self.frame.push(byte);
                if self.frame.len() > self.max_event_bytes {
                    self.frame.clear();
                    self.dropping = true;
                    self.overflowed = true;
                }
            }
            if byte == b'\n' {
                if !self.line_has_content {
                    if !self.dropping {
                        match parse_frame_raw(&self.frame) {
                            Some(event) if event.data.trim() == "[DONE]" => self.done = true,
                            Some(event) => events.push(event),
                            None => {}
                        }
                    }
                    self.frame.clear();
                    self.dropping = false;
                }
                self.line_has_content = false;
            } else if byte != b'\r' {
                self.line_has_content = true;
            }
        }
        events
    }

    /// True once a `data: [DONE]` frame has been seen.
    pub fn done(&self) -> bool {
        self.done
    }

    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// True when bytes of an unfinished event are still buffered (the stream
    /// was cut off mid-event).
    pub fn has_partial(&self) -> bool {
        self.dropping || self.frame.iter().any(|byte| !byte.is_ascii_whitespace())
    }
}

fn parse_frame_raw(frame: &[u8]) -> Option<SseEvent> {
    let text = std::str::from_utf8(frame).ok()?;
    let mut event = None;
    let mut data = Vec::new();
    for line in text.lines() {
        if line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').unwrap_or((line, ""));
        let value = value.strip_prefix(' ').unwrap_or(value);
        match field {
            "event" => event = Some(value.to_owned()),
            "data" => data.push(value),
            _ => {}
        }
    }
    if data.is_empty() {
        return None;
    }
    Some(SseEvent {
        event,
        data: data.join("\n"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_parser_reports_a_cut_off_event() {
        let mut parser = SseParser::new(1024);
        parser.push(b"data: {\"a\":1}\n\n");
        assert!(!parser.has_partial());
        parser.push(b"data: {\"b\":");
        assert!(parser.has_partial());
    }

    #[test]
    fn sse_parser_handles_split_frames_and_crlf() {
        let source = b": keepalive\r\nevent: update\r\ndata: first\r\ndata: second\r\n\r\ndata: [DONE]\r\n\r\ndata: last\n\n";
        for split in 0..=source.len() {
            let mut parser = SseParser::new(1024);
            let mut events = parser.push(&source[..split]);
            events.extend(parser.push(&source[split..]));
            assert_eq!(
                events,
                vec![
                    SseEvent {
                        event: Some("update".into()),
                        data: "first\nsecond".into()
                    },
                    SseEvent {
                        event: None,
                        data: "last".into()
                    },
                ]
            );
            assert!(!parser.overflowed());
        }
        let mut parser = SseParser::new(16);
        assert!(parser.push(b"data: this event exceeds the cap").is_empty());
        assert!(parser.overflowed());
        assert_eq!(parser.push(b"\r\n\r\ndata: ok\r\n\r\n")[0].data, "ok");
        let mut parser = SseParser::new(1024);
        let events: Vec<_> = "data: héllo\n\n"
            .as_bytes()
            .chunks(1)
            .flat_map(|chunk| parser.push(chunk))
            .collect();
        assert_eq!(events[0].data, "héllo");
    }
}
