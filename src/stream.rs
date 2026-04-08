//! Parser for the katagrapho-v1 record stream that katagrapho receives
//! over stdin. Returns Events the caller can act on, along with the
//! raw line bytes so they can be forwarded into the encrypted output
//! verbatim.

use serde_json::Value;
use std::io::{BufRead, BufReader, Read};

use crate::error::KatagraphoError;

#[derive(Debug, Clone)]
pub enum Event {
    Header(HeaderInfo),
    Out { t: f64 },
    In { t: f64 },
    Resize { t: f64, cols: u16, rows: u16 },
    Chunk(ChunkInfo),
    End { t: f64, reason: String, exit_code: i32 },
}

#[derive(Debug, Clone)]
pub struct HeaderInfo {
    pub session_id: String,
    pub user: String,
    pub host: String,
    pub boot_id: String,
    pub part: u32,
    pub started: f64,
    pub epitropos_version: String,
    pub epitropos_commit: String,
    pub audit_session_id: Option<u32>,
    #[allow(dead_code)]
    pub raw: Value,
}

#[derive(Debug, Clone)]
pub struct ChunkInfo {
    pub seq: u64,
    pub bytes: u64,
    pub messages: u64,
    pub elapsed: f64,
    pub sha256_hex: String,
}

pub struct Reader<R: Read> {
    inner: BufReader<R>,
    line_buf: String,
    pub bytes_read: u64,
}

impl<R: Read> Reader<R> {
    pub fn new(r: R) -> Self {
        Self {
            inner: BufReader::new(r),
            line_buf: String::new(),
            bytes_read: 0,
        }
    }

    /// Read the next event. Returns Ok(None) on EOF. On success,
    /// returns the event plus the raw bytes (including trailing \n)
    /// for forwarding into the encrypted output.
    pub fn next_event(&mut self) -> Result<Option<(Event, Vec<u8>)>, KatagraphoError> {
        self.line_buf.clear();
        let n = self
            .inner
            .read_line(&mut self.line_buf)
            .map_err(|e| KatagraphoError::Stream(format!("read: {e}")))?;
        if n == 0 {
            return Ok(None);
        }
        self.bytes_read += n as u64;
        let raw_bytes = self.line_buf.as_bytes().to_vec();
        let v: Value = serde_json::from_str(self.line_buf.trim())
            .map_err(|e| KatagraphoError::Stream(format!("parse: {e}")))?;
        let kind = v["kind"]
            .as_str()
            .ok_or_else(|| KatagraphoError::Stream("missing kind".to_string()))?;
        let event = match kind {
            "header" => Event::Header(HeaderInfo {
                session_id: v["session_id"].as_str().unwrap_or_default().to_string(),
                user: v["user"].as_str().unwrap_or_default().to_string(),
                host: v["host"].as_str().unwrap_or_default().to_string(),
                boot_id: v["boot_id"].as_str().unwrap_or_default().to_string(),
                part: v["part"].as_u64().unwrap_or(0) as u32,
                started: v["started"].as_f64().unwrap_or(0.0),
                epitropos_version: v["epitropos_version"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                epitropos_commit: v["epitropos_commit"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                audit_session_id: v["audit_session_id"].as_u64().map(|x| x as u32),
                raw: v.clone(),
            }),
            "out" => Event::Out {
                t: v["t"].as_f64().unwrap_or(0.0),
            },
            "in" => Event::In {
                t: v["t"].as_f64().unwrap_or(0.0),
            },
            "resize" => Event::Resize {
                t: v["t"].as_f64().unwrap_or(0.0),
                cols: v["cols"].as_u64().unwrap_or(80) as u16,
                rows: v["rows"].as_u64().unwrap_or(24) as u16,
            },
            "chunk" => Event::Chunk(ChunkInfo {
                seq: v["seq"].as_u64().unwrap_or(0),
                bytes: v["bytes"].as_u64().unwrap_or(0),
                messages: v["messages"].as_u64().unwrap_or(0),
                elapsed: v["elapsed"].as_f64().unwrap_or(0.0),
                sha256_hex: v["sha256"].as_str().unwrap_or_default().to_string(),
            }),
            "end" => Event::End {
                t: v["t"].as_f64().unwrap_or(0.0),
                reason: v["reason"].as_str().unwrap_or("eof").to_string(),
                exit_code: v["exit_code"].as_i64().unwrap_or(0) as i32,
            },
            other => {
                return Err(KatagraphoError::Stream(format!(
                    "unknown record kind: {other}"
                )));
            }
        };
        Ok(Some((event, raw_bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_header_then_out_then_chunk_then_end() {
        let input = concat!(
            r#"{"kind":"header","v":"katagrapho-v1","session_id":"s","user":"u","host":"h","boot_id":"b","part":0,"started":1.0,"epitropos_version":"0","epitropos_commit":"x","audit_session_id":null}"#,
            "\n",
            r#"{"kind":"out","t":0.1,"b":"aGk="}"#,
            "\n",
            r#"{"kind":"chunk","seq":0,"bytes":42,"messages":1,"elapsed":0.5,"sha256":"deadbeef"}"#,
            "\n",
            r#"{"kind":"end","t":1.0,"reason":"eof","exit_code":0}"#,
            "\n",
        );
        let mut reader = Reader::new(input.as_bytes());
        let (e1, _) = reader.next_event().unwrap().unwrap();
        assert!(matches!(e1, Event::Header(_)));
        let (e2, _) = reader.next_event().unwrap().unwrap();
        assert!(matches!(e2, Event::Out { .. }));
        let (e3, _) = reader.next_event().unwrap().unwrap();
        assert!(matches!(e3, Event::Chunk(_)));
        let (e4, _) = reader.next_event().unwrap().unwrap();
        assert!(matches!(e4, Event::End { .. }));
        assert!(reader.next_event().unwrap().is_none());
    }

    #[test]
    fn rejects_unknown_kind() {
        let input = "{\"kind\":\"weird\"}\n";
        let mut reader = Reader::new(input.as_bytes());
        assert!(reader.next_event().is_err());
    }

    #[test]
    fn empty_stream_returns_none() {
        let mut reader = Reader::new(&[][..]);
        assert!(reader.next_event().unwrap().is_none());
    }
}
