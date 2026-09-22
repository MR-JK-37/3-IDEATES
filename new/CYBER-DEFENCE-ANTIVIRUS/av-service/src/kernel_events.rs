use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::mem::size_of;
use std::net::Ipv4Addr;
use uuid::Uuid;

use crate::kernel_comm::ParsedEvent;
use anyhow::Context;

pub const KERNEL_EVENT_SCHEMA_VERSION: u16 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelEventKind {
    FileAccess,
    ProcessExec,
    NetworkConnect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelEventSource {
    KernelSocket,
    ProcfsFallback,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelEvent {
    pub schema_version: u16,
    pub event_id: String,
    pub timestamp: String,
    pub timestamp_ns: u64,
    pub kind: KernelEventKind,
    pub source: KernelEventSource,
    pub pid: u32,
    pub tgid: u32,
    pub comm: String,
    pub path: Option<String>,
    pub open_flags: Option<u32>,
    pub write_intent: Option<bool>,
    pub network_ip: Option<String>,
    pub network_port: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecision {
    Allow,
    Monitor,
    Quarantine,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOutcome {
    pub decision: PolicyDecision,
    pub reason: String,
    pub severity: String,
    pub confidence: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelPolicyAuditRecord {
    pub event: KernelEvent,
    pub outcome: PolicyOutcome,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum KernelWirePayload {
    FileAccess {
        pid: u32,
        tgid: u32,
        comm: String,
        path: String,
        timestamp_ns: u64,
        open_flags: u32,
        write_intent: bool,
    },
    ProcessExec {
        pid: u32,
        tgid: u32,
        comm: String,
        path: String,
        timestamp_ns: u64,
    },
    NetworkConnect {
        pid: u32,
        tgid: u32,
        comm: String,
        ip: String,
        port: u16,
        timestamp_ns: u64,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct KernelWireEvent {
    pub schema_version: u16,
    #[serde(default)]
    pub source: Option<KernelEventSource>,
    #[serde(flatten)]
    payload: KernelWirePayload,
}

impl KernelWireEvent {
    pub fn from_ringbuf_frame(input: &[u8]) -> anyhow::Result<Self> {
        if input.len() < size_of::<LinuxRingbufEventFrame>() {
            anyhow::bail!(
                "ringbuffer frame too short: {} < {}",
                input.len(),
                size_of::<LinuxRingbufEventFrame>()
            );
        }

        let frame = unsafe { std::ptr::read_unaligned(input.as_ptr() as *const LinuxRingbufEventFrame) };
        let comm = cstr_from_bytes(&frame.comm);

        let payload = match frame.event_kind {
            1 => KernelWirePayload::FileAccess {
                pid: frame.pid,
                tgid: frame.tgid,
                comm,
                path: cstr_from_bytes(&frame.path),
                timestamp_ns: frame.timestamp,
                open_flags: frame.open_flags,
                write_intent: frame.write_intent != 0,
            },
            2 => KernelWirePayload::ProcessExec {
                pid: frame.pid,
                tgid: frame.tgid,
                comm,
                path: cstr_from_bytes(&frame.path),
                timestamp_ns: frame.timestamp,
            },
            3 => KernelWirePayload::NetworkConnect {
                pid: frame.pid,
                tgid: frame.tgid,
                comm,
                ip: Ipv4Addr::from(u32::from_be(frame.remote_ip)).to_string(),
                port: frame.remote_port,
                timestamp_ns: frame.timestamp,
            },
            other => anyhow::bail!("unknown kernel event kind {}", other),
        };

        Ok(Self {
            schema_version: frame.schema_version,
            source: Some(KernelEventSource::KernelSocket),
            payload,
        })
    }

    pub fn into_parsed_event(self) -> ParsedEvent {
        match self.payload {
            KernelWirePayload::FileAccess {
                pid,
                tgid,
                path,
                comm,
                timestamp_ns,
                open_flags,
                write_intent,
                ..
            } => ParsedEvent::FileAccess {
                pid,
                tgid,
                path,
                comm,
                timestamp_ns,
                open_flags,
                write_intent,
            },
            KernelWirePayload::ProcessExec {
                pid,
                tgid,
                path,
                comm,
                timestamp_ns,
                ..
            } => ParsedEvent::ProcessExec {
                pid,
                tgid,
                path,
                comm,
                timestamp_ns,
            },
            KernelWirePayload::NetworkConnect {
                pid,
                tgid,
                ip,
                port,
                comm,
                timestamp_ns,
                ..
            } => ParsedEvent::NetworkConnect {
                pid,
                tgid,
                ip,
                port,
                comm,
                timestamp_ns,
            },
        }
    }
}

pub fn parse_wire_event_json(input: &str) -> anyhow::Result<KernelWireEvent> {
    serde_json::from_str::<KernelWireEvent>(input)
        .with_context(|| "failed to deserialize kernel wire event")
}

pub fn ensure_schema_compatible(schema_version: u16) -> anyhow::Result<()> {
    if schema_version != KERNEL_EVENT_SCHEMA_VERSION {
        anyhow::bail!(
            "kernel event schema mismatch: received {}, expected {}",
            schema_version,
            KERNEL_EVENT_SCHEMA_VERSION
        );
    }
    Ok(())
}

pub fn normalize_kernel_event(event: ParsedEvent) -> KernelEvent {
    match event {
        ParsedEvent::FileAccess {
            pid,
            tgid,
            path,
            comm,
            timestamp_ns,
            open_flags,
            write_intent,
        } => KernelEvent {
            schema_version: KERNEL_EVENT_SCHEMA_VERSION,
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            timestamp_ns,
            kind: KernelEventKind::FileAccess,
            source: infer_source(pid, &comm, timestamp_ns),
            pid,
            tgid,
            comm,
            path: Some(path),
            open_flags: Some(open_flags),
            write_intent: Some(write_intent),
            network_ip: None,
            network_port: None,
        },
        ParsedEvent::ProcessExec {
            pid,
            tgid,
            path,
            comm,
            timestamp_ns,
        } => KernelEvent {
            schema_version: KERNEL_EVENT_SCHEMA_VERSION,
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            timestamp_ns,
            kind: KernelEventKind::ProcessExec,
            source: infer_source(pid, &comm, timestamp_ns),
            pid,
            tgid,
            comm,
            path: Some(path),
            open_flags: None,
            write_intent: None,
            network_ip: None,
            network_port: None,
        },
        ParsedEvent::NetworkConnect {
            pid,
            tgid,
            ip,
            port,
            comm,
            timestamp_ns,
        } => KernelEvent {
            schema_version: KERNEL_EVENT_SCHEMA_VERSION,
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now().to_rfc3339(),
            timestamp_ns,
            kind: KernelEventKind::NetworkConnect,
            source: infer_source(pid, &comm, timestamp_ns),
            pid,
            tgid,
            comm,
            path: None,
            open_flags: None,
            write_intent: None,
            network_ip: Some(ip),
            network_port: Some(port),
        },
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct LinuxRingbufEventFrame {
    schema_version: u16,
    event_kind: u16,
    pid: u32,
    tgid: u32,
    uid: u32,
    gid: u32,
    timestamp: u64,
    open_flags: u32,
    write_intent: u32,
    inode: u64,
    comm: [u8; 16],
    path: [u8; 256],
    remote_ip: u32,
    remote_port: u16,
    reserved: u16,
}

fn cstr_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

fn infer_source(pid: u32, comm: &str, timestamp_ns: u64) -> KernelEventSource {
    if timestamp_ns > 0 {
        KernelEventSource::KernelSocket
    } else if comm == "kernel-ebpf" && pid == 0 {
        KernelEventSource::KernelSocket
    } else if comm == "filesystem" || comm == "unknown" {
        KernelEventSource::ProcfsFallback
    } else {
        KernelEventSource::Unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wire_event_and_validates_schema() {
        let raw = r#"{"schema_version":2,"kind":"file_access","pid":42,"tgid":42,"path":"/tmp/a.bin","comm":"loader","timestamp_ns":11,"open_flags":0,"write_intent":false}"#;
        let event = parse_wire_event_json(raw).expect("wire event should parse");
        ensure_schema_compatible(event.schema_version).expect("schema should match");
        let parsed = event.into_parsed_event();
        match parsed {
            ParsedEvent::FileAccess {
                pid,
                tgid,
                path,
                comm,
                timestamp_ns,
                open_flags,
                write_intent,
            } => {
                assert_eq!(pid, 42);
                assert_eq!(tgid, 42);
                assert_eq!(path, "/tmp/a.bin");
                assert_eq!(comm, "loader");
                assert_eq!(timestamp_ns, 11);
                assert_eq!(open_flags, 0);
                assert!(!write_intent);
            }
            _ => panic!("unexpected parsed variant"),
        }
    }

    #[test]
    fn rejects_mismatched_schema_version() {
        let raw = r#"{"schema_version":99,"kind":"file_access","pid":42,"tgid":42,"path":"/tmp/a.bin","comm":"loader","timestamp_ns":11,"open_flags":0,"write_intent":false}"#;
        let event = parse_wire_event_json(raw).expect("wire event should parse");
        assert!(ensure_schema_compatible(event.schema_version).is_err());
    }

    #[test]
    fn parses_ringbuffer_frame_file_access() {
        let mut frame = LinuxRingbufEventFrame {
            schema_version: 2,
            event_kind: 1,
            pid: 1001,
            tgid: 1000,
            uid: 0,
            gid: 0,
            timestamp: 1234,
            open_flags: 0x241,
            write_intent: 1,
            inode: 55,
            comm: [0; 16],
            path: [0; 256],
            remote_ip: 0,
            remote_port: 0,
            reserved: 0,
        };
        frame.comm[..4].copy_from_slice(b"bash");
        frame.path[..12].copy_from_slice(b"/tmp/x.bin\0\0");

        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&frame as *const LinuxRingbufEventFrame).cast::<u8>(),
                size_of::<LinuxRingbufEventFrame>(),
            )
        };
        let event = KernelWireEvent::from_ringbuf_frame(bytes).expect("frame should parse");
        ensure_schema_compatible(event.schema_version).expect("schema should match");

        match event.into_parsed_event() {
            ParsedEvent::FileAccess {
                pid,
                tgid,
                path,
                comm,
                timestamp_ns,
                open_flags,
                write_intent,
            } => {
                assert_eq!(pid, 1001);
                assert_eq!(tgid, 1000);
                assert_eq!(path, "/tmp/x.bin");
                assert_eq!(comm, "bash");
                assert_eq!(timestamp_ns, 1234);
                assert_eq!(open_flags, 0x241);
                assert!(write_intent);
            }
            _ => panic!("unexpected parsed variant"),
        }
    }
}
