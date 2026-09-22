use std::collections::{HashMap, HashSet, VecDeque};
use std::path::PathBuf;
use tokio::sync::mpsc;
use tokio::time::Duration;

#[derive(Debug, Clone)]
pub enum ParsedEvent {
    FileAccess {
        pid: u32,
        tgid: u32,
        path: String,
        comm: String,
        timestamp_ns: u64,
        open_flags: u32,
        write_intent: bool,
    },
    ProcessExec {
        pid: u32,
        tgid: u32,
        path: String,
        comm: String,
        timestamp_ns: u64,
    },
    NetworkConnect {
        pid: u32,
        tgid: u32,
        ip: String,
        port: u16,
        comm: String,
        timestamp_ns: u64,
    },
}

#[derive(Clone)]
pub struct KernelEventMonitor {
    tx: mpsc::UnboundedSender<ParsedEvent>,
}

impl KernelEventMonitor {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<ParsedEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }

    pub async fn start_procfs_fallback(&self) -> anyhow::Result<()> {
        tracing::warn!("eBPF monitor not attached as root; starting procfs fallback monitors");

        let tx1 = self.tx.clone();
        let tx2 = self.tx.clone();
        let tx3 = self.tx.clone();

        tokio::spawn(async move {
            procfs_process_monitor(tx1).await;
        });
        tokio::spawn(async move {
            procfs_network_monitor(tx2).await;
        });
        tokio::spawn(async move {
            file_event_monitor(tx3).await;
        });

        Ok(())
    }

    pub fn push_socket_path_event(&self, path: String) {
        let _ = self.tx.send(ParsedEvent::FileAccess {
            pid: 0,
            tgid: 0,
            path,
            comm: "kernel-ebpf".to_string(),
            timestamp_ns: 0,
            open_flags: 0,
            write_intent: false,
        });
    }

    pub fn push_event(&self, event: ParsedEvent) {
        let _ = self.tx.send(event);
    }
}

async fn procfs_process_monitor(tx: mpsc::UnboundedSender<ParsedEvent>) {
    let mut known = HashSet::<u32>::new();
    let mut interval = tokio::time::interval(Duration::from_secs(2));
    loop {
        interval.tick().await;
        let mut seen_now = HashSet::new();
        for (pid, path, comm) in read_process_execs() {
            seen_now.insert(pid);
            if known.contains(&pid) {
                continue;
            }
            known.insert(pid);
            let _ = tx.send(ParsedEvent::ProcessExec {
                pid,
                tgid: pid,
                path,
                comm,
                timestamp_ns: 0,
            });
        }
        known.retain(|pid| seen_now.contains(pid));
    }
}

async fn procfs_network_monitor(tx: mpsc::UnboundedSender<ParsedEvent>) {
    let mut known = HashSet::<String>::new();
    let mut interval = tokio::time::interval(Duration::from_secs(3));
    loop {
        interval.tick().await;
        for (ip, port) in read_proc_tcp_connections() {
            let key = format!("{ip}:{port}");
            if known.contains(&key) {
                continue;
            }
            known.insert(key);
            let _ = tx.send(ParsedEvent::NetworkConnect {
                pid: 0,
                tgid: 0,
                ip,
                port,
                comm: "unknown".to_string(),
                timestamp_ns: 0,
            });
        }
    }
}

async fn file_event_monitor(tx: mpsc::UnboundedSender<ParsedEvent>) {
    let watch_paths = default_watch_paths();
    let mut known: HashMap<String, u64> = HashMap::new();
    let mut initialized = false;
    loop {
        let snapshot = collect_watch_snapshot(&watch_paths, 800, 3);
        let mut current = HashMap::new();
        for (path, mtime) in snapshot {
            current.insert(path.clone(), mtime);
            if initialized {
                let changed = known.get(&path).map(|v| *v != mtime).unwrap_or(true);
                if changed {
                    let _ = tx.send(ParsedEvent::FileAccess {
                        pid: 0,
                        tgid: 0,
                        path,
                        comm: "filesystem".to_string(),
                        timestamp_ns: 0,
                        open_flags: 0,
                        write_intent: false,
                    });
                }
            }
        }
        known = current;
        initialized = true;
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn read_process_execs() -> Vec<(u32, String, String)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let pid = match entry.file_name().to_string_lossy().parse::<u32>() {
            Ok(x) => x,
            Err(_) => continue,
        };
        let exe_link = format!("/proc/{pid}/exe");
        let comm_path = format!("/proc/{pid}/comm");
        let exe = match std::fs::read_link(exe_link) {
            Ok(v) => v.to_string_lossy().to_string(),
            Err(_) => continue,
        };
        let comm = std::fs::read_to_string(comm_path)
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        if !exe.is_empty() {
            out.push((pid, exe, comm));
        }
    }
    out
}

fn read_proc_tcp_connections() -> Vec<(String, u16)> {
    let mut out = Vec::new();
    let Ok(content) = std::fs::read_to_string("/proc/net/tcp") else {
        return out;
    };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[3] != "01" {
            continue;
        }
        if let Some((ip, port)) = parse_hex_addr(fields[2]) {
            out.push((ip, port));
        }
    }
    out
}

fn parse_hex_addr(hex: &str) -> Option<(String, u16)> {
    let parts: Vec<&str> = hex.split(':').collect();
    if parts.len() != 2 {
        return None;
    }
    let ip_hex = u32::from_str_radix(parts[0], 16).ok()?;
    let port = u16::from_str_radix(parts[1], 16).ok()?;
    let ip = format!(
        "{}.{}.{}.{}",
        ip_hex & 0xFF,
        (ip_hex >> 8) & 0xFF,
        (ip_hex >> 16) & 0xFF,
        (ip_hex >> 24) & 0xFF
    );
    Some((ip, port))
}

fn default_watch_paths() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    vec![
        PathBuf::from(format!("{home}/Downloads")),
        PathBuf::from(format!("{home}/Desktop")),
        PathBuf::from("/tmp"),
        PathBuf::from("/var/tmp"),
    ]
}

fn collect_watch_snapshot(paths: &[PathBuf], max_files: usize, max_depth: usize) -> Vec<(String, u64)> {
    let mut out = Vec::new();
    let mut queue: VecDeque<(PathBuf, usize)> = VecDeque::new();
    for p in paths {
        queue.push_back((p.clone(), 0));
    }

    while let Some((path, depth)) = queue.pop_front() {
        if out.len() >= max_files {
            break;
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.is_file() {
            let mtime = meta
                .modified()
                .ok()
                .and_then(|m| m.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            out.push((path.to_string_lossy().to_string(), mtime));
            continue;
        }
        if !meta.is_dir() || depth >= max_depth {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(path) else {
            continue;
        };
        for entry in entries.flatten() {
            queue.push_back((entry.path(), depth + 1));
        }
    }
    out
}
