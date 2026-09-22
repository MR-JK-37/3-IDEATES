use inotify::{Inotify, EventMask, WatchMask};
use serde::Serialize;
use std::fs::File;
use std::io::{Read, Write, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::thread;
use log::{info, warn};
use std::sync::{Arc, Mutex, mpsc};
use std::os::unix::net::{UnixListener, UnixStream};
use std::collections::HashSet;

#[derive(Serialize)]
struct ScanResult {
    path: String,
    size: u64,
    entropy: f64,
}

pub fn calculate_entropy(sample: &[u8]) -> f64 {
    if sample.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in sample {
        freq[b as usize] += 1;
    }
    let len = sample.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &freq {
        if c == 0 { continue; }
        let p = (c as f64) / len;
        entropy -= p * p.log2();
    }
    entropy
}

fn now_millis() -> u128 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::from_secs(0)).as_millis()
}

/// Start a unix domain socket server at `sock_path`. Returns a sender channel to send JSON event strings.
fn start_socket_server(sock_path: &Path) -> mpsc::Sender<String> {
    // Remove existing socket file if present
    let _ = std::fs::remove_file(sock_path);

    let listener = UnixListener::bind(sock_path).expect("Failed to bind unix socket");
    listener.set_nonblocking(true).ok();

    let clients = Arc::new(Mutex::new(Vec::<UnixStream>::new()));
    let clients_clone = clients.clone();

    // Channel to receive events to broadcast
    let (tx, rx) = mpsc::channel::<String>();

    // Thread: accept connections
    thread::spawn(move || {
        info!("Unix socket server listening on {}", sock_path.display());
        for stream_res in listener.incoming() {
            match stream_res {
                Ok(mut stream) => {
                    info!("Client connected to unix socket");
                    // set nonblocking to false for writing convenience
                    stream.set_nonblocking(false).ok();
                    clients_clone.lock().unwrap().push(stream);
                }
                Err(_e) => {
                    // non-blocking accept will produce would-block; sleep briefly
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
    });

    // Thread: broadcast events from channel to all connected clients
    let clients_writer = clients.clone();
    thread::spawn(move || {
        for msg in rx.iter() {
            let mut to_remove = Vec::new();
            let mut guard = clients_writer.lock().unwrap();
            for (i, stream) in guard.iter_mut().enumerate() {
                let mut writer = BufWriter::new(stream);
                if let Err(e) = writer.write_all(msg.as_bytes()) {
                    warn!("Failed to write to client: {}", e);
                    to_remove.push(i);
                } else if let Err(e) = writer.write_all(b"\n") {
                    warn!("Failed to write newline to client: {}", e);
                    to_remove.push(i);
                } else if let Err(e) = writer.flush() {
                    warn!("Failed to flush to client: {}", e);
                    to_remove.push(i);
                }
            }
            // Remove closed clients (in reverse order to keep indices valid)
            for idx in to_remove.into_iter().rev() {
                guard.remove(idx);
            }
        }
    });

    tx
}

pub fn scan_file(path: &PathBuf) -> Result<String, String> {
    if !path.exists() {
        return Err(format!("File not found: {}", path.display()));
    }
    let metadata = std::fs::metadata(path).map_err(|e| e.to_string())?;
    let size = metadata.len();
    let mut f = File::open(path).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    // read up to 64 KiB sample
    let _ = f.by_ref().take(65536).read_to_end(&mut buf);
    let entropy = calculate_entropy(&buf);
    let result = ScanResult {
        path: path.display().to_string(),
        size,
        entropy,
        timestamp: now_millis(),
        event: "scan".to_string(),
    };
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

pub fn monitor_paths(dirs: Vec<PathBuf>) {
    info!("Starting monitor for {:?}", dirs);
    let mut inotify = Inotify::init().expect("Failed to init inotify");

    // Keep track of watch directories to reconstruct full paths
    let mut watch_dirs = Vec::<PathBuf>::new();

    for d in &dirs {
        if d.exists() && d.is_dir() {
            if let Err(e) = inotify.add_watch(d, WatchMask::CREATE | WatchMask::MODIFY | WatchMask::MOVED_TO) {
                warn!("Failed to watch {}: {}", d.display(), e);
            } else {
                info!("Watching {}", d.display());
                watch_dirs.push(d.clone());
            }
        }
    }

    // Setup socket server if provided via environment variable CYBERSHIELD_SOCKET
    // (main.rs can pass this via env or we can accept later CLI arg)
    let socket_env = std::env::var("CYBERSHIELD_SOCKET").ok();
    let tx = socket_env.as_ref().map(|p| start_socket_server(Path::new(p)));

    // Convert to blocking event stream
    let mut buffer = [0u8; 4096];
    loop {
        match inotify.read_events_blocking(&mut buffer) {
            Ok(events) => {
                for event in events {
                    if let Some(name) = event.name {
                        let filename = name.to_string_lossy().to_string();
                        // Try to reconstruct full path by checking which watched dir contains the file
                        let mut full_path = None;
                        for d in &watch_dirs {
                            let candidate = d.join(&filename);
                            if candidate.exists() {
                                full_path = Some(candidate);
                                break;
                            }
                        }

                        let event_type = if event.mask.contains(EventMask::CREATE) { "create" }
                            else if event.mask.contains(EventMask::MODIFY) { "modify" }
                            else if event.mask.contains(EventMask::MOVED_TO) { "moved_to" }
                            else { "unknown" };

                        let scan_result = if let Some(ref pathbuf) = full_path {
                            match scan_file(pathbuf) {
                                Ok(json) => json,
                                Err(_e) => {
                                    let sr = ScanResult {
                                        path: pathbuf.display().to_string(),
                                        size: 0,
                                        entropy: 0.0,
                                        timestamp: now_millis(),
                                        event: event_type.to_string(),
                                    };
                                    serde_json::to_string(&sr).unwrap_or_else(|_| "{}".to_string())
                                }
                            }
                        } else {
                            // Unknown full path; emit minimal JSON including filename and dir candidates
                            let sr = ScanResult {
                                path: filename.clone(),
                                size: 0,
                                entropy: 0.0,
                                timestamp: now_millis(),
                                event: event_type.to_string(),
                            };
                            serde_json::to_string(&sr).unwrap_or_else(|_| "{}".to_string())
                        };

                        info!("Event JSON: {}", scan_result);

                        if let Some(ref sender) = tx {
                            // Send event to socket broadcaster (ignore errors)
                            let _ = sender.send(scan_result);
                        }
                    }
                }
            }
            Err(e) => {
                warn!("inotify read error: {}", e);
            }
        }
        // throttle loop
        thread::sleep(Duration::from_millis(200));
    }
}
