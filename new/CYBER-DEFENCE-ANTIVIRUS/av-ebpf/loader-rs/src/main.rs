use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::ffi::CStr;
use std::os::raw::c_void;

fn main() -> Result<()> {
    println!("av-ebpf Rust loader starting");

    // NOTE: This program depends on system libbpf and libbpf-rs crate.
    // It loads av_monitor.bpf.o from current directory and consumes the 'events' ringbuffer.

    let exiting = Arc::new(AtomicBool::new(false));
    {
        let ex = exiting.clone();
        ctrlc::set_handler(move || {
            ex.store(true, Ordering::SeqCst);
        }).context("register ctrlc handler")?;
    }

    // Load BPF object
    let obj_path = "av_monitor.bpf.o";
    let builder = libbpf_rs::ObjectBuilder::default();
    let mut obj = builder.open_file(obj_path).context("open bpf object")?;
    obj.load().context("load bpf object")?;

    // Get map fd
    let map = obj.map("events").context("find map 'events'")?;
    let map_fd = map.fd();

    // Create unix socket path used by av-service
    let sock_path = "/var/run/av_event.sock";

    // Create consumer callback
    let sock_path_owned = sock_path.to_string();
    let cb = move |data: *const c_void, size: usize| {
        if data.is_null() || size == 0 { return 0; }
        // Safe: data points to event_t defined in BPF program
        unsafe {
            let bytes = std::slice::from_raw_parts(data as *const u8, size);
            // Try to find a nul-terminated filename inside
            let s = match std::str::from_utf8(bytes) {
                Ok(s) => s,
                Err(_) => return 0,
            };
            // crude extraction: take substring after first nulls/whitespace
            let filename = s.split('\0').next().unwrap_or("");

            // send filename to unix datagram socket
            let _ = std::os::unix::net::UnixDatagram::unbound()
                .and_then(|sock| {
                    sock.connect(&sock_path_owned)?;
                    sock.send(filename.as_bytes()).map(|_| ())
                });
        }
        0
    };

    // Build ring buffer
    let mut rb = libbpf_rs::RingBufferBuilder::new(map_fd)
        .add(cb)
        .build()
        .context("create ringbuffer")?;

    println!("loader-rs: listening for events and forwarding to {}", sock_path);

    while !exiting.load(Ordering::SeqCst) {
        rb.poll(100).ok();
    }

    println!("loader-rs: exiting");
    Ok(())
}
