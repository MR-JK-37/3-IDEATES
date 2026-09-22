# AV Project - Linux PoC Scaffold

This workspace contains a proof-of-concept scaffold for a Linux antivirus PoC.

Contents:
- `av-ebpf/` - skeleton eBPF program and build script (PoC only)
- `av-service/` - Rust userspace service stub that listens for events and runs a basic scanner stub

Security & safety:
- Kernel and eBPF code requires root to build/load and can crash systems. Only load on test VMs.
- This is a defensive PoC. Do not deploy to production without code review, signing, and testing.

Next steps:
- Implement libbpf-based loader and ringbuffer consumer
- Integrate real scan engines (ClamAV/YARA) in `av-service`
