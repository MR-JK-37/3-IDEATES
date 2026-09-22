#!/usr/bin/env bash
set -euo pipefail

# Simple loader that uses bpftool to load the object into the kernel and create a pinned map.
# This is a convenience script for the PoC. A production solution should use libbpf with CO-RE.

OBJ=av_monitor.bpf.o
PIN_PATH=/sys/fs/bpf/av_monitor_events

if [ "$EUID" -ne 0 ]; then
  echo "This script requires root. Run with sudo." >&2
  exit 1
fi

if [ ! -f "$OBJ" ]; then
  echo "Build the BPF object first: make" >&2
  exit 1
fi

echo "Loading BPF object..."
bpftool prog load "$OBJ" /sys/fs/bpf/av_monitor.o type lsm

echo "Pinning ringbuf map (map id may vary)"
MAP_ID=$(bpftool prog show | grep av_monitor | awk '{print $1}' | sed 's/prog\///') || true
echo "Loaded program id(s): $MAP_ID"

echo "Note: For ringbuf consumption use a libbpf-based loader that attaches and reads the ringbuffer." 
echo "PoC complete."
