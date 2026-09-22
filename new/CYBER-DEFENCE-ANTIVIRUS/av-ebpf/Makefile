
BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -Werror -D__KERNEL__
BPF_TARGET ?= bpf

PKG_CFLAGS := $(shell pkg-config --cflags libbpf 2>/dev/null || echo "")
PKG_LIBS := $(shell pkg-config --libs libbpf 2>/dev/null || echo "-lbpf -lelf -lz -pthread")

all: av_monitor.bpf.o loader

av_monitor.bpf.o: av_monitor.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -target $(BPF_TARGET) -c $< -o $@

loader: loader.c av_monitor.bpf.o
	# Build C loader (legacy)
	gcc -O2 -g loader.c -o loader $(PKG_CFLAGS) $(PKG_LIBS) || true

	# Build Rust libbpf loader (preferred)
	cd loader-rs && cargo build --release && cp target/release/av-ebpf-loader ../av-ebpf-loader-rs || true

clean:
	rm -f *.o loader av_monitor.bpf.o
