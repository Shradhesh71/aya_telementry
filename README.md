# aya-telementry

A high-performance network telemetry tool built with eBPF and Aya framework for real-time packet analysis and QUIC protocol detection.

## Overview

This tool monitors network packets at the kernel level using eBPF tracepoints, providing deep visibility into network traffic with minimal overhead. It specializes in detecting and analyzing QUIC protocol packets (HTTP/3 transport layer) while capturing essential metadata from all network traffic.

## Features

- Real-time packet capture using eBPF tracepoints
- QUIC protocol detection and analysis for both IPv4 and IPv6
- Connection ID (CID) extraction and version tracking
- Support for standard QUIC ports (443, 4433, 8000)
- UDP traffic monitoring
- Backend ID and queue ID identification from QUIC connection IDs
- Low-overhead kernel-level packet inspection
- Ring buffer-based event communication

## Prerequisites

### Required
- Stable Rust toolchain: `rustup toolchain install stable`
- Nightly Rust toolchain: `rustup toolchain install nightly --component rust-src`
- bpf-linker: `cargo install bpf-linker` (use `--no-default-features` on macOS)

### For Cross-Compilation
- Target architecture: `rustup target add ${ARCH}-unknown-linux-musl`
- LLVM toolchain (macOS): `brew install llvm`
- musl C toolchain (macOS): `brew install filosottile/musl-cross/musl-cross`

## Build & Run

Build and run the project in release mode:

```shell
cargo build --release
cargo run --release
```

The eBPF program is automatically compiled and embedded during the build process.

## Cross-Compilation (macOS)

Supports both Intel and Apple Silicon architectures:

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package aya-telementry --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

Deploy the binary from `target/${ARCH}-unknown-linux-musl/release/aya-telementry` to your Linux target system.

## Architecture

- **aya-telementry**: User-space application for event processing and display
- **aya-telementry-ebpf**: Kernel-space eBPF program for packet capture
- **aya-telementry-common**: Shared data structures and types

## License

With the exception of eBPF code, aya-telementry is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
