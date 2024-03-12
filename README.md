# YtFlowCore

![build tests ci](https://github.com/YtFlow/YtFlowCore/actions/workflows/build-tests.yml/badge.svg)

A modern proxy framework, core of YtFlow.

If you are looking for the UWP app powered by YtFlowCore, please head over to [YtFlowApp](https://github.com/YtFlow/YtFlowApp).

## Features

- Fully customizable. Design your own network flow!
- Multiple inbound types: VPN, SOCKS5.
- Supports common proxy protocols: Shadowsocks, Trojan, VMess, SOCKS5 and HTTP.
- Flexible outbound transports: simple-obfs, WebSocket, TLS etc.
- DNS resolvers at your option: libc resolver, classic DNS over UDP, DNS over HTTPS.
- Rule-based split routing modules: GeoIP, Surge domain set, Quantumult X filter.
- Runs on Linux, macOS and Universal Windows Platform.

## Usage

Use `ytflow-edit` to generate a new database file `conf.db` and a profile `my_profile`, and edit plugins accordingly. For newcomers, you may be interested in the `default-ss` and `default-redir` plugins. Read the [YtFlowCore Book](https://ytflow.github.io/ytflow-book/) to learn more about configuration.

When the profile is ready, execute `ytflow-core --db-file conf.db my_profile` to launch YtFlowCore.

## Project Layout

| Package | Description | Dependency |
|---------|-------------|------------|
| ytflow  | Includes all components and plugins to run a YtFlowCore instance. | - |
| ytflow-bin | Shell executables for the core `ytflow-core` and a TUI editor `ytflow-edit` that actually call into entrypoints exposed by `ytflow-bin-shared`. | ytflow-bin-shared |
| ytflow-bin-shared | Contains the actual code for the binaries. Produces a single cdylib that reuses common dependencies to reduce final artifact size. | ytflow, ytflow-app-util |
| ytflow-app-util | Provides utilities for app frontends to handle share links, subscriptions etc. Also exports FFI functions and generates a C header file. | ytflow |

## Build

Steps to build `ytflow-core` and `ytflow-edit`:
1. Setup [rustup](https://rustup.rs/) and Visual C++ Build Tools on Windows or GCC toolchain on Linux.
2. Clone this repository.
3. Rename `.cargo/publish.config.toml` to `.cargo/config.toml`.
4. Run `cargo build -p ytflow-bin --release`.
5. If no error occurrs, you can find the binaries in `target/release/`.

To build for YtFlowApp, please refer to the build steps on https://github.com/YtFlow/YtFlowApp/blob/main/README.md.

## Credits

This project is inspired from:

- [shadowsocks-rust](https://github.com/shadowsocks/shadowsocks-rust)
- [Leaf](https://github.com/eycorsican/leaf)
- [Project V](https://github.com/v2fly/v2ray-core)
- ... and many more others!
