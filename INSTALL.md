# Installation Guide - LoopHunter

This document details the steps required to compile and install **LoopHunter** on your Linux environment.

## Prerequisites

To compile LoopHunter, you will need the Rust compiler and the Cargo package manager.

```bash
# Install Rust and Cargo via rustup (recommended standard method)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

Since LoopHunter uses SQLite locally, you must have the SQLite development library installed on your system (although the Rust driver tries to compile in bundled mode by default, it is recommended to have it installed). On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install build-essential sqlite3 libsqlite3-dev -y
```

## Compiling

To compile the code in production mode (with all performance optimizations enabled):

1. Clone or navigate to the project directory:
   ```bash
   cd /home/gondim/projetos/staticloop
   ```

2. Compile in release mode using Cargo:
   ```bash
   cargo build --release
   ```

The compiled binary will be available at: `./target/release/loophunter`.

## Special Socket Permissions (Crucial)

LoopHunter uses raw sockets to send and receive native ICMP/ICMPv6 packets without relying on external utilities (such as `ping` or `fping`). On Linux, creating raw sockets requires administrative privileges.

You have two options to successfully execute the binary:

### Option A: Run via Sudo (Simple)
Always run the check command with `sudo`:
```bash
sudo ./target/release/loophunter check
```

### Option B: Assign the `CAP_NET_RAW` capability to the executable (Recommended for automation)
You can grant low-level network permissions to the compiled binary. This allows you to run it without `sudo` and without full root privileges:

```bash
sudo setcap cap_net_raw+ep ./target/release/loophunter
```

After doing this, any system user will be able to run routing loop scans directly:
```bash
./target/release/loophunter check
```

## SMTP & Scan Configuration

To enable email notifications and customize scanning parameters:

1. Create a file named `config.toml` in the same directory as the executable (or in the root folder where you run the command).
2. Configure it with your SMTP credentials and scanning configurations following this template:

```toml
[smtp]
host = "smtp.example.com"
port = 587
username = "alerts@example.com"
password = "your_password_here"
from_address = "alerts@example.com"
encryption = "tls" # Options: "none", "tls", "ssl"

[scan]
ipv4_delay_ms = 1      # Delay between IPv4 sends in milliseconds (Default: 1ms)
ipv6_delay_us = 200    # Delay between IPv6 sends in microseconds (Default: 200us)
timeout_secs = 1.0     # Time to wait for responses in seconds (Default: 1.0s)
```

3. **Security Warning:** Since `config.toml` contains plain-text SMTP credentials, you should restrict access to it using `chmod 600` to ensure only the owner can read or write it:
```bash
chmod 600 config.toml
```
