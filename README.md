# LoopHunter

```
$$\                                    $$\   $$\                      $$\                         
$$ |                                   $$ |  $$ |                     $$ |                        
$$ |      $$$$$$\   $$$$$$\   $$$$$$\  $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$ |     $$  __$$\ $$  __$$\ $$  __$$\ $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ 
$$ |     $$ /  $$ |$$ /  $$ |$$ /  $$ |$$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|
$$ |     $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |      
$$$$$$$$\\$$$$$$  |\$$$$$$  |$$$$$$$  |$$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      
\________|\______/  \______/ $$  ____/ \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      
                             $$ |                                                                 
                             $$ |                                                                 
                             \__|
```

**LoopHunter** is a high-performance command-line tool written in Rust designed to monitor and detect static routing loops in IPv4 and IPv6 networks.

It replaces legacy Bash scripts based on `fping`, `awk`, and `diff`, bringing more speed, robustness, lower CPU usage, and ease of automation per client.

---

## Key Advantages of LoopHunter

1. **Ultra-fast Asynchronous Scanning (Tokio):** Instead of pinging each prefix or IP sequentially (which blocks the terminal), LoopHunter runs checks concurrently using green threads. A scan that used to take minutes now completes in just a few seconds.
2. **Native IPv6 Support:** The tool is fully compatible with IPv6 subnets (such as `/48`, `/56`, `/64`, or `/128`), detecting ICMPv6 packets with *Hop Limit Exceeded* (Time Exceeded type 3) in the same manner as IPv4 (*TTL Exceeded* type 11).
3. **Data Persistence and History (SQLite):** It uses a structured local SQLite database (`static_loop.db`) to map prefixes to clients and retain the latest active loops, completely eliminating temporary text files in `/tmp`.
4. **Integrated Smart Diffs:** Computes the diff in memory using native data structures and generates side-by-side reports consistent with the legacy format to highlight loops created or resolved since the last run.
5. **Customized Notification per Client:** Sends tailored emails directly to each client's technical contact using their corporate description in the database and SMTP credentials read from a `config.toml` file.

---

## How Routing Loop Detection Works

When a static routing loop exists (for example, Router A points a route to Router B, and Router B has a default or static route pointing back to Router A), any packet destined for that prefix will cycle infinitely between them.

At each hop, the **TTL** (IPv4) or **Hop Limit** (IPv6) field is decremented by 1. When the value reaches 0, the router holding the packet discards it and sends an ICMP **Time Exceeded** error message back to the sender.

**LoopHunter** sends representative probe packets and listens for these returns. If it receives a *Time Exceeded* message, it identifies the IP of the router that originated the error and reports that there is an active loop at that destination.

---

## Quick Start Guide

### 1. Client Management

Add clients with their notification emails and corporate names:

```bash
# Add a client
loophunter client add --name "Company" --email "support@company.com" --corporate-name "Company Name Ltd"

# Update client data (--new-name, --email, and --corporate-name are optional)
loophunter client update --name "Company" --email "new_support@company.com" --corporate-name "Updated Company Name Ltd"

# List registered clients
loophunter client list

# Remove client (automatically removes all associated prefixes due to cascade deletion)
loophunter client remove --name "Company"
```

### 2. Prefix Management

Register the IPv4 or IPv6 prefixes belonging to each client, optionally associating them with the ASN number:

```bash
# Associate an IPv4 prefix with a client, defining the ASN (only the number, without the 'AS' prefix)
loophunter prefix add --name "Company" --prefix "198.18.0.0/24" --asn "65001"

# Associate an IPv6 prefix with a client, defining the ASN
loophunter prefix add --name "Company" --prefix "2001:db8:beef::/48" --asn "65001"

# List all prefixes registered in the system (ASNs are automatically formatted with 'AS')
loophunter prefix list

# List prefixes for a specific client
loophunter prefix list --name "Company"

# Remove a specific prefix
loophunter prefix remove --prefix "198.18.0.0/24"
```

### 3. Running Checks and Notifications

```bash
# Run check on all clients and display results in the terminal
loophunter check

# Run check only for the client named "Company"
loophunter check --name "Company"

# Run check on all clients and send email alerts if there are changes or active loops
loophunter check --send-email
```

### 4. SMTP Configuration

To enable email alerts (`--send-email`), you must configure the `config.toml` file located in the execution directory (a default template is provided in the repository). Fill it with your SMTP provider details:

```toml
[smtp]
host = "smtp.example.com"
port = 587
username = "alerts@example.com"
password = "your_password_here"
from_address = "alerts@example.com"
encryption = "tls" # Options: "none", "tls", "ssl"
```

---

## Sample Report

```
CURRENT STATIC LOOPS: 2
====================

10.0.0.1 - 198.18.0.1
2001:db8::1 - 2001:db8:beef::1

PREVIOUS DIFFERENCES
====================

OLD SIDE                                                                              NEW SIDE
===================================================================================================================================

10.0.0.5 - 198.18.0.15                                                                <
                                                                                      > 10.0.0.1 - 198.18.0.1
```

The `<` character indicates that the previous loop on IP `198.18.0.15` was resolved. The `>` character indicates that a new loop has emerged on IP `198.18.0.1`.

---

## 🚀 CI/CD & Release Automation (Codeberg)

This repository supports build and test automation via **Woodpecker CI** hosted on Codeberg:

* **Continuous Integration (CI):** On every `push` or `pull_request` sent to the `main` branch, the complete test suite is executed automatically (with parallelism limited to `-j 1` to respect Codeberg's shared resource guidelines).
* **Continuous Delivery (CD):** When creating and pushing a version tag (e.g., `v1.4.0`), the pipeline compiles the binary (`loophunter`) in production mode (Release) for Linux x86_64, compresses it into a `.tar.gz` file, and attaches the final file directly to the Releases page on Codeberg.
