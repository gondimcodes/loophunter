//! # Checker Engine Module (Custom Ping)
//!
//! This module implements a native ping engine based on Linux raw sockets (via `socket2`).
//! It sends ICMP/ICMPv6 Echo Request packets and listens to all responses. When an intermediate
//! router sends a "Time Exceeded" packet, the engine parses the nested original IP header inside
//! the ICMP payload to recover the intended target IP address.
//!
//! This bypasses the limitations of high-level libraries that cannot associate Time Exceeded
//! messages from third-party IPs back to the original probed destination.

use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ipnetwork::{IpNetwork, Ipv6Network};
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use colored::Colorize;

/// Renders the scan progress bar to stderr — identical style to the ampscan project.
/// Uses unicode block characters and terminal colors for a clean, readable display.
fn draw_progress(label: &str, done: usize, total: usize) {
    use std::io::Write;
    let width = 30usize;
    let ratio = if total > 0 {
        (done as f64 / total as f64).clamp(0.0, 1.0)
    } else {
        1.0
    };
    let percent = ratio * 100.0;
    let filled = (ratio * width as f64).round() as usize;
    let empty = width - filled;
    let bar_filled = "█".repeat(filled).cyan();
    let bar_empty = "░".repeat(empty).bright_black();
    eprint!(
        "\r  [{}] Progress: [{}{}] {:.1}% ({}/{})",
        label, bar_filled, bar_empty, percent, done, total
    );
    let _ = std::io::stderr().flush();
}

/// Structure containing the results of scanning a specific target IP.
#[derive(Debug, Clone)]
pub struct LoopResult {
    /// The registered parent prefix this target IP belongs to.
    pub prefix: String,
    /// The specific IP tested.
    pub target_ip: IpAddr,
    /// Contains the IP of the router that responded with the loop (`Some(IpAddr)`) or `None`.
    pub router_ip: Option<IpAddr>,
    /// Error description if the ping attempt failed due to OS/network operational issues.
    pub error: Option<String>,
}

/// Helper to calculate the Internet Checksum (RFC 1071) for ICMPv4 packets.
fn calc_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in data.chunks_exact(2) {
        sum += u32::from(u16::from_be_bytes([chunk[0], chunk[1]]));
    }
    if data.len() % 2 != 0 {
        sum += u32::from(data[data.len() - 1]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Splits an IPv6 prefix into representative sub-blocks (e.g. /32 → /48s)
/// and returns the first, middle, and last usable IP of each.
fn get_ipv6_delegated_targets(net_v6: &Ipv6Network) -> Vec<IpAddr> {
    let prefix_len = net_v6.prefix();
    let start_bits = u128::from(net_v6.network());

    let target_sub_len = if prefix_len < 48 {
        48
    } else if prefix_len < 56 {
        56
    } else {
        // For smaller blocks (>= /56), define targets according to the available space
        let step = 128 - prefix_len;
        if step == 0 {
            return vec![IpAddr::V6(Ipv6Addr::from(start_bits))];
        } else if step == 1 {
            return vec![
                IpAddr::V6(Ipv6Addr::from(start_bits)),
                IpAddr::V6(Ipv6Addr::from(start_bits + 1)),
            ];
        } else {
            return vec![
                IpAddr::V6(Ipv6Addr::from(start_bits + 1)),
                IpAddr::V6(Ipv6Addr::from(start_bits + (1u128 << (step - 1)))),
                IpAddr::V6(Ipv6Addr::from(start_bits + (1u128 << step) - 1)),
            ];
        }
    };

    let step = 128 - target_sub_len; // 80 for /48, 72 for /56
    let num_subnets_shift = target_sub_len - prefix_len;

    if num_subnets_shift > 16 {
        // Prevent subnet explosion in memory; return only base-block targets
        return vec![
            IpAddr::V6(Ipv6Addr::from(start_bits + 1)),
            IpAddr::V6(Ipv6Addr::from(start_bits + (1u128 << (step - 1)))),
            IpAddr::V6(Ipv6Addr::from(start_bits + (1u128 << step) - 1)),
        ];
    }

    let num_subnets = 1usize << num_subnets_shift;
    let mut targets = Vec::with_capacity(num_subnets * 3);

    for i in 0..num_subnets {
        let subnet_bits = start_bits + ((i as u128) << step);
        targets.push(IpAddr::V6(Ipv6Addr::from(subnet_bits + 1)));
        targets.push(IpAddr::V6(Ipv6Addr::from(subnet_bits + (1u128 << (step - 1)))));
        targets.push(IpAddr::V6(Ipv6Addr::from(subnet_bits + (1u128 << step) - 1)));
    }

    targets
}

/// Performs the complete scan by sending raw ICMP packets and parsing ICMP error responses.
///
/// # Arguments
/// * `prefixes`        - List of CIDR prefixes to scan.
/// * `ipv4_delay_ms`   - Delay between IPv4 sends in milliseconds.
/// * `ipv6_delay_us`   - Delay between IPv6 sends in microseconds.
/// * `timeout_secs`    - Seconds to wait for responses after all packets are sent.
/// * `rounds`          - Number of transmission rounds (to mitigate ARP/cold-route drops).
/// * `round_delay_ms`  - Delay between rounds in milliseconds.
/// * `label`           - Client identifier used in progress output (supports parallel scans).
pub async fn check_prefixes(
    prefixes: &[String],
    ipv4_delay_ms: u64,
    ipv6_delay_us: u64,
    timeout_secs: f64,
    rounds: u32,
    round_delay_ms: u64,
    label: &str,
) -> Result<Vec<LoopResult>, String> {
    // SEC-2: Random 16-bit session identifier per scan run.
    // Using PID (previous approach) was predictable; a local attacker could inject
    // spoofed Time Exceeded packets with the known identifier to produce false positives.
    let session_id: u16 = rand::thread_rng().gen();
    let id_high = (session_id >> 8) as u8;
    let id_low = (session_id & 0xff) as u8;

    // Create raw sockets
    let socket_v4 = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|e| format!("Failed to create IPv4 raw socket (needs cap_net_raw): {}", e))?;
    let socket_v6 = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .map_err(|e| format!("Failed to create IPv6 raw socket (needs cap_net_raw): {}", e))?;

    // Short timeout on recv so receiver threads can check the `running` flag regularly
    socket_v4
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();
    socket_v6
        .set_read_timeout(Some(Duration::from_millis(100)))
        .ok();

    // Enlarge OS kernel buffers to absorb bursts without dropping packets under heavy load
    socket_v4.set_recv_buffer_size(4 * 1024 * 1024).ok();
    socket_v6.set_recv_buffer_size(4 * 1024 * 1024).ok();
    socket_v4.set_send_buffer_size(4 * 1024 * 1024).ok();
    socket_v6.set_send_buffer_size(4 * 1024 * 1024).ok();

    // Shared map: target_ip → router_ip (populated by receiver threads)
    let detected_loops = Arc::new(Mutex::new(HashMap::<IpAddr, IpAddr>::new()));

    // Expand prefixes into individual target IPs and build the reverse map
    let mut ip_to_prefixes_map: HashMap<IpAddr, Vec<String>> = HashMap::new();
    let mut errors: Vec<LoopResult> = Vec::new();

    for prefix_str in prefixes {
        let net = match prefix_str.parse::<IpNetwork>() {
            Ok(n) => n,
            Err(e) => {
                errors.push(LoopResult {
                    prefix: prefix_str.clone(),
                    target_ip: Ipv4Addr::UNSPECIFIED.into(),
                    router_ip: None,
                    error: Some(format!("Invalid prefix: {}", e)),
                });
                continue;
            }
        };
        match net {
            IpNetwork::V4(net_v4) => {
                for ip in net_v4.iter() {
                    ip_to_prefixes_map
                        .entry(IpAddr::V4(ip))
                        .or_default()
                        .push(prefix_str.clone());
                }
            }
            IpNetwork::V6(net_v6) => {
                for ip in get_ipv6_delegated_targets(&net_v6) {
                    ip_to_prefixes_map
                        .entry(ip)
                        .or_default()
                        .push(prefix_str.clone());
                }
            }
        }
    }

    // PERF-2: Wrap the map in Arc directly — no full clone needed.
    // Both receiver threads and the final result loop share a single allocation.
    let ip_to_prefixes = Arc::new(ip_to_prefixes_map);

    // Clone sockets for the receiver threads (socket2::Socket is Send + Sync on Unix)
    let rx_socket_v4 = socket_v4.try_clone().map_err(|e| e.to_string())?;
    let rx_socket_v6 = socket_v6.try_clone().map_err(|e| e.to_string())?;

    // Shared flag to signal receiver threads to exit after the scan is done
    let running = Arc::new(Mutex::new(true));

    // ── IPv4 Receiver Thread ──────────────────────────────────────────────────
    {
        let detected_loops = Arc::clone(&detected_loops);
        let ip_to_prefixes = Arc::clone(&ip_to_prefixes);
        let running = Arc::clone(&running);

        thread::spawn(move || {
            // ROB-3: 4096-byte buffer handles oversized ICMP error packets
            // (standard ICMP Time Exceeded can exceed 1024 bytes with IP options)
            let mut buf = [MaybeUninit::new(0u8); 4096];

            // ROB-1: Recover from mutex poisoning instead of panicking
            while *running.lock().unwrap_or_else(|e| e.into_inner()) {
                if let Ok((sz, _)) = rx_socket_v4.recv_from(&mut buf) {
                    if sz < 20 {
                        continue;
                    }
                    // SAFETY: `recv_from` guarantees that exactly `sz` bytes in `buf`
                    // were initialised by the OS kernel before returning.
                    let data =
                        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, sz) };

                    // Sanity-check the outer IP header: must be IPv4 (version=4)
                    // with a valid IHL (≥ 5 → ≥ 20 bytes). Raw sockets occasionally
                    // deliver malformed frames that would produce garbage offsets.
                    let outer_ihl_words = data[0] & 0x0f;
                    if data[0] >> 4 != 4 || outer_ihl_words < 5 {
                        continue;
                    }
                    let ihl = (outer_ihl_words * 4) as usize;
                    if sz < ihl + 8 {
                        continue;
                    }
                    if data[ihl] != 11 {
                        // Not ICMP Type 11 (Time Exceeded)
                        continue;
                    }

                    let orig_ip_start = ihl + 8;
                    if sz < orig_ip_start + 20 {
                        continue;
                    }
                    if data[orig_ip_start + 9] != 1 {
                        // Encapsulated protocol is not ICMPv4
                        continue;
                    }

                    let target_ip = Ipv4Addr::new(
                        data[orig_ip_start + 16],
                        data[orig_ip_start + 17],
                        data[orig_ip_start + 18],
                        data[orig_ip_start + 19],
                    );
                    let ip_addr = IpAddr::V4(target_ip);

                    if ip_to_prefixes.contains_key(&ip_addr) {
                        let router_ip =
                            Ipv4Addr::new(data[12], data[13], data[14], data[15]);

                        // Filter 1: router_ip must differ from target_ip.
                        // When they are equal the target host itself sent the Time
                        // Exceeded (hairpin route, misconfigured static route, etc.)
                        // — that is NOT a routing loop between two distinct routers.
                        if router_ip == target_ip {
                            continue;
                        }

                        // SEC-2 (FAIL-CLOSED): Verify the ICMP identifier inside
                        // the Time Exceeded payload against our random session token.
                        // Logic:
                        //   outer_ihl + 8 (ICMP TE header)
                        //   + orig_inner_ihl (inner IP header)
                        //   + 4 bytes (type/code/checksum)
                        //   = offset of ICMP identifier (id_high, id_low)
                        // FAIL-CLOSED: if the packet is too short to contain the
                        // full inner ICMP header, REJECT it instead of accepting
                        // speculatively. This prevents truncated stray traffic from
                        // bypassing the session check.
                        // EMBEDDED TYPE: also confirm the embedded ICMP message is
                        // an Echo Request (type 8) — guarantees this Time Exceeded
                        // is a response to our probe and not to some other ICMP type.
                        let orig_inner_ihl_words = data[orig_ip_start] & 0x0f;
                        if orig_inner_ihl_words < 5 {
                            continue; // Invalid inner IHL — reject
                        }
                        let orig_inner_ihl = (orig_inner_ihl_words * 4) as usize;
                        let orig_icmp_start = orig_ip_start + orig_inner_ihl;
                        // Need at least 6 bytes of the embedded ICMP: type(1)+code(1)+cksum(2)+id(2)
                        if sz < orig_icmp_start + 6 {
                            continue; // Too short to verify — REJECT (fail-closed)
                        }
                        if data[orig_icmp_start] != 8 {
                            continue; // Embedded type is not Echo Request — not our probe
                        }
                        if data[orig_icmp_start + 4] != id_high
                            || data[orig_icmp_start + 5] != id_low
                        {
                            continue; // Session ID mismatch — not our packet
                        }

                        // ROB-1: Skip insert on poisoned mutex instead of panicking
                        if let Ok(mut map) = detected_loops.lock() {
                            map.insert(ip_addr, IpAddr::V4(router_ip));
                        }
                    }
                }
            }
        });
    }

    // ── ICMPv6 Receiver Thread ────────────────────────────────────────────────
    {
        let detected_loops = Arc::clone(&detected_loops);
        let ip_to_prefixes = Arc::clone(&ip_to_prefixes);
        let running = Arc::clone(&running);

        thread::spawn(move || {
            let mut buf = [MaybeUninit::new(0u8); 4096];

            while *running.lock().unwrap_or_else(|e| e.into_inner()) {
                // ICMPv6 raw sockets on Linux omit the outer IPv6 header;
                // the buffer starts directly at the ICMPv6 header.
                if let Ok((sz, addr)) = rx_socket_v6.recv_from(&mut buf) {
                    if sz < 8 {
                        continue;
                    }
                    // SAFETY: `recv_from` guarantees that exactly `sz` bytes in `buf`
                    // were initialised by the OS kernel before returning.
                    let data =
                        unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, sz) };

                    if data[0] != 3 {
                        // Not ICMPv6 Type 3 (Time Exceeded / Hop Limit Exceeded)
                        continue;
                    }
                    // Original IPv6 header starts at data[8]; dest IP at data[8 + 24] = data[32]
                    if sz < 48 || data[14] != 58 {
                        // Too short, or encapsulated next-header is not ICMPv6 (58)
                        continue;
                    }

                    let mut ip_bytes = [0u8; 16];
                    ip_bytes.copy_from_slice(&data[32..48]);
                    let target_ip = Ipv6Addr::from(ip_bytes);
                    let ip_addr = IpAddr::V6(target_ip);

                    if ip_to_prefixes.contains_key(&ip_addr) {
                        if let Some(socket_addr) = addr.as_socket() {
                            if let IpAddr::V6(router_ip) = socket_addr.ip() {
                                // Filter 1: router must differ from target
                                if IpAddr::V6(router_ip) == ip_addr {
                                    continue;
                                }

                                // SEC-2 (FAIL-CLOSED): Verify the ICMPv6 session ID
                                // and embedded message type.
                                //
                                // Buffer layout (Linux omits outer IPv6 header):
                                //   data[0..8]   ICMPv6 Time Exceeded header
                                //   data[8..48]  original IPv6 header (fixed 40 bytes)
                                //   data[48]     original ICMPv6 type  (must be 128)
                                //   data[49]     code
                                //   data[50..52] checksum
                                //   data[52]     id_high  ← session ID
                                //   data[53]     id_low   ← session ID
                                //   data[54..56] sequence
                                //
                                // FAIL-CLOSED: require at least 56 bytes so all
                                // fields above are present before checking any of them.
                                if sz < 56 {
                                    continue; // Too short — REJECT
                                }
                                if data[48] != 128 {
                                    continue; // Embedded type is not ICMPv6 Echo Request
                                }
                                if data[52] != id_high || data[53] != id_low {
                                    continue; // Session ID mismatch — not our packet
                                }

                                if let Ok(mut map) = detected_loops.lock() {
                                    map.insert(ip_addr, IpAddr::V6(router_ip));
                                }
                            }
                        }
                    }
                }
            }
        });
    }

    // ── Send Loop ─────────────────────────────────────────────────────────────
    let targets: std::collections::BTreeSet<IpAddr> = ip_to_prefixes.keys().cloned().collect();
    let total_targets = targets.len();
    let total_sends = total_targets * (rounds as usize);
    let mut sent_count = 0usize;

    println!(
        "[{}] Scanning {} targets ({} rounds)...",
        label, total_targets, rounds
    );

    for round in 1..=rounds {
        if round > 1 && round_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(round_delay_ms)).await;
        }

        for &target_ip in &targets {
            match target_ip {
                IpAddr::V4(addr) => {
                    let mut packet = [0u8; 64];
                    packet[0] = 8; // Echo Request
                    packet[1] = 0;
                    packet[4] = id_high;
                    packet[5] = id_low;
                    for i in 8..64 {
                        packet[i] = i as u8;
                    }
                    let checksum = calc_checksum(&packet);
                    packet[2] = (checksum >> 8) as u8;
                    packet[3] = (checksum & 0xff) as u8;

                    let dest = SocketAddr::new(IpAddr::V4(addr), 0);
                    // PERF-1: Use tokio::time::sleep for retries so other async tasks
                    // can run during the brief backoff — thread::sleep would block the executor.
                    for _ in 0..10 {
                        if socket_v4.send_to(&packet, &dest.into()).is_ok() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
                IpAddr::V6(addr) => {
                    let mut packet = [0u8; 64];
                    packet[0] = 128; // Echo Request (ICMPv6)
                    packet[1] = 0;
                    // Checksum at packet[2..4] is computed by the OS for ICMPv6
                    packet[4] = id_high;
                    packet[5] = id_low;
                    for i in 8..64 {
                        packet[i] = i as u8;
                    }

                    let dest = SocketAddr::new(IpAddr::V6(addr), 0);
                    for _ in 0..10 {
                        if socket_v6.send_to(&packet, &dest.into()).is_ok() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            }

            sent_count += 1;
            draw_progress(label, sent_count, total_sends);

            // PERF-1: Async sleep between packets — yields to other Tokio tasks
            // (e.g. other clients scanning in parallel) during the inter-packet delay.
            let delay = match target_ip {
                IpAddr::V4(_) => Duration::from_millis(ipv4_delay_ms),
                IpAddr::V6(_) => Duration::from_micros(ipv6_delay_us),
            };
            tokio::time::sleep(delay).await;
        }
    }
    eprintln!(); // Move to next line after progress bar

    // Wait for all in-flight Time Exceeded responses to arrive
    tokio::time::sleep(Duration::from_secs_f64(timeout_secs)).await;

    // Signal receiver threads to exit on their next loop iteration
    if let Ok(mut flag) = running.lock() {
        *flag = false;
    }
    // Wait for receiver threads to finish their current recv_from call (max 100ms timeout).
    // Without this, a Time Exceeded packet that arrived just as we set running=false
    // would be processed by the receiver thread AFTER we snapshot detected_loops, causing
    // a false negative. The 150ms sleep covers the worst case of the 100ms recv timeout.
    tokio::time::sleep(Duration::from_millis(150)).await;

    // ── Build Results ─────────────────────────────────────────────────────────
    let loops_map = detected_loops.lock().unwrap_or_else(|e| e.into_inner());
    let mut results = errors;

    // PERF-2: Iterate via Arc reference — no HashMap clone needed
    for (target_ip, prefixes_list) in ip_to_prefixes.iter() {
        let router_ip = loops_map.get(target_ip).cloned();
        for prefix in prefixes_list {
            results.push(LoopResult {
                prefix: prefix.clone(),
                target_ip: *target_ip,
                router_ip,
                error: None,
            });
        }
    }

    Ok(results)
}
