//! # Checker Engine Module (Custom Ping)
//! 
//! This module implements a native ping engine based on Linux raw sockets (via `socket2`).
//! It sends ICMP/ICMPv6 Echo Request packets and listens to all responses. When an intermediate router
//! sends a "Time Exceeded" packet (exceeded hop limit), the engine parses the nested packet inside the ICMP
//! payload (which contains a copy of the original IP header) to recover the intended target IP address.
//! This bypasses the limitations of high-level libraries that do not associate Time Exceeded messages from third-party IPs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::thread;
use ipnetwork::{IpNetwork, Ipv6Network};
use socket2::{Socket, Domain, Type, Protocol};

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

/// Helper to split an IPv6 prefix into representative subnets (e.g. breaking a /32 into /48s)
/// and returning the first usable IP of each.
fn get_ipv6_delegated_targets(net_v6: &Ipv6Network) -> Vec<IpAddr> {
    let prefix_len = net_v6.prefix();
    let start_bits = u128::from(net_v6.network());

    let target_sub_len = if prefix_len < 48 {
        48
    } else if prefix_len < 56 {
        56
    } else {
        // For smaller blocks (prefix length >= 56), define targets according to the available space
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
        // Prevent subnet explosion in memory, return targets only for the base block
        return vec![
            IpAddr::V6(Ipv6Addr::from(start_bits + 1)),
            IpAddr::V6(Ipv6Addr::from(start_bits + (1u128 << (step - 1)))),
            IpAddr::V6(Ipv6Addr::from(start_bits + (1u128 << step) - 1)),
        ];
    }

    let num_subnets = 1 << num_subnets_shift;
    let mut targets = Vec::with_capacity(num_subnets * 3);

    for i in 0..num_subnets {
        let subnet_bits = start_bits + ((i as u128) << step);
        // Beginning (::1)
        targets.push(IpAddr::V6(Ipv6Addr::from(subnet_bits + 1)));
        // Middle
        targets.push(IpAddr::V6(Ipv6Addr::from(subnet_bits + (1u128 << (step - 1)))));
        // End
        targets.push(IpAddr::V6(Ipv6Addr::from(subnet_bits + (1u128 << step) - 1)));
    }

    targets
}

/// Performs the complete scan by sending raw ICMP packets and parsing responses.
pub async fn check_prefixes(prefixes: &[String]) -> Result<Vec<LoopResult>, String> {
    let pid = std::process::id();
    let pid_high = ((pid >> 8) & 0xff) as u8;
    let pid_low = (pid & 0xff) as u8;

    // Creation of raw sockets using socket2
    let socket_v4 = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))
        .map_err(|e| format!("Failed to create IPv4 raw socket (Run as root/sudo): {}", e))?;
    let socket_v6 = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))
        .map_err(|e| format!("Failed to create IPv6 raw socket (Run as root/sudo): {}", e))?;

    // Configures non-blocking or short read timeouts on the sockets
    socket_v4.set_read_timeout(Some(Duration::from_millis(100))).ok();
    socket_v6.set_read_timeout(Some(Duration::from_millis(100))).ok();

    // Increase the send/receive buffer sizes to prevent packet loss under heavy load
    socket_v4.set_recv_buffer_size(4 * 1024 * 1024).ok();
    socket_v6.set_recv_buffer_size(4 * 1024 * 1024).ok();
    socket_v4.set_send_buffer_size(4 * 1024 * 1024).ok();
    socket_v6.set_send_buffer_size(4 * 1024 * 1024).ok();

    // Map of detected loop IPs: target_ip -> router_ip
    let detected_loops = Arc::new(Mutex::new(HashMap::<IpAddr, IpAddr>::new()));

    // Expands the list of IPs to be tested and maps which IP belongs to which prefixes
    let mut ip_to_prefixes: HashMap<IpAddr, Vec<String>> = HashMap::new();
    let mut errors = Vec::new();

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
                    ip_to_prefixes
                        .entry(IpAddr::V4(ip))
                        .or_default()
                        .push(prefix_str.clone());
                }
            }
            IpNetwork::V6(net_v6) => {
                for ip in get_ipv6_delegated_targets(&net_v6) {
                    ip_to_prefixes
                        .entry(ip)
                        .or_default()
                        .push(prefix_str.clone());
                }
            }
        }
    }

    // Clone sockets for the packet receiving threads
    let rx_socket_v4 = socket_v4.try_clone().map_err(|e| e.to_string())?;
    let rx_socket_v6 = socket_v6.try_clone().map_err(|e| e.to_string())?;

    let detected_loops_clone = detected_loops.clone();

    // Flag to stop the receiver threads after scanning
    let running = Arc::new(Mutex::new(true));
    let running_clone = running.clone();

    let ip_to_prefixes_rx = Arc::new(ip_to_prefixes.clone());
    let ip_to_prefixes_rx2 = ip_to_prefixes_rx.clone();

    // Spawn thread to listen for and process ICMPv4 packets
    thread::spawn(move || {
        let mut buf = [std::mem::MaybeUninit::new(0u8); 1024];
        while *running_clone.lock().unwrap() {
            if let Ok((sz, _)) = rx_socket_v4.recv_from(&mut buf) {
                if sz >= 20 {
                    // Safe cast since u8 and MaybeUninit<u8> share the same memory layout
                    let initialized_buf = unsafe { &*(&buf[..sz] as *const [std::mem::MaybeUninit<u8>] as *const [u8]) };
                    
                    let ihl = ((initialized_buf[0] & 0x0f) * 4) as usize;
                    if sz >= ihl + 8 {
                        let icmp_type = initialized_buf[ihl];
                        if icmp_type == 11 { // Time Exceeded
                            let orig_ip_start = ihl + 8;
                            if sz >= orig_ip_start + 20 {
                                let orig_proto = initialized_buf[orig_ip_start + 9];
                                // Verify original protocol is ICMPv4 (1)
                                if orig_proto == 1 {
                                    let target_ip = Ipv4Addr::new(
                                        initialized_buf[orig_ip_start + 16],
                                        initialized_buf[orig_ip_start + 17],
                                        initialized_buf[orig_ip_start + 18],
                                        initialized_buf[orig_ip_start + 19],
                                    );
                                    let ip_addr = IpAddr::V4(target_ip);
                                    if ip_to_prefixes_rx.contains_key(&ip_addr) {
                                        let router_ip = Ipv4Addr::new(initialized_buf[12], initialized_buf[13], initialized_buf[14], initialized_buf[15]);
                                        detected_loops_clone.lock().unwrap().insert(ip_addr, IpAddr::V4(router_ip));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    let detected_loops_clone2 = detected_loops.clone();
    let running_clone2 = running.clone();

    // Spawn thread to listen for and process ICMPv6 packets
    thread::spawn(move || {
        let mut buf = [std::mem::MaybeUninit::new(0u8); 1024];
        while *running_clone2.lock().unwrap() {
            if let Ok((sz, addr)) = rx_socket_v6.recv_from(&mut buf) {
                // ICMPv6 RAW sockets in Linux do not include the outer IPv6 header in the buffer.
                // The buffer starts directly at the ICMPv6 header.
                if sz >= 8 {
                    let initialized_buf = unsafe { &*(&buf[..sz] as *const [std::mem::MaybeUninit<u8>] as *const [u8]) };
                    let icmpv6_type = initialized_buf[0];
                    if icmpv6_type == 3 { // Time Exceeded (Hop Limit Exceeded)
                        // The original IPv6 header starts at buf[8] (8 bytes of ICMPv6 header)
                        // The destination IP starts at offset 8 + 24 = 32.
                        if sz >= 48 {
                            let orig_next_header = initialized_buf[14];
                            if orig_next_header == 58 { // ICMPv6
                                let mut ip_bytes = [0u8; 16];
                                ip_bytes.copy_from_slice(&initialized_buf[32..48]);
                                let target_ip = Ipv6Addr::from(ip_bytes);
                                let ip_addr = IpAddr::V6(target_ip);
                                if ip_to_prefixes_rx2.contains_key(&ip_addr) {
                                    if let Some(socket_addr) = addr.as_socket() {
                                        if let IpAddr::V6(router_ip) = socket_addr.ip() {
                                            detected_loops_clone2.lock().unwrap().insert(ip_addr, IpAddr::V6(router_ip));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    // Send ICMP Echo Request packets (Ping)
    for &target_ip in ip_to_prefixes.keys() {
        match target_ip {
            IpAddr::V4(addr) => {
                let mut packet = [0u8; 64];
                packet[0] = 8;  // Type: Echo Request
                packet[1] = 0;  // Code: 0
                // Checksum at packet[2..4]
                packet[4] = pid_high; // Identifier High (from PID)
                packet[5] = pid_low;  // Identifier Low (from PID)
                for i in 8..64 {
                    packet[i] = i as u8;
                }
                let checksum = calc_checksum(&packet);
                packet[2] = (checksum >> 8) as u8;
                packet[3] = (checksum & 0xff) as u8;

                let dest = SocketAddr::new(IpAddr::V4(addr), 0);
                let mut retries = 0;
                while let Err(_) = socket_v4.send_to(&packet, &dest.into()) {
                    if retries >= 10 {
                        break;
                    }
                    retries += 1;
                    thread::sleep(Duration::from_millis(1));
                }
            }
            IpAddr::V6(addr) => {
                let mut packet = [0u8; 64];
                packet[0] = 128; // Type: Echo Request (ICMPv6)
                packet[1] = 0;   // Code: 0
                // Checksum at packet[2..4] (written by OS)
                packet[4] = pid_high;  // Identifier High (from PID)
                packet[5] = pid_low;   // Identifier Low (from PID)
                for i in 8..64 {
                    packet[i] = i as u8;
                }

                let dest = SocketAddr::new(IpAddr::V6(addr), 0);
                let mut retries = 0;
                while let Err(_) = socket_v6.send_to(&packet, &dest.into()) {
                    if retries >= 10 {
                        break;
                    }
                    retries += 1;
                    thread::sleep(Duration::from_millis(1));
                }
            }
        }
        // Small delay between sends to avoid overloading the local buffer and router ICMP rate-limiting
        let delay = match target_ip {
            IpAddr::V4(_) => Duration::from_millis(1),
            IpAddr::V6(_) => Duration::from_micros(200),
        };
        thread::sleep(delay);
    }

    // Wait for responses to arrive (2 seconds timeout)
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Shutdown the receiving threads
    *running.lock().unwrap() = false;

    // Build final results matching loops with their respective prefixes
    let loops_map = detected_loops.lock().unwrap();
    let mut results = errors;

    for (target_ip, prefixes_list) in ip_to_prefixes {
        let router_ip = loops_map.get(&target_ip).cloned();
        for prefix in prefixes_list {
            results.push(LoopResult {
                prefix,
                target_ip,
                router_ip,
                error: None,
            });
        }
    }

    Ok(results)
}
