//! # Loophunter: CLI Entrypoint
//!
//! This module manages command-line arguments using the `clap` library,
//! routes user actions to local SQLite database functions, and orchestrates
//! the lifecycle of the routing loop scan (including diff calculations
//! and dispatching email notifications).
//!
//! ## Parallel Scan Architecture (PERF-4)
//!
//! When multiple clients exist, the scan runs in three phases:
//! 1. **Pre-fetch**: All DB data for all clients is loaded sequentially.
//! 2. **Parallel scan**: One `tokio::task` per client runs `check_prefixes` concurrently.
//!    Tasks share the same Tokio executor and interleave during `tokio::time::sleep` yields.
//! 3. **Sequential post-processing**: Results are collected via `JoinSet::join_next`,
//!    DB writes and email sends are done one client at a time (safe, no concurrent writes).

use clap::{Parser, Subcommand};
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv6Addr};
use std::path::PathBuf;
use std::process;
use tokio::task::JoinSet;
use ipnetwork::IpNetwork;

mod checker;
mod db;
mod notifier;

// ── CLI Structure ─────────────────────────────────────────────────────────────

/// Main structure for the `clap` CLI parser.
#[derive(Parser)]
#[command(name = "loophunter")]
#[command(about = "Checks for static routing loops in IPv4 and IPv6 networks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to the SQLite database file.
    /// SEC-3: Explicit flag avoids silent creation of multiple DB files when the
    /// binary is invoked from different working directories (e.g. via cron).
    #[arg(long, default_value = "static_loop.db", global = true)]
    db_path: PathBuf,
}

/// List of available CLI subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Manage clients registered in the system.
    Client {
        #[command(subcommand)]
        action: ClientActions,
    },
    /// Manage CIDR IP prefixes associated with clients.
    Prefix {
        #[command(subcommand)]
        action: PrefixActions,
    },
    /// Run active scanning for routing loops.
    Check {
        /// Filter and scan only this specific client by name.
        #[arg(long)]
        name: Option<String>,

        /// Dispatch email reports to the respective clients if active loops are found/changed.
        #[arg(long)]
        send_email: bool,
    },
}

/// Available actions for client management.
#[derive(Subcommand)]
enum ClientActions {
    /// Register a new client: `client add --name <name> --email <email> --corporate-name <corporate-name>`
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        email: String,
        #[arg(long, rename_all = "kebab-case")]
        corporate_name: String,
    },
    /// Update details of an existing client: `client update --name <name> [--new-name <new-name>] [--email <email>] [--corporate-name <corporate-name>]`
    Update {
        #[arg(long)]
        name: String,
        #[arg(long, rename_all = "kebab-case")]
        new_name: Option<String>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long, rename_all = "kebab-case")]
        corporate_name: Option<String>,
    },
    /// Remove a client: `client remove --name <name>`
    Remove {
        #[arg(long)]
        name: String,
    },
    /// List all registered clients.
    List,
}

/// Available actions for network prefix management.
#[derive(Subcommand)]
enum PrefixActions {
    /// Associate a CIDR prefix (IPv4/IPv6) with a client: `prefix add --name <name> --prefix <prefix> --asn <asn>`
    Add {
        #[arg(long)]
        name: String,
        #[arg(long)]
        prefix: String,
        #[arg(long)]
        asn: String,
    },
    /// Remove a prefix: `prefix remove --prefix <prefix>`
    Remove {
        #[arg(long)]
        prefix: String,
    },
    /// List registered prefixes (optionally filtered by client: `prefix list [--name <name>]`)
    List {
        #[arg(long)]
        name: Option<String>,
    },
}

// ── ASCII Banner ──────────────────────────────────────────────────────────────

const BANNER: &str = r#"$$\                                    $$\   $$\                      $$\                         
$$ |                                   $$ |  $$ |                     $$ |                        
$$ |      $$$$$$\   $$$$$$\   $$$$$$\  $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$ |     $$  __$$\ $$  __$$\ $$  __$$\ $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ 
$$ |     $$ /  $$ |$$ /  $$ |$$ /  $$ |$$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|
$$ |     $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |      
$$$$$$$$\\$$$$$$  |\$$$$$$  |$$$$$$$  |$$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      
\________|\_______/  \______/ $$  ____/ \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      
                              $$ |                                                                 
                              $$ |                                                                 
                              \__|"#;

// ── Parallel Scan Types ───────────────────────────────────────────────────────

/// Scan parameters passed to each client's async scan task.
/// Must be `Clone` so each spawned task gets its own copy.
#[derive(Clone)]
struct ScanParams {
    ipv4_delay_ms: u64,
    ipv6_delay_us: u64,
    timeout_secs: f64,
    rounds: u32,
    round_delay_ms: u64,
}

/// All output produced by a single client's scan task.
/// Returned from the JoinSet and processed sequentially in Phase 3.
struct ClientScanReport {
    client: db::Client,
    saved_loops: Vec<db::SavedLoop>,
    console_output: String,
    email_attachments: Vec<notifier::EmailAttachment>,
    email_subject: String,
    email_body: String,
    total_loops: usize,
    has_changes: bool,
}

// ── Per-client Scan Logic (runs as an independent Tokio task) ─────────────────

/// Executes a full routing loop scan for one client and returns a complete report.
///
/// Designed to be spawned with `tokio::task::JoinSet::spawn` for parallel execution.
/// All database I/O is done outside this function (pre-fetched before spawn, written
/// after all tasks complete) so no DB connection crosses async task boundaries.
async fn run_client_scan(
    client: db::Client,
    prefixes: Vec<db::ClientPrefix>,
    previous_loops: Vec<db::SavedLoop>,
    params: ScanParams,
) -> ClientScanReport {
    // This label is printed in progress output so parallel scans are distinguishable
    let label = client.name.clone();

    let header = format!("Checking client: {} ({})", client.name, client.corporate_name);
    let separator = "=".repeat(header.len());
    let mut console_output = format!("{}\n{}\n{}\n", separator, header, separator);

    if prefixes.is_empty() {
        console_output.push_str("No prefixes registered for this client.\n");
        return ClientScanReport {
            client,
            saved_loops: vec![],
            console_output,
            email_attachments: vec![],
            email_subject: String::new(),
            email_body: String::new(),
            total_loops: 0,
            has_changes: false,
        };
    }

    // Build prefix → ASN mapping for report grouping
    let mut prefix_to_asn: HashMap<String, String> = HashMap::new();
    let mut all_asns: BTreeSet<String> = BTreeSet::new();
    for p in &prefixes {
        let raw_asn = p.asn.as_deref().unwrap_or("AS_UNKNOWN");
        let asn_val = if raw_asn == "AS_UNKNOWN" || raw_asn.starts_with("AS") {
            raw_asn.to_string()
        } else {
            format!("AS{}", raw_asn)
        };
        prefix_to_asn.insert(p.prefix.clone(), asn_val.clone());
        all_asns.insert(asn_val);
    }

    let prefix_strings: Vec<String> = prefixes.iter().map(|p| p.prefix.clone()).collect();

    // Run the ICMP scan (async — yields frequently via tokio::time::sleep)
    let mut results = match checker::check_prefixes(
        &prefix_strings,
        params.ipv4_delay_ms,
        params.ipv6_delay_us,
        params.timeout_secs,
        params.rounds,
        params.round_delay_ms,
        &label,
    )
    .await
    {
        Ok(res) => res,
        Err(e) => {
            console_output.push_str(&format!("Error running scan: {}\n", e));
            return ClientScanReport {
                client,
                saved_loops: vec![],
                console_output,
                email_attachments: vec![],
                email_subject: String::new(),
                email_body: String::new(),
                total_loops: 0,
                has_changes: false,
            };
        }
    };

    // Surface per-IP errors (e.g. failed to send to an IP due to OS constraints)
    for r in &results {
        if let Some(ref err) = r.error {
            console_output.push_str(&format!(
                "Warning: Failed to check prefix {} (target: {}): {}\n",
                r.prefix, r.target_ip, err
            ));
        }
    }

    // ── Confirmation pass ─────────────────────────────────────────────────────
    // Any IP that was looping in the previous scan but not detected in this scan is
    // re-probed with conservative parameters before being treated as "resolved".
    //
    // Root cause this addresses: `tokio::time::sleep(1ms)` is ~4× more precise than
    // the old `thread::sleep(1ms)` (Linux timer granularity was ~4ms at 250Hz). The
    // higher packet rate causes the loop router to hit its ICMP error rate limit,
    // silently dropping some Time Exceeded responses → false "resolved" reports.
    {
        let current_detected: std::collections::HashSet<std::net::IpAddr> = results
            .iter()
            .filter(|r| r.router_ip.is_some())
            .map(|r| r.target_ip)
            .collect();

        // Build /32 or /128 host-route pseudo-prefixes for targeted re-probing
        let confirm_prefixes: Vec<String> = previous_loops
            .iter()
            .filter_map(|pl| {
                let prev_ip = pl.target_ip.parse::<std::net::IpAddr>().ok()?;
                if current_detected.contains(&prev_ip) {
                    return None; // Already confirmed looping — no re-probe needed
                }
                Some(match prev_ip {
                    std::net::IpAddr::V4(_) => format!("{}/32", prev_ip),
                    std::net::IpAddr::V6(_) => format!("{}/128", prev_ip),
                })
            })
            .collect();

        if !confirm_prefixes.is_empty() {
            eprintln!(
                "  [{}] {} candidate(s) undetected — running confirmation scan...",
                label,
                confirm_prefixes.len()
            );

            // Conservative parameters: slower sends and longer recovery time between
            // rounds so the rate-limiting router has time to reset its token bucket.
            let confirm_label = format!("{} [confirm]", label);
            if let Ok(confirm_res) = checker::check_prefixes(
                &confirm_prefixes,
                10,   // ipv4_delay_ms — 10× slower than default (less rate-limit pressure)
                1000, // ipv6_delay_us
                2.0,  // timeout_secs
                3,    // rounds
                2000, // round_delay_ms — 2s recovery window between rounds
                &confirm_label,
            )
            .await
            {
                for cr in confirm_res {
                    if let Some(router_ip) = cr.router_ip {
                        // Still looping! Map the confirmation result back to the
                        // original prefix (the confirm scan used a /32 pseudo-prefix)
                        let original_prefix = previous_loops
                            .iter()
                            .find(|pl| pl.target_ip == cr.target_ip.to_string())
                            .map(|pl| pl.prefix.clone())
                            .unwrap_or_else(|| cr.prefix.clone());

                        results.push(checker::LoopResult {
                            prefix: original_prefix,
                            target_ip: cr.target_ip,
                            router_ip: Some(router_ip),
                            error: None,
                        });
                    }
                }
            }
        }
    }

    // Build the list of loops to persist
    let saved_loops: Vec<db::SavedLoop> = results
        .iter()
        .filter(|r| r.router_ip.is_some())
        .map(|r| db::SavedLoop {
            prefix: r.prefix.clone(),
            target_ip: r.target_ip.to_string(),
            router_ip: r.router_ip.unwrap().to_string(),
        })
        .collect();

    // Internal grouping structure (per-ASN)
    struct AsnResult {
        current_v4_count: usize,
        current_v6_count: usize,
        current_loops: BTreeSet<String>,
        previous_loops: BTreeSet<String>,
    }

    let mut asn_results: HashMap<String, AsnResult> = all_asns
        .iter()
        .map(|asn| {
            (
                asn.clone(),
                AsnResult {
                    current_v4_count: 0,
                    current_v6_count: 0,
                    current_loops: BTreeSet::new(),
                    previous_loops: BTreeSet::new(),
                },
            )
        })
        .collect();

    // Group current scan results by ASN → (router_ip, target_block)
    let mut current_grouped: HashMap<String, HashMap<(String, String), BTreeSet<String>>> =
        HashMap::new();
    for r in &results {
        if let Some(router) = r.router_ip {
            let asn_val = prefix_to_asn
                .get(&r.prefix)
                .cloned()
                .unwrap_or_else(|| "AS_UNKNOWN".to_string());
            let target_str = if r.target_ip.is_ipv6() {
                get_ipv6_subblock(r.target_ip, &r.prefix)
            } else {
                r.target_ip.to_string()
            };
            current_grouped
                .entry(asn_val)
                .or_default()
                .entry((router.to_string(), target_str))
                .or_default()
                .insert(r.target_ip.to_string());
        }
    }

    // Group previous scan results by ASN → (router_ip, target_block)
    let mut previous_grouped: HashMap<String, HashMap<(String, String), BTreeSet<String>>> =
        HashMap::new();
    for l in &previous_loops {
        let asn_val = prefix_to_asn
            .get(&l.prefix)
            .cloned()
            .unwrap_or_else(|| "AS_UNKNOWN".to_string());
        let target_ip_parsed: Result<IpAddr, _> = l.target_ip.parse();
        let target_str = if let Ok(ip) = target_ip_parsed {
            if ip.is_ipv6() {
                get_ipv6_subblock(ip, &l.prefix)
            } else {
                l.target_ip.clone()
            }
        } else {
            l.target_ip.clone()
        };
        previous_grouped
            .entry(asn_val)
            .or_default()
            .entry((l.router_ip.clone(), target_str))
            .or_default()
            .insert(l.target_ip.clone());
    }

    // Populate per-ASN results
    for (asn_val, asn_res) in asn_results.iter_mut() {
        if let Some(groups) = current_grouped.get(asn_val) {
            for ((router, target_str), targets) in groups {
                let is_v6 = targets.iter().any(|t| t.contains(':'));
                let display_str = if is_v6 {
                    format!(
                        "{} - {} (target: {})",
                        router,
                        target_str,
                        targets.iter().cloned().collect::<Vec<_>>().join(", ")
                    )
                } else {
                    format!("{} - {}", router, target_str)
                };
                asn_res.current_loops.insert(display_str);
                if is_v6 {
                    asn_res.current_v6_count += 1;
                } else {
                    asn_res.current_v4_count += 1;
                }
            }
        }
        if let Some(groups) = previous_grouped.get(asn_val) {
            for ((router, target_str), targets) in groups {
                let is_v6 = targets.iter().any(|t| t.contains(':'));
                let display_str = if is_v6 {
                    format!(
                        "{} - {} (target: {})",
                        router,
                        target_str,
                        targets.iter().cloned().collect::<Vec<_>>().join(", ")
                    )
                } else {
                    format!("{} - {}", router, target_str)
                };
                asn_res.previous_loops.insert(display_str);
            }
        }
    }

    let mut email_attachments = Vec::new();
    let mut total_loops = 0usize;
    let mut has_changes = false;
    let mut sorted_asns: Vec<String> = all_asns.into_iter().collect();
    sorted_asns.sort();

    let mut report_body = String::new();
    let mut email_body_totals = String::new();

    for asn_name in &sorted_asns {
        if let Some(asn_res) = asn_results.get(asn_name) {
            let current_count = asn_res.current_loops.len();
            total_loops += current_count;

            // PERF-3: BTreeSet::difference() is O(n) — cleaner and faster than
            // iterating one set and calling .contains() (O(n log n) overall) on the other.
            let mut diff_lines = Vec::new();
            for old in asn_res.previous_loops.difference(&asn_res.current_loops) {
                diff_lines.push(format!("{:<85} <", old));
            }
            for new in asn_res.current_loops.difference(&asn_res.previous_loops) {
                diff_lines.push(format!("{:<85} > {}", "", new));
            }

            if !diff_lines.is_empty() {
                has_changes = true;
            }

            email_body_totals.push_str(&format!(
                "{} - IPv4: {} / IPv6: {}\n",
                asn_name, asn_res.current_v4_count, asn_res.current_v6_count
            ));

            let mut asn_report = String::new();
            asn_report.push_str(&format!(
                "CURRENT STATIC LOOPS: {} (IPv4: {} / IPv6: {})\n",
                current_count, asn_res.current_v4_count, asn_res.current_v6_count
            ));
            asn_report.push_str("====================\n\n");
            for l in &asn_res.current_loops {
                asn_report.push_str(&format!("{}\n", l));
            }
            asn_report.push('\n');

            if !asn_res.previous_loops.is_empty() {
                asn_report.push_str("PREVIOUS DIFFERENCES\n");
                asn_report.push_str("====================\n\n");
                asn_report.push_str(
                    "OLD SIDE                                                                              NEW SIDE\n",
                );
                asn_report.push_str(
                    "===================================================================================================================================\n\n",
                );
                for line in &diff_lines {
                    asn_report.push_str(&format!("{}\n", line));
                }
            }

            report_body.push_str(&format!("ASN: {}\n", asn_name));
            report_body.push_str(&"=".repeat(15 + asn_name.len()));
            report_body.push('\n');
            report_body.push_str(&asn_report);
            report_body.push_str("\n\n");

            if current_count > 0 {
                email_attachments.push(notifier::EmailAttachment {
                    filename: format!("report_{}.txt", asn_name),
                    content: asn_report,
                });
            }
        }
    }

    console_output.push('\n');
    console_output.push_str(&report_body);

    let email_subject = format!("STATIC LOOP - {}", client.corporate_name);
    let email_body = format!(
        "Dear User,\n\n\
         Static Routing Loop Scan Report:\n\
         Corporate Name: {}\n\n\
         Totals per ASN:\n\
         {}\n\n\
         Best regards,\n\
         LoopHunter Monitoring System",
        client.corporate_name,
        email_body_totals.trim_end()
    );

    ClientScanReport {
        client,
        saved_loops,
        console_output,
        email_attachments,
        email_subject,
        email_body,
        total_loops,
        has_changes,
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    println!("{}", BANNER);
    println!("v{} | https://ispfocus.net.br\n", env!("CARGO_PKG_VERSION"));

    let cli = Cli::parse();

    // SEC-3: db_path comes from CLI flag — no more silent CWD-relative file creation.
    // Defaults to "static_loop.db" but can be overridden globally across all subcommands.
    let db_path = &cli.db_path;

    let mut conn = match db::init_db(db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error initializing database: {}", e);
            process::exit(1);
        }
    };

    match cli.command {
        // ── Client management ─────────────────────────────────────────────────
        Commands::Client { action } => match action {
            ClientActions::Add {
                name,
                email,
                corporate_name,
            } => {
                // SEC-5: Validate email format before persisting to DB.
                // Uses lettre's own Mailbox parser — same validation used at send time.
                if let Err(e) = notifier::validate_email_list(&email) {
                    eprintln!("Error: {}", e);
                    process::exit(1);
                }
                match db::add_client(&conn, &name, &email, &corporate_name) {
                    Ok(_) => println!("Client '{}' added successfully.", name),
                    Err(e) => {
                        eprintln!("Error adding client: {}", e);
                        process::exit(1);
                    }
                }
            }
            ClientActions::Update {
                name,
                new_name,
                email,
                corporate_name,
            } => {
                // SEC-5: Validate new email if provided
                if let Some(ref em) = email {
                    if let Err(e) = notifier::validate_email_list(em) {
                        eprintln!("Error: {}", e);
                        process::exit(1);
                    }
                }
                match db::update_client(
                    &conn,
                    &name,
                    new_name.as_deref(),
                    email.as_deref(),
                    corporate_name.as_deref(),
                ) {
                    Ok(count) if count > 0 => {
                        println!("Client '{}' updated successfully.", name)
                    }
                    Ok(_) => println!("Client '{}' not found or no changes provided.", name),
                    Err(e) => {
                        eprintln!("Error updating client: {}", e);
                        process::exit(1);
                    }
                }
            }
            ClientActions::Remove { name } => {
                match db::remove_client(&conn, &name) {
                    Ok(count) if count > 0 => {
                        println!("Client '{}' removed successfully.", name)
                    }
                    Ok(_) => println!("Client '{}' not found.", name),
                    Err(e) => {
                        eprintln!("Error removing client: {}", e);
                        process::exit(1);
                    }
                }
            }
            ClientActions::List => {
                match db::list_clients(&conn) {
                    Ok(clients) => {
                        println!("{:<5} | {:<20} | {:<30} | Corporate Name", "ID", "Name", "Email");
                        println!("{}", "-".repeat(85));
                        for c in clients {
                            println!(
                                "{:<5} | {:<20} | {:<30} | {}",
                                c.id, c.name, c.email, c.corporate_name
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("Error listing clients: {}", e);
                        process::exit(1);
                    }
                }
            }
        },

        // ── Prefix management ─────────────────────────────────────────────────
        Commands::Prefix { action } => match action {
            PrefixActions::Add { name, prefix, asn } => {
                let net: ipnetwork::IpNetwork = match prefix.parse() {
                    Ok(n) => n,
                    Err(e) => {
                        eprintln!("Error parsing prefix '{}': {}", prefix, e);
                        process::exit(1);
                    }
                };

                match net {
                    ipnetwork::IpNetwork::V4(v4) => {
                        if v4.prefix() < 16 {
                            eprintln!(
                                "Error: IPv4 prefix size must be /16 or smaller. Got /{}",
                                v4.prefix()
                            );
                            process::exit(1);
                        }
                    }
                    ipnetwork::IpNetwork::V6(v6) => {
                        if v6.prefix() < 32 {
                            eprintln!(
                                "Error: IPv6 prefix size must be /32 or smaller. Got /{}",
                                v6.prefix()
                            );
                            process::exit(1);
                        }
                    }
                }

                if !asn.chars().all(|c| c.is_ascii_digit()) {
                    eprintln!(
                        "Error: ASN must contain only digits (no prefix). Got '{}'",
                        asn
                    );
                    process::exit(1);
                }

                match db::add_prefix(&conn, &name, &prefix, Some(&asn)) {
                    Ok(_) => println!("Prefix '{}' (AS{}) added to client '{}'.", prefix, asn, name),
                    Err(e) => {
                        eprintln!("Error adding prefix: {}", e);
                        process::exit(1);
                    }
                }
            }
            PrefixActions::Remove { prefix } => {
                match db::remove_prefix(&conn, &prefix) {
                    Ok(count) if count > 0 => {
                        println!("Prefix '{}' removed successfully.", prefix)
                    }
                    Ok(_) => println!("Prefix '{}' not found.", prefix),
                    Err(e) => {
                        eprintln!("Error removing prefix: {}", e);
                        process::exit(1);
                    }
                }
            }
            PrefixActions::List { name } => {
                match db::list_prefixes(&conn, name.as_deref()) {
                    Ok(prefixes) => {
                        println!("{:<30} | {:<20} | ASN", "Prefix", "Client");
                        println!("{}", "-".repeat(65));
                        for p in prefixes {
                            let asn_str = match p.asn.as_deref() {
                                Some("AS_UNKNOWN") | None => "UNKNOWN".to_string(),
                                Some(val) => {
                                    if val.starts_with("AS") && val != "AS_UNKNOWN" {
                                        val[2..].to_string()
                                    } else {
                                        val.to_string()
                                    }
                                }
                            };
                            println!("{:<30} | {:<20} | {}", p.prefix, p.client_name, asn_str);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error listing prefixes: {}", e);
                        process::exit(1);
                    }
                }
            }
        },

        // ── Scan ──────────────────────────────────────────────────────────────
        Commands::Check { name, send_email } => {
            // Load config.toml — SEC-4 permission check happens inside load_config on Unix
            let config_loaded = notifier::load_config("config.toml").ok();

            let smtp_config = if send_email {
                if let Some(ref cfg) = config_loaded {
                    Some(cfg.smtp.clone())
                } else {
                    eprintln!(
                        "Error: config.toml must be present and valid when --send-email is active."
                    );
                    process::exit(1);
                }
            } else {
                None
            };

            // Extract scan parameters from config or use safe defaults
            let (ipv4_delay_ms, ipv6_delay_us, timeout_secs, rounds, round_delay_ms) =
                if let Some(ref cfg) = config_loaded {
                    if let Some(ref scan) = cfg.scan {
                        (
                            scan.ipv4_delay_ms.unwrap_or(10),
                            scan.ipv6_delay_us.unwrap_or(200),
                            scan.timeout_secs.unwrap_or(2.0),
                            scan.rounds.unwrap_or(3),
                            scan.round_delay_ms.unwrap_or(1000),
                        )
                    } else {
                        (10, 200, 2.0, 3, 1000)
                    }
                } else {
                    (10, 200, 2.0, 3, 1000)
                };

            // Determine which clients will be scanned
            let clients_to_check = if let Some(ref n) = name {
                match db::get_client_by_name(&conn, n) {
                    Ok(Some(c)) => vec![c],
                    Ok(None) => {
                        eprintln!("Client '{}' not found.", n);
                        process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Error retrieving client: {}", e);
                        process::exit(1);
                    }
                }
            } else {
                match db::list_clients(&conn) {
                    Ok(list) => list,
                    Err(e) => {
                        eprintln!("Error listing clients: {}", e);
                        process::exit(1);
                    }
                }
            };

            if clients_to_check.is_empty() {
                println!("No clients registered in database.");
                return;
            }

            // ── Phase 1: Pre-fetch all DB data ───────────────────────────────
            // All DB reads happen sequentially here, before any async tasks are spawned.
            // This keeps SQLite access single-threaded and avoids connection-sharing issues.
            let mut pre_scan_list: Vec<(db::Client, Vec<db::ClientPrefix>, Vec<db::SavedLoop>)> =
                Vec::new();

            for c in clients_to_check {
                let prefixes = match db::get_prefixes_for_client(&conn, c.id) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!(
                            "Error reading prefixes for client '{}': {}",
                            c.name, e
                        );
                        continue;
                    }
                };

                if prefixes.is_empty() {
                    println!("No prefixes registered for client '{}'. Skipping.", c.name);
                    continue;
                }

                let previous_loops = match db::get_active_loops(&conn, c.id) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!(
                            "Error reading loop history for '{}': {}",
                            c.name, e
                        );
                        Vec::new()
                    }
                };

                pre_scan_list.push((c, prefixes, previous_loops));
            }

            if pre_scan_list.is_empty() {
                println!("No clients with prefixes to scan.");
                return;
            }

            let num_clients = pre_scan_list.len();
            let params = ScanParams {
                ipv4_delay_ms,
                ipv6_delay_us,
                timeout_secs,
                rounds,
                round_delay_ms,
            };

            if num_clients > 1 {
                println!(
                    "Launching parallel scan for {} client(s). Each scan runs concurrently.\n",
                    num_clients
                );
            }

            // ── Phase 2: Spawn parallel scan tasks (PERF-4) ──────────────────
            // Each task owns its data (moved), runs check_prefixes concurrently,
            // and yields during tokio::time::sleep so all tasks make progress together.
            let mut join_set: JoinSet<ClientScanReport> = JoinSet::new();

            for (client, prefixes, previous_loops) in pre_scan_list {
                let params = params.clone();
                join_set.spawn(async move {
                    run_client_scan(client, prefixes, previous_loops, params).await
                });
            }

            // ── Phase 3: Collect results, write DB, send emails ───────────────
            // join_next() returns whichever task finishes first (not necessarily in order).
            // DB writes and email sends are sequential here — no concurrent DB access.
            while let Some(task_result) = join_set.join_next().await {
                match task_result {
                    Ok(report) => {
                        print!("{}", report.console_output);

                        if let Err(e) =
                            db::set_active_loops(&mut conn, report.client.id, &report.saved_loops)
                        {
                            eprintln!(
                                "Error saving active loops for '{}': {}",
                                report.client.name, e
                            );
                        }

                        if let Some(ref smtp_cfg) = smtp_config {
                            if report.total_loops > 0 || report.has_changes {
                                println!(
                                    "Sending email report to {}...",
                                    report.client.email
                                );
                                match notifier::send_email(
                                    smtp_cfg,
                                    &report.client.email,
                                    &report.email_subject,
                                    &report.email_body,
                                    &report.email_attachments,
                                ) {
                                    Ok(_) => println!("Email sent successfully."),
                                    Err(e) => eprintln!("Error sending email: {}", e),
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Client scan task failed unexpectedly: {}", e);
                    }
                }
            }
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Returns the IPv6 sub-block (e.g. /48 or /56) that contains `target_ip`,
/// computed relative to `parent_prefix_str`. Used for grouping loop displays.
fn get_ipv6_subblock(target_ip: IpAddr, parent_prefix_str: &str) -> String {
    let target_v6 = match target_ip {
        IpAddr::V6(v6) => v6,
        IpAddr::V4(_) => return target_ip.to_string(),
    };

    let parent_net = match parent_prefix_str.parse::<IpNetwork>() {
        Ok(IpNetwork::V6(net)) => net,
        _ => return target_ip.to_string(),
    };

    let parent_len = parent_net.prefix();
    let sub_len = if parent_len < 48 {
        48
    } else if parent_len < 56 {
        56
    } else {
        parent_len
    };

    let ip_u128 = u128::from(target_v6);
    let mask = !0u128 ^ ((1u128 << (128 - sub_len)) - 1);
    let masked_ip = Ipv6Addr::from(ip_u128 & mask);

    format!("{}/{}", masked_ip, sub_len)
}
