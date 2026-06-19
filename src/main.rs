//! # Loophunter: CLI Entrypoint
//! 
//! This module manages command-line arguments using the `clap` library,
//! routes user actions to local SQLite database functions, and orchestrates
//! the lifecycle of the routing loop scan (including diff calculations
//! and dispatching email notifications).

use clap::{Parser, Subcommand};
use std::collections::{BTreeSet, HashMap};
use std::process;
use std::net::{IpAddr, Ipv6Addr};
use ipnetwork::IpNetwork;

mod db;
mod checker;
mod notifier;

/// Main structure for the `clap` CLI parser.
#[derive(Parser)]
#[command(name = "loophunter")]
#[command(about = "Checks for static routing loops in IPv4 and IPv6 networks", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
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

/// ASCII Banner printed on the console during every run.
const BANNER: &str = r#"$$\                                    $$\   $$\                      $$\                         
$$ |                                   $$ |  $$ |                     $$ |                        
$$ |      $$$$$$\   $$$$$$\   $$$$$$\  $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$ |     $$  __$$\ $$  __$$\ $$  __$$\ $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ 
$$ |     $$ /  $$ |$$ /  $$ |$$ /  $$ |$$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|
$$ |     $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |      
$$$$$$$$\\$$$$$$  |\$$$$$$  |$$$$$$$  |$$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      
\________|\______/  \______/ $$  ____/ \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      
                             $$ |                                                                 
                             $$ |                                                                 
                             \__|"#;

#[tokio::main]
async fn main() {
    // Print welcome banner
    println!("{}", BANNER);
    println!("v{} | https://ispfocus.net.br\n", env!("CARGO_PKG_VERSION"));

    let cli = Cli::parse();
    let db_path = "static_loop.db";

    // Initialize local SQLite database
    let mut conn = match db::init_db(db_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error initializing database: {}", e);
            process::exit(1);
        }
    };

    // Route subcommands
    match cli.command {
        Commands::Client { action } => match action {
            ClientActions::Add { name, email, corporate_name } => {
                match db::add_client(&conn, &name, &email, &corporate_name) {
                    Ok(_) => println!("Client '{}' added successfully.", name),
                    Err(e) => {
                        eprintln!("Error adding client: {}", e);
                        process::exit(1);
                    }
                }
            }
            ClientActions::Update { name, new_name, email, corporate_name } => {
                match db::update_client(
                    &conn,
                    &name,
                    new_name.as_deref(),
                    email.as_deref(),
                    corporate_name.as_deref(),
                ) {
                    Ok(count) if count > 0 => println!("Client '{}' updated successfully.", name),
                    Ok(_) => println!("Client '{}' not found or no changes provided.", name),
                    Err(e) => {
                        eprintln!("Error updating client: {}", e);
                        process::exit(1);
                    }
                }
            }
            ClientActions::Remove { name } => {
                match db::remove_client(&conn, &name) {
                    Ok(count) if count > 0 => println!("Client '{}' removed successfully.", name),
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
                            println!("{:<5} | {:<20} | {:<30} | {}", c.id, c.name, c.email, c.corporate_name);
                        }
                    }
                    Err(e) => {
                        eprintln!("Error listing clients: {}", e);
                        process::exit(1);
                    }
                }
            }
        },
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
                            eprintln!("Error: IPv4 prefix size must be /16 or smaller (prefix length >= 16). Got /{}", v4.prefix());
                            process::exit(1);
                        }
                    }
                    ipnetwork::IpNetwork::V6(v6) => {
                        if v6.prefix() < 32 {
                            eprintln!("Error: IPv6 prefix size must be /32 or smaller (prefix length >= 32). Got /{}", v6.prefix());
                            process::exit(1);
                        }
                    }
                }

                if !asn.chars().all(|c| c.is_ascii_digit()) {
                    eprintln!("Error: ASN must contain only numbers (digits) and no prefix. Got '{}'", asn);
                    process::exit(1);
                }

                match db::add_prefix(&conn, &name, &prefix, Some(&asn)) {
                    Ok(_) => {
                        println!("Prefix '{}' (AS{}) added to client '{}'.", prefix, asn, name);
                    }
                    Err(e) => {
                        eprintln!("Error adding prefix: {}", e);
                        process::exit(1);
                    }
                }
            }
            PrefixActions::Remove { prefix } => {
                match db::remove_prefix(&conn, &prefix) {
                    Ok(count) if count > 0 => println!("Prefix '{}' removed successfully.", prefix),
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
        Commands::Check { name, send_email } => {
            // Always try to load config.toml to extract custom scan settings or SMTP credentials
            let config_loaded = notifier::load_config("config.toml").ok();

            let smtp_config = if send_email {
                if let Some(ref cfg) = config_loaded {
                    Some(cfg.smtp.clone())
                } else {
                    eprintln!("Error: config.toml must be present and valid when --send-email is active.");
                    process::exit(1);
                }
            } else {
                None
            };

            // Extract custom scan parameters or fall back to safe defaults
            let (ipv4_delay_ms, ipv6_delay_us, timeout_secs, rounds, round_delay_ms) = if let Some(ref cfg) = config_loaded {
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

            // Run the loop check for each selected client
            for c in clients_to_check {
                let header = format!("Checking client: {} ({})", c.name, c.corporate_name);
                let separator = "=".repeat(header.len());
                println!("{}", separator);
                println!("{}", header);
                println!("{}", separator);

                let prefixes = match db::get_prefixes_for_client(&conn, c.id) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error reading prefixes for client {}: {}", c.name, e);
                        continue;
                    }
                };

                if prefixes.is_empty() {
                    println!("No prefixes registered for this client.");
                    continue;
                }

                // Map prefixes to their respective ASNs
                let mut prefix_to_asn = HashMap::new();
                let mut all_asns = BTreeSet::new();
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

                // Run asynchronous checks and capture results
                let results = match checker::check_prefixes(
                    &prefix_strings,
                    ipv4_delay_ms,
                    ipv6_delay_us,
                    timeout_secs,
                    rounds,
                    round_delay_ms,
                ).await {
                    Ok(res) => res,
                    Err(e) => {
                        eprintln!("Error running checker: {}", e);
                        continue;
                    }
                };

                // Report on stderr if any IP failed to initialize due to local constraints
                for r in &results {
                    if let Some(ref err) = r.error {
                        eprintln!("Warning: Failed to check prefix {} (target: {}): {}", r.prefix, r.target_ip, err);
                    }
                }

                // Load active loops from the previous scan to compute the diff
                let previous_saved = match db::get_active_loops(&conn, c.id) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Error reading active loops history: {}", e);
                        Vec::new()
                    }
                };

                // Update active loops status in the local database
                let saved_loops: Vec<db::SavedLoop> = results
                    .iter()
                    .filter(|r| r.router_ip.is_some())
                    .map(|r| db::SavedLoop {
                        prefix: r.prefix.clone(),
                        target_ip: r.target_ip.to_string(),
                        router_ip: r.router_ip.unwrap().to_string(),
                    })
                    .collect();

                if let Err(e) = db::set_active_loops(&mut conn, c.id, &saved_loops) {
                    eprintln!("Error saving active loops: {}", e);
                }

                // Group results by ASN
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

                // Group current loops by ASN and (router_ip, target_str)
                let mut current_grouped: HashMap<String, HashMap<(String, String), BTreeSet<String>>> = HashMap::new();
                for r in &results {
                    if let Some(router) = r.router_ip {
                        let asn_val = prefix_to_asn.get(&r.prefix).cloned().unwrap_or_else(|| "AS_UNKNOWN".to_string());
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

                // Group previous loops by ASN and (router_ip, target_str)
                let mut previous_grouped: HashMap<String, HashMap<(String, String), BTreeSet<String>>> = HashMap::new();
                for l in &previous_saved {
                    let asn_val = prefix_to_asn.get(&l.prefix).cloned().unwrap_or_else(|| "AS_UNKNOWN".to_string());
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

                // Populate the results structures grouped by ASN
                for (asn_val, asn_res) in asn_results.iter_mut() {
                    if let Some(groups) = current_grouped.get(asn_val) {
                        for ((router, target_str), targets) in groups {
                            let is_v6 = targets.iter().any(|t| t.contains(':'));
                            let display_str = if is_v6 {
                                let targets_joined = targets.iter().cloned().collect::<Vec<_>>().join(", ");
                                format!("{} - {} (target: {})", router, target_str, targets_joined)
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
                                let targets_joined = targets.iter().cloned().collect::<Vec<_>>().join(", ");
                                format!("{} - {} (target: {})", router, target_str, targets_joined)
                            } else {
                                format!("{} - {}", router, target_str)
                            };
                            asn_res.previous_loops.insert(display_str);
                        }
                    }
                }

                let mut email_attachments = Vec::new();
                let mut total_loops_all_asn = 0;
                let mut has_changes = false;

                let mut sorted_asns: Vec<String> = all_asns.into_iter().collect();
                sorted_asns.sort();

                let mut console_report = String::new();
                let mut email_body_totals = String::new();

                for asn_name in &sorted_asns {
                    if let Some(asn_res) = asn_results.get(asn_name) {
                        let current_count = asn_res.current_loops.len();
                        total_loops_all_asn += current_count;

                        // Compute differences using ordered sets
                        let mut diff_lines = Vec::new();
                        for old in &asn_res.previous_loops {
                            if !asn_res.current_loops.contains(old) {
                                diff_lines.push(format!("{:<85} <", old));
                            }
                        }
                        for new in &asn_res.current_loops {
                            if !asn_res.previous_loops.contains(new) {
                                diff_lines.push(format!("{:<85} > {}", "", new));
                            }
                        }

                        if !diff_lines.is_empty() {
                            has_changes = true;
                        }

                        // Write totals to the email body splitting by IPv4 and IPv6
                        email_body_totals.push_str(&format!(
                            "{} - IPv4: {} / IPv6: {}\n",
                            asn_name, asn_res.current_v4_count, asn_res.current_v6_count
                        ));

                        // Build individual report for the ASN
                        let mut asn_report = String::new();
                        asn_report.push_str(&format!(
                            "CURRENT STATIC LOOPS: {} (IPv4: {} / IPv6: {})\n",
                            current_count, asn_res.current_v4_count, asn_res.current_v6_count
                        ));
                        asn_report.push_str("====================\n\n");
                        for l in &asn_res.current_loops {
                            asn_report.push_str(&format!("{}\n", l));
                        }
                        asn_report.push_str("\n");

                        if !asn_res.previous_loops.is_empty() {
                            asn_report.push_str("PREVIOUS DIFFERENCES\n");
                            asn_report.push_str("====================\n\n");
                            asn_report.push_str("OLD SIDE                                                                              NEW SIDE\n");
                            asn_report.push_str("===================================================================================================================================\n\n");
                            for line in &diff_lines {
                                asn_report.push_str(&format!("{}\n", line));
                            }
                        }

                        // Console builder
                        console_report.push_str(&format!("ASN: {}\n", asn_name));
                        console_report.push_str(&"=".repeat(15 + asn_name.len()));
                        console_report.push_str("\n");
                        console_report.push_str(&asn_report);
                        console_report.push_str("\n\n");

                        // Add attachment if active loops exist
                        if current_count > 0 {
                            email_attachments.push(notifier::EmailAttachment {
                                filename: format!("report_{}.txt", asn_name),
                                content: asn_report,
                            });
                        }
                    }
                }

                println!();
                println!("{}", console_report);

                // Dispatch email if configured and loops are active or status has changed
                if let Some(ref smtp_cfg) = smtp_config {
                    if total_loops_all_asn > 0 || has_changes {
                        let subject = format!("STATIC LOOP - {}", c.corporate_name);
                        let body = format!(
                            "Dear User,\n\n\
                             Static Routing Loop Scan Report:\n\
                             Corporate Name: {}\n\n\
                             Totals per ASN:\n\
                             {}\n\n\
                             Best regards,\n\
                             LoopHunter Monitoring System",
                            c.corporate_name, email_body_totals.trim_end()
                        );

                        println!("Sending email report to {}...", c.email);
                        match notifier::send_email(smtp_cfg, &c.email, &subject, &body, &email_attachments) {
                            Ok(_) => println!("Email sent successfully."),
                            Err(e) => eprintln!("Error sending email: {}", e),
                        }
                    }
                }
            }
        }
    }
}

/// Helper to extract correct IPv6 sub-block according to checker prefix rules.
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
