//! # Email Notification Module (SMTP)
//! 
//! This module loads the SMTP configuration from a TOML file and sends
//! detected loop reports directly to the clients' emails using the `lettre` library.

use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::{Attachment, MultiPart, SinglePart};
use lettre::message::header::ContentType;
use serde::Deserialize;
use std::fs;

/// Validates a comma/semicolon-separated list of email addresses (SEC-5).
/// Uses `lettre`'s own parser — the same one used at send time — so validation is exact.
pub fn validate_email_list(email_str: &str) -> Result<(), String> {
    use lettre::message::Mailbox;
    let mut has_valid = false;
    for addr in email_str.split(|c| c == ',' || c == ';') {
        let trimmed = addr.trim();
        if !trimmed.is_empty() {
            trimmed
                .parse::<Mailbox>()
                .map_err(|_| format!("Invalid email address: '{}'", trimmed))?;
            has_valid = true;
        }
    }
    if !has_valid {
        return Err("At least one valid email address is required".to_string());
    }
    Ok(())
}

/// SEC-4: Verifies that the config file is not readable by group or others.
/// Fails fast with a clear error message if permissions are too broad.
#[cfg(unix)]
fn check_config_permissions(path: &str) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path)
        .map_err(|e| format!("Cannot read metadata for '{}': {}", path, e))?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(format!(
            "Security: '{}' has world/group-readable permissions ({:04o}). \
             Fix with: chmod 600 {}",
            path, mode & 0o777, path
        ));
    }
    Ok(())
}

/// SMTP configuration for sending reports.
#[derive(Debug, Deserialize, Clone)]
pub struct SmtpConfig {
    /// The Host/IP of the SMTP sending server (e.g. "smtp.gmail.com").
    pub host: String,
    /// SMTP Port (e.g. 587 for TLS/STARTTLS, 465 for SSL/implicit TLS).
    pub port: u16,
    /// SMTP Authentication Username (optional).
    pub username: Option<String>,
    /// SMTP Authentication Password (optional).
    pub password: Option<String>,
    /// Sender email address (e.g. "loophunter-alerts@company.com").
    pub from_address: String,
    /// Encryption type: "none", "tls" (STARTTLS), or "ssl" (Implicit TLS).
    pub encryption: Option<String>,
}

/// Scan configuration settings.
#[derive(Debug, Deserialize, Clone)]
pub struct ScanConfig {
    /// Delay between IPv4 packet sends in milliseconds.
    pub ipv4_delay_ms: Option<u64>,
    /// Delay between IPv6 packet sends in microseconds.
    pub ipv6_delay_us: Option<u64>,
    /// Timeout in seconds to wait for responses after sending all requests.
    pub timeout_secs: Option<f64>,
    /// Number of packet transmission rounds.
    pub rounds: Option<u32>,
    /// Delay between rounds in milliseconds.
    pub round_delay_ms: Option<u64>,
}

/// Maps the entire TOML configuration document.
#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub smtp: SmtpConfig,
    pub scan: Option<ScanConfig>,
}

/// Represents an attachment to be sent along with the email.
pub struct EmailAttachment {
    pub filename: String,
    pub content: String,
}

/// Loads and deserializes the `config.toml` file containing SMTP credentials.
/// On Unix, also enforces that the file is not world/group readable (SEC-4).
pub fn load_config(path: &str) -> Result<AppConfig, String> {
    #[cfg(unix)]
    check_config_permissions(path)?;

    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file ({}): {}", path, e))?;
    let config: AppConfig = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;
    Ok(config)
}

fn build_message(
    from_address: &str,
    to_email: &str,
    subject: &str,
    body: &str,
    attachments: &[EmailAttachment],
) -> Result<Message, String> {
    // Basic email construction
    let mut builder = Message::builder()
        .from(
            from_address
                .parse()
                .map_err(|e| format!("Invalid from address: {}", e))?,
        );

    let mut has_recipients = false;
    for addr in to_email.split(|c| c == ',' || c == ';') {
        let trimmed = addr.trim();
        if !trimmed.is_empty() {
            builder = builder.to(trimmed
                .parse()
                .map_err(|e| format!("Invalid to address '{}': {}", trimmed, e))?);
            has_recipients = true;
        }
    }

    if !has_recipients {
        return Err("No valid recipients provided".to_string());
    }

    let builder = builder.subject(subject);

    // Builds the message with or without attachments
    let email = if attachments.is_empty() {
        builder
            .header(ContentType::TEXT_PLAIN)
            .body(body.to_string())
            .map_err(|e| format!("Failed to build email: {}", e))?
    } else {
        let mut multipart = MultiPart::mixed()
            .singlepart(SinglePart::plain(body.to_string()));

        for att in attachments {
            let attachment = Attachment::new(att.filename.clone())
                .body(att.content.clone(), ContentType::TEXT_PLAIN);
            multipart = multipart.singlepart(attachment);
        }

        builder
            .multipart(multipart)
            .map_err(|e| format!("Failed to build email: {}", e))?
    };

    Ok(email)
}

/// Sends an email containing the routing loops report, optionally with attachments.
pub fn send_email(
    config: &SmtpConfig,
    to_email: &str,
    subject: &str,
    body: &str,
    attachments: &[EmailAttachment],
) -> Result<(), String> {
    let email = build_message(&config.from_address, to_email, subject, body, attachments)?;

    // Determines transport based on the specified port or encryption string
    let mut builder = if config.port == 465 || config.encryption.as_deref() == Some("ssl") {
        SmtpTransport::relay(&config.host).map_err(|e| e.to_string())?
    } else {
        SmtpTransport::starttls_relay(&config.host).map_err(|e| e.to_string())?
    };

    builder = builder.port(config.port);

    // Adds credentials if provided in configurations
    if let (Some(user), Some(pass)) = (&config.username, &config.password) {
        builder = builder.credentials(Credentials::new(user.clone(), pass.clone()));
    }

    // Instantiates the transport client and dispatches the email
    let transport = builder.build();
    transport.send(&email).map_err(|e| format!("Failed to send email: {}", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_message_multiple_emails() {
        let from = "alerts@example.com";
        let to = "user1@example.com, user2@example.com; user3@example.com";
        let subject = "Test Subject";
        let body = "Test Body";
        let attachments = vec![];

        let msg = build_message(from, to, subject, body, &attachments).unwrap();

        // Check envelope from address
        assert_eq!(msg.envelope().from().map(|addr| addr.to_string()), Some("alerts@example.com".to_string()));

        // Check envelope to addresses
        let to_envelopes: Vec<String> = msg.envelope().to().iter().map(|addr| addr.to_string()).collect();
        assert_eq!(to_envelopes.len(), 3);
        assert!(to_envelopes.contains(&"user1@example.com".to_string()));
        assert!(to_envelopes.contains(&"user2@example.com".to_string()));
        assert!(to_envelopes.contains(&"user3@example.com".to_string()));
    }

    #[test]
    fn test_build_message_no_recipients() {
        let from = "alerts@example.com";
        let to = "   , ;;   ";
        let subject = "Test Subject";
        let body = "Test Body";
        let attachments = vec![];

        let res = build_message(from, to, subject, body, &attachments);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err(), "No valid recipients provided");
    }
}
