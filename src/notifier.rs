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
pub fn load_config(path: &str) -> Result<AppConfig, String> {
    let content = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read config file ({}): {}", path, e))?;
    let config: AppConfig = toml::from_str(&content)
        .map_err(|e| format!("Failed to parse config file: {}", e))?;
    Ok(config)
}

/// Sends an email containing the routing loops report, optionally with attachments.
pub fn send_email(
    config: &SmtpConfig,
    to_email: &str,
    subject: &str,
    body: &str,
    attachments: &[EmailAttachment],
) -> Result<(), String> {
    // Basic email construction
    let builder = Message::builder()
        .from(
            config
                .from_address
                .parse()
                .map_err(|e| format!("Invalid from address: {}", e))?,
        )
        .to(to_email
            .parse()
            .map_err(|e| format!("Invalid to address: {}", e))?)
        .subject(subject);

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
