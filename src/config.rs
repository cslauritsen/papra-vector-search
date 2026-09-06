use std::{collections::HashSet, env, fmt, path::PathBuf};

use anyhow::{Result, anyhow};
use secrecy::{ExposeSecret, SecretString};

#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub sqlite_vec_extension_path: PathBuf,
    pub papra_webhook_secret: SecretString,
    pub papra_organization_id: String,
    pub google_client_id: SecretString,
    pub google_client_secret: SecretString,
    pub google_redirect_uri: String,
    pub google_issuer: String,
    pub google_allowed_emails: HashSet<String>,
    pub auth_enabled: bool,
    pub papra_base_url: Option<String>,
    pub webhook_timestamp_tolerance_seconds: i64,
    pub search_result_limit: usize,
    pub otel_exporter_endpoint: Option<String>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("database_url", &self.database_url)
            .field("sqlite_vec_extension_path", &self.sqlite_vec_extension_path)
            .field("papra_webhook_secret", &"[REDACTED]")
            .field("papra_organization_id", &self.papra_organization_id)
            .field("google_client_id", &"[REDACTED]")
            .field("google_client_secret", &"[REDACTED]")
            .field("google_redirect_uri", &self.google_redirect_uri)
            .field("google_issuer", &self.google_issuer)
            .field("google_allowed_emails", &self.google_allowed_emails)
            .field("auth_enabled", &self.auth_enabled)
            .field("papra_base_url", &self.papra_base_url)
            .field(
                "webhook_timestamp_tolerance_seconds",
                &self.webhook_timestamp_tolerance_seconds,
            )
            .field("search_result_limit", &self.search_result_limit)
            .field("otel_exporter_endpoint", &self.otel_exporter_endpoint)
            .finish()
    }
}

impl Config {
    pub fn from_env() -> Result<Self> {
        let required = |name: &str| -> Result<String> {
            env::var(name)
                .map_err(|_| anyhow!("required environment variable {name} is missing"))
                .and_then(|v| {
                    if v.trim().is_empty() {
                        Err(anyhow!("{name} must not be empty"))
                    } else {
                        Ok(v)
                    }
                })
        };
        let tolerance = env::var("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS")
            .unwrap_or_else(|_| "300".into())
            .parse::<i64>()
            .map_err(|_| anyhow!("WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS must be an integer"))?;
        if tolerance <= 0 {
            return Err(anyhow!(
                "WEBHOOK_TIMESTAMP_TOLERANCE_SECONDS must be positive"
            ));
        }
        let limit = env::var("SEARCH_RESULT_LIMIT")
            .unwrap_or_else(|_| "20".into())
            .parse::<usize>()
            .map_err(|_| anyhow!("SEARCH_RESULT_LIMIT must be an integer"))?;
        if limit == 0 {
            return Err(anyhow!("SEARCH_RESULT_LIMIT must be positive"));
        }
        let auth_enabled = env::var("AUTH_ENABLED")
            .unwrap_or_else(|_| "true".into())
            .parse::<bool>()
            .map_err(|_| anyhow!("AUTH_ENABLED must be true or false"))?;
        let google_allowed_emails = required("GOOGLE_ALLOWED_EMAILS")?
            .split(',')
            .map(|email| email.trim().to_ascii_lowercase())
            .filter(|email| !email.is_empty())
            .collect::<HashSet<_>>();
        if google_allowed_emails.is_empty() {
            return Err(anyhow!(
                "GOOGLE_ALLOWED_EMAILS must contain at least one email"
            ));
        }
        Ok(Self {
            database_url: required("DATABASE_URL")?,
            sqlite_vec_extension_path: PathBuf::from(required("SQLITE_VEC_EXTENSION_PATH")?),
            papra_webhook_secret: SecretString::from(required("PAPRA_WEBHOOK_SECRET")?),
            papra_organization_id: required("PAPRA_ORGANIZATION_ID")?,
            google_client_id: SecretString::from(required("GOOGLE_CLIENT_ID")?),
            google_client_secret: SecretString::from(required("GOOGLE_CLIENT_SECRET")?),
            google_redirect_uri: required("GOOGLE_REDIRECT_URI")?,
            google_issuer: required("GOOGLE_ISSUER")?,
            google_allowed_emails,
            auth_enabled,
            papra_base_url: env::var("PAPRA_BASE_URL").ok(),
            webhook_timestamp_tolerance_seconds: tolerance,
            search_result_limit: limit.min(100),
            otel_exporter_endpoint: env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
        })
    }

    pub fn database_path(&self) -> &str {
        self.database_url
            .strip_prefix("sqlite://")
            .unwrap_or(&self.database_url)
    }

    pub fn google_client_id(&self) -> &str {
        self.google_client_id.expose_secret()
    }

    pub fn google_client_secret(&self) -> &str {
        self.google_client_secret.expose_secret()
    }
}
