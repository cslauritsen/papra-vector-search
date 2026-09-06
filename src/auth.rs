use std::collections::HashSet;

use anyhow::{Result, anyhow};
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header, jwk::JwkSet};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::Config;

#[derive(Clone)]
pub struct Authenticator {
    client: Client,
    issuer: String,
    audience: String,
    client_secret: SecretString,
    redirect_uri: String,
    allowed_emails: HashSet<String>,
}

#[derive(Debug, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub aud: String,
    pub exp: usize,
    pub email: Option<String>,
    pub hd: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    pub id_token: Option<String>,
    pub token_type: String,
}

impl Authenticator {
    pub fn new(config: &Config) -> Self {
        Self {
            client: Client::new(),
            issuer: config.google_issuer.clone(),
            audience: config.google_client_id().to_string(),
            client_secret: config.google_client_secret.clone(),
            redirect_uri: config.google_redirect_uri.clone(),
            allowed_emails: config.google_allowed_emails.clone(),
        }
    }

    pub fn authorization_url(&self, state: &str) -> Result<String> {
        let mut url = Url::parse("https://accounts.google.com/o/oauth2/v2/auth")?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.audience)
            .append_pair("redirect_uri", &self.redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email profile")
            .append_pair("state", state)
            .append_pair("access_type", "online");
        Ok(url.into())
    }

    pub async fn exchange_code(&self, code: &str) -> Result<OAuthTokenResponse> {
        self.client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("code", code),
                ("client_id", self.audience.as_str()),
                ("client_secret", self.client_secret.expose_secret()),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json()
            .await
            .map_err(Into::into)
    }

    pub async fn authenticate(&self, authorization: Option<&str>) -> Result<Claims> {
        let value = authorization.ok_or_else(|| anyhow!("missing authorization"))?;
        let token = value
            .strip_prefix("Bearer ")
            .ok_or_else(|| anyhow!("invalid authorization scheme"))?;
        let header = decode_header(token)?;
        if header.alg != Algorithm::RS256 {
            return Err(anyhow!("unsupported token algorithm"));
        }
        let endpoint = if self.issuer == "https://accounts.google.com" {
            "https://www.googleapis.com/oauth2/v3/certs".to_string()
        } else {
            format!(
                "{}/.well-known/jwks.json",
                self.issuer.trim_end_matches('/')
            )
        };
        let keys: JwkSet = self
            .client
            .get(endpoint)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let kid = header.kid.ok_or_else(|| anyhow!("token key id missing"))?;
        let jwk = keys
            .find(&kid)
            .ok_or_else(|| anyhow!("token key not found"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(std::slice::from_ref(&self.issuer));
        validation.set_audience(std::slice::from_ref(&self.audience));
        let claims = decode::<Claims>(token, &DecodingKey::from_jwk(jwk)?, &validation)?.claims;
        let email = claims
            .email
            .as_deref()
            .ok_or_else(|| anyhow!("token email missing"))?;
        let normalized_email = email.to_ascii_lowercase();
        if !self.allowed_emails.contains(&normalized_email) {
            return Err(anyhow!("email address is not authorized"));
        }
        Ok(claims)
    }
}
