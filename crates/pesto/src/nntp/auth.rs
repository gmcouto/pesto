//! NNTP authentication and SOCKS5 proxy validation.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use tracing::debug;

use super::{with_hint, Connection};

impl Connection {
    /// Authenticate
    ///
    /// Neither the username nor the password is logged or included in error messages.
    pub async fn authenticate(&mut self, username: &str, password: &str) -> Result<()> {
        debug!(username = "<redacted>", "authenticating");
        let resp = self.command(&format!("AUTHINFO USER {username}")).await?;
        match resp.code {
            281 => {
                debug!("authenticated (no password required)");
                return Ok(());
            }
            381 => {}
            _ => {
                let base = format!("AUTHINFO USER rejected: {} {}", resp.code, resp.text);
                bail!(with_hint(resp.code, &resp.text, base));
            }
        }

        // Password is kept out of log output; only the command prefix is logged.
        debug!("sending AUTHINFO PASS <redacted>");
        let resp = self.send_command("AUTHINFO PASS ", password).await?;
        if resp.code != 281 {
            // resp.text is only pattern-matched inside with_hint/classify_error,
            // never included verbatim in the message — see that fn's doc comment.
            let base = format!(
                "authentication rejected by server (code {}); check the configured username and password",
                resp.code
            );
            bail!(with_hint(resp.code, &resp.text, base));
        }
        debug!("authenticated");
        Ok(())
    }
}

/// Validate the SOCKS5 and NNTP authentication path before posting articles.
pub(crate) async fn validate_proxy(server: &crate::config::ServerEntry) -> Result<()> {
    let Some(proxy) = server.proxy.as_ref() else {
        return Ok(());
    };
    let mut conn = Connection::connect_with_proxy(
        &server.host,
        server.port,
        server.ssl,
        server.timeout,
        Some(proxy),
    )
    .await
    .with_context(|| format!("validating SOCKS5 proxy {}", proxy.address()))?;
    if let Some(username) = &server.username {
        conn.authenticate(username, server.password.as_deref().unwrap_or(""))
            .await
            .context("NNTP authentication through SOCKS5 proxy failed")?;
    }
    conn.quit().await;
    Ok(())
}

/// Build a `reqwest::Proxy` without string-formatting credentials into the URL.
///
/// ASVS V8: credentials are attached via `Proxy::basic_auth` rather than formatted
/// into the URL string, preventing credential leakage in parser errors or logs.
pub(crate) fn build_reqwest_proxy(proxy: &crate::config::Socks5Proxy) -> Result<reqwest::Proxy> {
    let mut proxy_scheme = reqwest::Proxy::all(format!("socks5h://{}", proxy.address()))
        .context("configuring SOCKS5 proxy for exit IP check")?;
    if let (Some(user), Some(password)) = (&proxy.username, &proxy.password) {
        proxy_scheme = proxy_scheme.basic_auth(user, password);
    }
    Ok(proxy_scheme)
}

/// Query the public exit IP through SOCKS5. This optional check contacts api.ipify.org.
///
/// ASVS V8 (Data Protection): credentials are never formatted into the proxy URL —
/// they are attached via `Proxy::basic_auth`, which stores them in the URL's
/// userinfo without ever appearing in a `format!` string that could leak through
/// error messages or logs (`pesto/AGENTS.md`: credentials must never be logged).
pub(crate) async fn proxy_exit_ip(proxy: &crate::config::Socks5Proxy) -> Result<String> {
    let proxy_scheme = build_reqwest_proxy(proxy)?;
    let client = reqwest::Client::builder()
        .proxy(proxy_scheme)
        .timeout(Duration::from_secs(15))
        .build()?;
    Ok(client
        .get("https://api.ipify.org")
        .send()
        .await
        .context("checking SOCKS5 proxy exit IP")?
        .error_for_status()?
        .text()
        .await?
        .trim()
        .to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// C2-02 regression: credentials must never be formatted into the proxy URL
    /// string passed to `reqwest::Proxy::all`. The old implementation built
    /// `socks5h://{user}:{password}@{addr}` inline, so a URL parse failure (e.g.
    /// special characters in the password) echoed the raw credentials inside
    /// the reqwest error message. `build_reqwest_proxy` passes the bare address
    /// to `Proxy::all` and attaches credentials via `basic_auth` afterwards, so
    /// any construction error can only ever reference the address — never the
    /// username or password.
    #[test]
    fn reqwest_proxy_construction_error_never_contains_credentials() {
        // Construct a proxy with an invalid address that fails reqwest URL parsing.
        let mut bad_proxy = crate::config::Socks5Proxy::parse("socks5://127.0.0.1:1080").unwrap();
        bad_proxy.address = "invalid address with spaces and \0 chars".to_string();
        bad_proxy.username = Some("SENTINEL_USER_ABC".to_string());
        bad_proxy.password = Some("SENTINEL_PASS_XYZ_9988".to_string());

        let err = build_reqwest_proxy(&bad_proxy).unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            !msg.contains("SENTINEL_USER_ABC"),
            "username leaked in construction error: {msg}"
        );
        assert!(
            !msg.contains("SENTINEL_PASS_XYZ_9988"),
            "password leaked in construction error: {msg}"
        );

        // Valid proxy builds cleanly with basic_auth
        let good_proxy = crate::config::Socks5Proxy::parse(
            "socks5://SENTINEL_USER_ABC:SENTINEL_PASS_XYZ_9988@127.0.0.1:1080",
        )
        .expect("proxy parses");
        assert!(build_reqwest_proxy(&good_proxy).is_ok());
    }
}
