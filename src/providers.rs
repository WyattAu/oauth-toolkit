//! Mail provider presets for desktop IMAP/SMTP XOAUTH2 flows, plus the
//! canonical endpoint URL constants shared by all provider modules.
//!
//! Every preset exposes the authorization URL, token URL, and the
//! IMAP/SMTP XOAUTH2 scope sets required to read and send mail.

use serde::{Deserialize, Serialize};

/// Canonical provider endpoint URLs — the single source of truth.
///
/// Other modules (`social`, mail presets) must reference these constants
/// instead of repeating literal URLs.
pub mod endpoints {
    /// GitHub authorization endpoint.
    pub const GITHUB_AUTHORIZE_URL: &str = "https://github.com/login/oauth/authorize";
    /// GitHub token endpoint.
    pub const GITHUB_TOKEN_URL: &str = "https://github.com/login/oauth/access_token";
    /// GitHub user info endpoint.
    pub const GITHUB_USER_INFO_URL: &str = "https://api.github.com/user";

    /// Google authorization endpoint.
    pub const GOOGLE_AUTHORIZE_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
    /// Google token endpoint.
    pub const GOOGLE_TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
    /// Google user info endpoint.
    pub const GOOGLE_USER_INFO_URL: &str = "https://www.googleapis.com/oauth2/v2/userinfo";

    /// Yahoo authorization endpoint.
    pub const YAHOO_AUTHORIZE_URL: &str = "https://api.login.yahoo.com/oauth2/request_auth";
    /// Yahoo token endpoint.
    pub const YAHOO_TOKEN_URL: &str = "https://api.login.yahoo.com/oauth2/get_token";

    /// AOL authorization endpoint (AOL shares Yahoo's OAuth2 stack).
    pub const AOL_AUTHORIZE_URL: &str = "https://api.login.aol.com/oauth2/request_auth";
    /// AOL token endpoint.
    pub const AOL_TOKEN_URL: &str = "https://api.login.aol.com/oauth2/get_token";

    /// Fastmail authorization endpoint.
    pub const FASTMAIL_AUTHORIZE_URL: &str = "https://app.fastmail.com/oauth/authorize";
    /// Fastmail token endpoint.
    pub const FASTMAIL_TOKEN_URL: &str = "https://api.fastmail.com/oauth/token";
}

/// Mail provider endpoints and XOAUTH2 scope sets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MailProvider {
    /// Authorization endpoint.
    pub auth_url: String,
    /// Token endpoint.
    pub token_url: String,
    /// `OAuth2` client id (the desktop app's registered client).
    pub client_id: String,
    /// Scopes required for IMAP XOAUTH2.
    pub imap_scopes: Vec<String>,
    /// Scopes required for SMTP XOAUTH2.
    pub smtp_scopes: Vec<String>,
    /// Extra scopes included in the authorization request
    /// (`openid`, `offline_access`, ...).
    pub extra_scopes: Vec<String>,
}

impl MailProvider {
    /// Gmail preset. The single `https://mail.google.com/` scope covers
    /// both IMAP and SMTP XOAUTH2.
    pub fn gmail(client_id: &str) -> Self {
        Self {
            auth_url: endpoints::GOOGLE_AUTHORIZE_URL.to_owned(),
            token_url: endpoints::GOOGLE_TOKEN_URL.to_owned(),
            client_id: client_id.to_owned(),
            imap_scopes: vec!["https://mail.google.com/".into()],
            smtp_scopes: vec!["https://mail.google.com/".into()],
            extra_scopes: vec!["openid".into(), "email".into()],
        }
    }

    /// Microsoft 365 / Outlook preset. `tenant` is the directory tenant
    /// path segment (e.g. `common`, `consumers`, or a tenant id).
    pub fn outlook(client_id: &str, tenant: &str) -> Self {
        Self {
            auth_url: format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"),
            token_url: format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"),
            client_id: client_id.to_owned(),
            imap_scopes: vec!["https://outlook.office.com/IMAP.AccessAsUser.All".into()],
            smtp_scopes: vec!["https://outlook.office.com/SMTP.Send".into()],
            extra_scopes: vec!["offline_access".into()],
        }
    }

    /// Yahoo Mail preset.
    pub fn yahoo(client_id: &str) -> Self {
        Self {
            auth_url: endpoints::YAHOO_AUTHORIZE_URL.to_owned(),
            token_url: endpoints::YAHOO_TOKEN_URL.to_owned(),
            client_id: client_id.to_owned(),
            imap_scopes: vec!["mail-w".into()],
            smtp_scopes: vec!["mail-w".into()],
            extra_scopes: vec![],
        }
    }

    /// AOL Mail preset (AOL shares Yahoo's OAuth2 stack).
    pub fn aol(client_id: &str) -> Self {
        Self {
            auth_url: endpoints::AOL_AUTHORIZE_URL.to_owned(),
            token_url: endpoints::AOL_TOKEN_URL.to_owned(),
            client_id: client_id.to_owned(),
            imap_scopes: vec!["mail-w".into()],
            smtp_scopes: vec!["mail-w".into()],
            extra_scopes: vec![],
        }
    }

    /// Fastmail preset with dedicated IMAP and SMTP protocol scopes.
    pub fn fastmail(client_id: &str) -> Self {
        Self {
            auth_url: endpoints::FASTMAIL_AUTHORIZE_URL.to_owned(),
            token_url: endpoints::FASTMAIL_TOKEN_URL.to_owned(),
            client_id: client_id.to_owned(),
            imap_scopes: vec!["https://www.fastmail.com/dev/protocolIMAP".into()],
            smtp_scopes: vec!["https://www.fastmail.com/dev/protocolSMTP".into()],
            extra_scopes: vec![],
        }
    }

    /// The scope list to send in the authorization request: the union of
    /// IMAP, SMTP, and extra scopes, de-duplicated preserving order.
    pub fn authorization_scopes(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for scope in self
            .imap_scopes
            .iter()
            .chain(self.smtp_scopes.iter())
            .chain(self.extra_scopes.iter())
        {
            if !out.contains(scope) {
                out.push(scope.clone());
            }
        }
        out
    }
}

#[cfg(test)]
// Test code: unwrap/expect are the idiomatic way to assert setup success.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn gmail_preset_shape() {
        let g = MailProvider::gmail("g");
        assert_eq!(g.auth_url, endpoints::GOOGLE_AUTHORIZE_URL);
        assert!(g.token_url.contains("googleapis"));
        let scopes = g.authorization_scopes();
        assert!(scopes.contains(&"https://mail.google.com/".to_string()));
        assert!(scopes.contains(&"openid".to_string()));
        // dedup: mail.google.com appears in both imap and smtp sets
        assert_eq!(
            scopes
                .iter()
                .filter(|s| *s == "https://mail.google.com/")
                .count(),
            1
        );
    }

    #[test]
    fn fastmail_preset_split_scopes() {
        let f = MailProvider::fastmail("f");
        assert!(f.token_url.contains("fastmail"));
        assert_eq!(
            f.imap_scopes,
            vec!["https://www.fastmail.com/dev/protocolIMAP"]
        );
        assert_eq!(
            f.smtp_scopes,
            vec!["https://www.fastmail.com/dev/protocolSMTP"]
        );
        let scopes = f.authorization_scopes();
        assert_eq!(scopes.len(), 2);
        assert!(scopes.contains(&"https://www.fastmail.com/dev/protocolIMAP".to_string()));
        assert!(scopes.contains(&"https://www.fastmail.com/dev/protocolSMTP".to_string()));
    }

    #[test]
    fn gmail_vs_fastmail_scope_shapes_differ() {
        // Gmail: one umbrella scope; Fastmail: two protocol scopes.
        let g = MailProvider::gmail("g");
        let f = MailProvider::fastmail("f");
        assert!(g.imap_scopes == g.smtp_scopes);
        assert_ne!(f.imap_scopes, f.smtp_scopes);
    }

    #[test]
    fn outlook_preset_tenant_aware() {
        let o = MailProvider::outlook("o", "common");
        assert!(o.auth_url.contains("login.microsoftonline.com/common"));
        assert!(o.token_url.contains("login.microsoftonline.com/common"));
        assert!(o.authorization_scopes().iter().any(|s| s.contains("IMAP")));
        assert!(
            o.authorization_scopes()
                .iter()
                .any(|s| s.contains("SMTP.Send"))
        );
        assert!(o.extra_scopes.contains(&"offline_access".to_string()));

        let t = MailProvider::outlook("o", "9188040d-6c67-4c5b-b112-36a304b66dad");
        assert!(t.auth_url.contains("9188040d"));
    }

    #[test]
    fn yahoo_and_aol_presets() {
        let y = MailProvider::yahoo("y");
        assert!(y.auth_url.contains("login.yahoo.com"));
        assert!(y.token_url.contains("login.yahoo.com"));
        assert!(y.authorization_scopes().contains(&"mail-w".to_string()));

        let a = MailProvider::aol("a");
        assert!(a.auth_url.contains("login.aol.com"));
        assert!(a.token_url.contains("login.aol.com"));
        assert!(a.authorization_scopes().contains(&"mail-w".to_string()));
    }

    #[test]
    fn gmail_shares_google_urls_with_social_module() {
        // Dedupe regression: the mail preset and social login must agree
        // on Google's endpoints.
        assert_eq!(
            MailProvider::gmail("x").auth_url,
            crate::social::SocialProvider::Google.authorize_url()
        );
        assert_eq!(
            MailProvider::gmail("x").token_url,
            crate::social::SocialProvider::Google.token_url()
        );
    }

    #[test]
    fn authorization_scopes_order_preserved() {
        let p = MailProvider {
            auth_url: "https://x".into(),
            token_url: "https://x".into(),
            client_id: "c".into(),
            imap_scopes: vec!["a".into(), "b".into()],
            smtp_scopes: vec!["b".into(), "c".into()],
            extra_scopes: vec!["d".into(), "a".into()],
        };
        assert_eq!(p.authorization_scopes(), vec!["a", "b", "c", "d"]);
    }
}
