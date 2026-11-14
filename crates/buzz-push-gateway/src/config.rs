use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::{collections::HashMap, net::SocketAddr, path::PathBuf};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApnsEnvironment {
    Production,
    Sandbox,
}

/// The single server-owned Apple application and APNs connection identity.
#[derive(Debug, Clone)]
pub struct ApplicationConfig {
    pub app_attest_app_id: String,
    /// Read-only mounted Apple App Attest root certificate PEM.
    pub app_attest_root_cert_path: PathBuf,
    /// Exact Apple attestation environment accepted for enrollment.
    pub app_attest_environment: AppAttestEnvironment,
    pub apns_cert_path: PathBuf,
    pub apns_topic: String,
    pub apns_environment: ApnsEnvironment,
}

/// Apple App Attest environment, independent of the APNs transport environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppAttestEnvironment {
    /// Distributed applications, also the default for personal development builds.
    Production,
    /// Development-signed applications in an explicitly opted-in gateway build.
    #[cfg(feature = "personal-dev-app-attest")]
    Development,
}

/// The gateway's Web Push identity and the push services it sends to.
#[derive(Debug, Clone)]
pub struct WebPushConfig {
    /// Read-only mounted P-256 VAPID private key PEM (PKCS#8 or SEC1).
    pub vapid_key_path: PathBuf,
    /// VAPID contact, a `mailto:` or `https:` URL.
    pub vapid_subject: String,
    /// Push service hosts: exact names or `*.suffix` patterns.
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyConfig {
    pub id: String,
    pub key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: SocketAddr,
    pub health_addr: SocketAddr,
    pub max_grant_lifetime_seconds: i64,
    pub max_installation_lifetime_seconds: i64,
    pub endpoint_quota_window_seconds: i64,
    pub endpoint_quota_max_deliveries: i64,
    /// Server-owned application identity and APNs transport, if configured.
    pub application: Option<ApplicationConfig>,
    /// Web Push transport, if configured. At least one transport is.
    pub webpush: Option<WebPushConfig>,
    /// Origins allowed to call the browser routes, as serialized origins
    /// (`https://app.example.org`). Empty: no CORS.
    pub cors_origins: Vec<String>,
    pub database_url: String,
    /// Ordered current key first, followed by decrypt-only predecessors.
    pub grant_keys: Vec<KeyConfig>,
    /// Independent token-custody keyring. These keys MUST NOT be reused for
    /// externally presented delivery capabilities.
    pub token_keys: Vec<KeyConfig>,
}

// Registered NIP-PL v1 App Attest audiences are protocol constants, not routing URLs.
/// Fixed NIP-PL v1 App Attest audience for installation enrollment.
pub const ENROLL_AUDIENCE: &str = "https://push.buzz.xyz/v1/installations";
/// Fixed audience for browser installation enrollment.
pub const WEB_ENROLL_AUDIENCE: &str = "https://push.buzz.xyz/v1/installations/web";
/// Fixed audience for replacing a browser installation's subscription.
pub const WEB_ROTATE_ENDPOINT_AUDIENCE: &str =
    "https://push.buzz.xyz/v1/installations/web/endpoint";
/// Fixed NIP-PL v1 App Attest audience for creating a delegation.
pub const DELEGATE_AUDIENCE: &str = "https://push.buzz.xyz/v1/delegations";
/// Fixed NIP-PL v1 App Attest audience for rotating an installation endpoint.
pub const ROTATE_ENDPOINT_AUDIENCE: &str = "https://push.buzz.xyz/v1/installations/endpoint";
/// Fixed NIP-PL v1 App Attest audience for revoking a delegation.
pub const REVOKE_DELEGATION_AUDIENCE: &str = "https://push.buzz.xyz/v1/delegations/revoke";
/// Fixed NIP-PL v1 App Attest audience for revoking an installation.
pub const REVOKE_INSTALLATION_AUDIENCE: &str = "https://push.buzz.xyz/v1/installations/revoke";

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid environment variable {0}")]
    Invalid(&'static str),
    #[error(
        "no push transport configured: set the APNs variables, the Web Push variables, or both"
    )]
    NoTransport,
}
fn parse_keyring(
    e: &HashMap<String, String>,
    variable: &'static str,
) -> Result<Vec<KeyConfig>, ConfigError> {
    let value = e
        .get(variable)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::Missing(variable))?;
    let keys = value
        .split(',')
        .map(|entry| {
            let (id, encoded) = entry
                .split_once(':')
                .filter(|(id, encoded)| !id.is_empty() && !encoded.is_empty())
                .ok_or(ConfigError::Invalid(variable))?;
            let key = STANDARD
                .decode(encoded)
                .map_err(|_| ConfigError::Invalid(variable))?;
            if key.len() != 32 {
                return Err(ConfigError::Invalid(variable));
            }
            Ok(KeyConfig {
                id: id.to_owned(),
                key,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    if keys.is_empty() {
        return Err(ConfigError::Invalid(variable));
    }
    Ok(keys)
}

/// Every variable of the Apple application. Setting any of them configures
/// APNs, and then the required ones must all be set.
const APPLICATION_VARIABLES: &[&str] = &[
    "BUZZ_PUSH_APP_ATTEST_APP_ID",
    "BUZZ_PUSH_APP_ATTEST_ROOT_CERT_PATH",
    "BUZZ_PUSH_APP_ATTEST_ENVIRONMENT",
    "BUZZ_PUSH_APNS_CERT_PATH",
    "BUZZ_PUSH_APNS_TOPIC",
    "BUZZ_PUSH_APNS_ENVIRONMENT",
];

/// Every Web Push variable, as for [`APPLICATION_VARIABLES`].
const WEBPUSH_VARIABLES: &[&str] = &[
    "BUZZ_PUSH_VAPID_KEY_PATH",
    "BUZZ_PUSH_VAPID_SUBJECT",
    "BUZZ_PUSH_WEBPUSH_ALLOWED_HOSTS",
];

fn parse_cors_origins(e: &HashMap<String, String>) -> Result<Vec<String>, ConfigError> {
    const KEY: &str = "BUZZ_PUSH_CORS_ORIGINS";
    let Some(value) = e.get(KEY) else {
        return Ok(Vec::new());
    };
    value
        .split(',')
        .map(|origin| {
            let origin = origin.trim();
            // Only a bare origin: what a browser sends in `Origin`.
            url::Url::parse(origin)
                .ok()
                .filter(|url| matches!(url.scheme(), "http" | "https"))
                .map(|url| url.origin().ascii_serialization())
                .filter(|serialized| serialized == origin)
                .ok_or(ConfigError::Invalid(KEY))
        })
        .collect()
}

fn parse_webpush(e: &HashMap<String, String>) -> Result<Option<WebPushConfig>, ConfigError> {
    if !WEBPUSH_VARIABLES.iter().any(|key| e.contains_key(*key)) {
        return Ok(None);
    }
    let required = |key: &'static str| {
        e.get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(ConfigError::Missing(key))
    };
    let vapid_key_path = PathBuf::from(required("BUZZ_PUSH_VAPID_KEY_PATH")?);
    let vapid_subject = required("BUZZ_PUSH_VAPID_SUBJECT")?.to_owned();
    let allowed_hosts: Vec<String> = match e.get("BUZZ_PUSH_WEBPUSH_ALLOWED_HOSTS") {
        None => crate::webpush::DEFAULT_PUSH_SERVICE_HOSTS
            .iter()
            .map(|host| (*host).to_owned())
            .collect(),
        Some(value) => value
            .split(',')
            .map(|host| host.trim().to_owned())
            .collect(),
    };
    crate::webpush::PushServiceAllowlist::new(allowed_hosts.iter().map(String::as_str))
        .map_err(|_| ConfigError::Invalid("BUZZ_PUSH_WEBPUSH_ALLOWED_HOSTS"))?;
    Ok(Some(WebPushConfig {
        vapid_key_path,
        vapid_subject,
        allowed_hosts,
    }))
}

fn parse_application(
    e: &HashMap<String, String>,
) -> Result<Option<ApplicationConfig>, ConfigError> {
    if !APPLICATION_VARIABLES.iter().any(|key| e.contains_key(*key)) {
        return Ok(None);
    }
    let app_id_key = "BUZZ_PUSH_APP_ATTEST_APP_ID";
    let cert_key = "BUZZ_PUSH_APNS_CERT_PATH";
    let topic_key = "BUZZ_PUSH_APNS_TOPIC";
    let environment_key = "BUZZ_PUSH_APNS_ENVIRONMENT";
    let required = |key: &'static str| {
        e.get(key)
            .map(String::as_str)
            .filter(|value| !value.is_empty())
            .ok_or(ConfigError::Missing(key))
    };
    let app_attest_app_id = required(app_id_key)?.to_owned();
    let app_attest_root_cert_path = PathBuf::from(required("BUZZ_PUSH_APP_ATTEST_ROOT_CERT_PATH")?);
    let app_attest_environment = match e
        .get("BUZZ_PUSH_APP_ATTEST_ENVIRONMENT")
        .map(String::as_str)
    {
        None | Some("production") => AppAttestEnvironment::Production,
        #[cfg(feature = "personal-dev-app-attest")]
        Some("development") => AppAttestEnvironment::Development,
        Some(_) => return Err(ConfigError::Invalid("BUZZ_PUSH_APP_ATTEST_ENVIRONMENT")),
    };
    let apns_topic = required(topic_key)?.to_owned();
    let apns_cert_path = PathBuf::from(required(cert_key)?);
    let apns_environment = match e.get(environment_key).map(String::as_str) {
        None | Some("production") => ApnsEnvironment::Production,
        Some("sandbox") => ApnsEnvironment::Sandbox,
        Some(_) => return Err(ConfigError::Invalid(environment_key)),
    };
    Ok(Some(ApplicationConfig {
        app_attest_app_id,
        app_attest_root_cert_path,
        app_attest_environment,
        apns_cert_path,
        apns_topic,
        apns_environment,
    }))
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_map(&std::env::vars().collect())
    }
    pub fn from_map(e: &HashMap<String, String>) -> Result<Self, ConfigError> {
        fn req<'a>(
            e: &'a HashMap<String, String>,
            k: &'static str,
        ) -> Result<&'a str, ConfigError> {
            e.get(k)
                .map(String::as_str)
                .filter(|v| !v.is_empty())
                .ok_or(ConfigError::Missing(k))
        }
        let grant_keys = parse_keyring(e, "BUZZ_PUSH_GRANT_KEYS")?;
        let token_keys = parse_keyring(e, "BUZZ_PUSH_TOKEN_KEYS")?;
        if grant_keys.iter().any(|grant| {
            token_keys
                .iter()
                .any(|token| grant.id == token.id || grant.key == token.key)
        }) {
            return Err(ConfigError::Invalid("BUZZ_PUSH_TOKEN_KEYS"));
        }
        let max_grant_lifetime_seconds = req(e, "BUZZ_PUSH_MAX_GRANT_LIFETIME_SECONDS")?
            .parse::<i64>()
            .ok()
            .filter(|seconds| (1..=31_536_000).contains(seconds))
            .ok_or(ConfigError::Invalid("BUZZ_PUSH_MAX_GRANT_LIFETIME_SECONDS"))?;
        let max_installation_lifetime_seconds = e
            .get("BUZZ_PUSH_MAX_INSTALLATION_LIFETIME_SECONDS")
            .map(String::as_str)
            .unwrap_or("7776000")
            .parse::<i64>()
            .ok()
            .filter(|seconds| (1..=31_536_000).contains(seconds))
            .ok_or(ConfigError::Invalid(
                "BUZZ_PUSH_MAX_INSTALLATION_LIFETIME_SECONDS",
            ))?;
        let bounded_positive = |key: &'static str, default: i64, max: i64| {
            e.get(key)
                .map(String::as_str)
                .unwrap_or("")
                .parse::<i64>()
                .ok()
                .or((!e.contains_key(key)).then_some(default))
                .filter(|value| (1..=max).contains(value))
                .ok_or(ConfigError::Invalid(key))
        };
        let endpoint_quota_window_seconds =
            bounded_positive("BUZZ_PUSH_ENDPOINT_QUOTA_WINDOW_SECONDS", 10, 86_400)?;
        let endpoint_quota_max_deliveries =
            bounded_positive("BUZZ_PUSH_ENDPOINT_QUOTA_MAX_DELIVERIES", 10, 10_000)?;
        let application = parse_application(e)?;
        let webpush = parse_webpush(e)?;
        if application.is_none() && webpush.is_none() {
            return Err(ConfigError::NoTransport);
        }
        let cors_origins = parse_cors_origins(e)?;
        let bind_addr = e
            .get("BUZZ_PUSH_BIND_ADDR")
            .map(String::as_str)
            .unwrap_or("0.0.0.0:8080")
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::Invalid("BUZZ_PUSH_BIND_ADDR"))?;
        let health_addr = e
            .get("BUZZ_PUSH_HEALTH_ADDR")
            .map(String::as_str)
            .unwrap_or("0.0.0.0:8081")
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::Invalid("BUZZ_PUSH_HEALTH_ADDR"))?;
        Ok(Self {
            bind_addr,
            health_addr,
            max_grant_lifetime_seconds,
            max_installation_lifetime_seconds,
            endpoint_quota_window_seconds,
            endpoint_quota_max_deliveries,
            application,
            webpush,
            cors_origins,
            database_url: req(e, "DATABASE_URL")?.to_owned(),
            grant_keys,
            token_keys,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn attestation_environment_is_explicit_and_build_gated() {
        let mut env = base();
        assert_eq!(
            Config::from_map(&env)
                .unwrap()
                .application
                .unwrap()
                .app_attest_environment,
            AppAttestEnvironment::Production
        );
        for value in ["", "sandbox", "Production", "unknown"] {
            env.insert("BUZZ_PUSH_APP_ATTEST_ENVIRONMENT".into(), value.into());
            assert!(Config::from_map(&env).is_err());
        }
        env.insert(
            "BUZZ_PUSH_APP_ATTEST_ENVIRONMENT".into(),
            "production".into(),
        );
        assert_eq!(
            Config::from_map(&env)
                .unwrap()
                .application
                .unwrap()
                .app_attest_environment,
            AppAttestEnvironment::Production
        );
        env.insert(
            "BUZZ_PUSH_APP_ATTEST_ENVIRONMENT".into(),
            "development".into(),
        );
        #[cfg(feature = "personal-dev-app-attest")]
        assert_eq!(
            Config::from_map(&env)
                .unwrap()
                .application
                .unwrap()
                .app_attest_environment,
            AppAttestEnvironment::Development
        );
        #[cfg(not(feature = "personal-dev-app-attest"))]
        assert!(Config::from_map(&env).is_err());
    }

    fn base() -> HashMap<String, String> {
        HashMap::from([
            (
                "BUZZ_PUSH_GRANT_KEYS".into(),
                format!(
                    "current:{},old:{}",
                    STANDARD.encode([1; 32]),
                    STANDARD.encode([2; 32])
                ),
            ),
            (
                "BUZZ_PUSH_TOKEN_KEYS".into(),
                format!(
                    "current-token:{},old-token:{}",
                    STANDARD.encode([3; 32]),
                    STANDARD.encode([4; 32])
                ),
            ),
            (
                "BUZZ_PUSH_MAX_GRANT_LIFETIME_SECONDS".into(),
                "2592000".into(),
            ),
            (
                "DATABASE_URL".into(),
                "postgres://buzz:test@localhost/buzz".into(), // sadscan:disable np.postgres.1
            ),
            (
                "BUZZ_PUSH_APP_ATTEST_APP_ID".into(),
                "TEAM.com.example.buzz".into(),
            ),
            (
                "BUZZ_PUSH_APP_ATTEST_ROOT_CERT_PATH".into(),
                "/apple-root.pem".into(),
            ),
            (
                "BUZZ_PUSH_APNS_CERT_PATH".into(),
                "/apns-identity.pem".into(),
            ),
            ("BUZZ_PUSH_APNS_TOPIC".into(), "com.example.buzz".into()),
            ("BUZZ_PUSH_APNS_ENVIRONMENT".into(), "production".into()),
            ("BUZZ_PUSH_BIND_ADDR".into(), "127.0.0.1:8080".into()),
            ("BUZZ_PUSH_HEALTH_ADDR".into(), "127.0.0.1:8081".into()),
        ])
    }

    #[test]
    fn application_requires_server_owned_identity_and_certificate() {
        let config = Config::from_map(&base()).unwrap();
        let application = config.application.unwrap();
        assert_eq!(
            application.apns_cert_path,
            PathBuf::from("/apns-identity.pem")
        );
        assert_eq!(application.apns_topic, "com.example.buzz");
        assert!(config.webpush.is_none());

        for variable in [
            "BUZZ_PUSH_APNS_CERT_PATH",
            "BUZZ_PUSH_APNS_TOPIC",
            "BUZZ_PUSH_APP_ATTEST_APP_ID",
            "BUZZ_PUSH_APP_ATTEST_ROOT_CERT_PATH",
        ] {
            let mut env = base();
            env.remove(variable);
            assert!(
                matches!(Config::from_map(&env), Err(ConfigError::Missing(key)) if key == variable)
            );
        }
    }

    fn without_application(mut env: HashMap<String, String>) -> HashMap<String, String> {
        for key in APPLICATION_VARIABLES {
            env.remove(*key);
        }
        env
    }

    fn with_webpush(mut env: HashMap<String, String>) -> HashMap<String, String> {
        env.insert("BUZZ_PUSH_VAPID_KEY_PATH".into(), "/vapid.pem".into());
        env.insert(
            "BUZZ_PUSH_VAPID_SUBJECT".into(),
            "mailto:push@example.org".into(),
        );
        env
    }

    #[test]
    fn each_transport_is_optional_but_one_is_required() {
        assert!(matches!(
            Config::from_map(&without_application(base())),
            Err(ConfigError::NoTransport)
        ));

        let web_only = Config::from_map(&with_webpush(without_application(base()))).unwrap();
        assert!(web_only.application.is_none());
        let webpush = web_only.webpush.unwrap();
        assert_eq!(webpush.vapid_key_path, PathBuf::from("/vapid.pem"));
        assert_eq!(webpush.vapid_subject, "mailto:push@example.org");
        assert_eq!(
            webpush.allowed_hosts,
            crate::webpush::DEFAULT_PUSH_SERVICE_HOSTS
        );

        let both = Config::from_map(&with_webpush(base())).unwrap();
        assert!(both.application.is_some() && both.webpush.is_some());

        // A partial group is a mistake, not a transport turned off.
        for variable in ["BUZZ_PUSH_VAPID_KEY_PATH", "BUZZ_PUSH_VAPID_SUBJECT"] {
            let mut env = with_webpush(without_application(base()));
            env.remove(variable);
            assert!(
                matches!(Config::from_map(&env), Err(ConfigError::Missing(key)) if key == variable),
                "{variable}"
            );
        }
        let mut env = without_application(base());
        env.insert("BUZZ_PUSH_APNS_ENVIRONMENT".into(), "sandbox".into());
        assert!(matches!(
            Config::from_map(&env),
            Err(ConfigError::Missing("BUZZ_PUSH_APP_ATTEST_APP_ID"))
        ));
    }

    #[test]
    fn webpush_allowlist_is_configurable_and_checked() {
        let mut env = with_webpush(without_application(base()));
        env.insert(
            "BUZZ_PUSH_WEBPUSH_ALLOWED_HOSTS".into(),
            "push.example.org, *.push.example.net".into(),
        );
        assert_eq!(
            Config::from_map(&env)
                .unwrap()
                .webpush
                .unwrap()
                .allowed_hosts,
            vec!["push.example.org", "*.push.example.net"]
        );
        for value in ["", "push.example.org,", "*", "localhost"] {
            env.insert("BUZZ_PUSH_WEBPUSH_ALLOWED_HOSTS".into(), value.into());
            assert!(
                matches!(
                    Config::from_map(&env),
                    Err(ConfigError::Invalid("BUZZ_PUSH_WEBPUSH_ALLOWED_HOSTS"))
                ),
                "{value:?}"
            );
        }
    }

    #[test]
    fn cors_origins_are_bare_origins() {
        assert!(Config::from_map(&base()).unwrap().cors_origins.is_empty());
        let mut env = base();
        env.insert(
            "BUZZ_PUSH_CORS_ORIGINS".into(),
            "https://app.example.org, http://localhost:5173".into(),
        );
        assert_eq!(
            Config::from_map(&env).unwrap().cors_origins,
            vec!["https://app.example.org", "http://localhost:5173"]
        );
        for value in [
            "",
            "*",
            "app.example.org",
            "https://app.example.org/",
            "https://app.example.org/path",
            "https://user@app.example.org",
            "ftp://app.example.org",
            "https://app.example.org,",
        ] {
            env.insert("BUZZ_PUSH_CORS_ORIGINS".into(), value.into());
            assert!(
                matches!(
                    Config::from_map(&env),
                    Err(ConfigError::Invalid("BUZZ_PUSH_CORS_ORIGINS"))
                ),
                "{value:?}"
            );
        }
    }

    #[test]
    fn startup_needs_no_origin_and_transcript_audiences_stay_registered() {
        assert!(!base().contains_key("BUZZ_PUSH_GATEWAY_ORIGIN"));
        Config::from_map(&base()).unwrap();
        assert_eq!(ENROLL_AUDIENCE, "https://push.buzz.xyz/v1/installations");
        assert_eq!(DELEGATE_AUDIENCE, "https://push.buzz.xyz/v1/delegations");
        assert_eq!(
            ROTATE_ENDPOINT_AUDIENCE,
            "https://push.buzz.xyz/v1/installations/endpoint"
        );
        assert_eq!(
            REVOKE_DELEGATION_AUDIENCE,
            "https://push.buzz.xyz/v1/delegations/revoke"
        );
        assert_eq!(
            REVOKE_INSTALLATION_AUDIENCE,
            "https://push.buzz.xyz/v1/installations/revoke"
        );
    }

    #[test]
    fn keyrings_preserve_current_then_predecessor_order_and_are_independent() {
        let config = Config::from_map(&base()).unwrap();
        assert_eq!(config.grant_keys[0].id, "current");
        assert_eq!(config.grant_keys[1].id, "old");
        assert_eq!(config.token_keys[0].id, "current-token");
        assert_eq!(config.token_keys[1].id, "old-token");
        assert_ne!(config.grant_keys[0].key, config.token_keys[0].key);
    }

    #[test]
    fn malformed_security_configuration_fails_startup() {
        for (key, value) in [
            ("BUZZ_PUSH_APP_ATTEST_APP_ID", ""),
            ("BUZZ_PUSH_APNS_ENVIRONMENT", "staging"),
            ("BUZZ_PUSH_MAX_GRANT_LIFETIME_SECONDS", "0"),
            ("BUZZ_PUSH_MAX_GRANT_LIFETIME_SECONDS", "31536001"),
            ("BUZZ_PUSH_MAX_GRANT_LIFETIME_SECONDS", "2.592e+06"),
            ("BUZZ_PUSH_MAX_GRANT_LIFETIME_SECONDS", "2592000.5"),
            ("BUZZ_PUSH_MAX_INSTALLATION_LIFETIME_SECONDS", "0"),
        ] {
            let mut env = base();
            env.insert(key.into(), value.into());
            assert!(Config::from_map(&env).is_err(), "accepted {key}={value}");
        }
    }

    // The chart test supplies actual Helm-rendered environment values. Keep this
    // separate from ordinary unit tests, which do not require Helm or fixtures.
    #[test]
    #[ignore = "run deploy/charts/buzz-push-gateway/tests/grant-lifetime.sh"]
    fn helm_rendered_grant_lifetimes() {
        let path = std::env::var("BUZZ_TEST_HELM_ENV_FILE").unwrap();
        let cases: Vec<(String, i64, HashMap<String, String>)> =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert_eq!(cases.len(), 9);
        for (label, expected, rendered) in cases {
            let mut env = base();
            env.extend(rendered);
            let config = Config::from_map(&env).unwrap_or_else(|error| panic!("{label}: {error}"));
            assert_eq!(config.max_grant_lifetime_seconds, expected, "{label}");
            assert_eq!(
                env["BUZZ_PUSH_MAX_GRANT_LIFETIME_SECONDS"],
                expected.to_string(),
                "{label} must render decimal integer text"
            );
        }
    }

    #[test]
    fn cross_keyring_id_or_material_reuse_fails_startup() {
        for token_keys in [
            format!("current:{}", STANDARD.encode([9; 32])),
            format!("other:{}", STANDARD.encode([1; 32])),
        ] {
            let mut env = base();
            env.insert("BUZZ_PUSH_TOKEN_KEYS".into(), token_keys);
            assert!(Config::from_map(&env).is_err());
        }
    }

    #[test]
    fn listener_defaults_remain_public_when_addresses_are_absent() {
        let mut env = base();
        env.remove("BUZZ_PUSH_BIND_ADDR");
        env.remove("BUZZ_PUSH_HEALTH_ADDR");

        let config = Config::from_map(&env).unwrap();
        assert_eq!(config.bind_addr, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(config.health_addr, "0.0.0.0:8081".parse().unwrap());
    }

    #[test]
    fn malformed_or_empty_keyrings_fail_startup() {
        for (variable, value) in [
            ("BUZZ_PUSH_GRANT_KEYS", ""),
            ("BUZZ_PUSH_GRANT_KEYS", "missing_separator"),
            ("BUZZ_PUSH_GRANT_KEYS", "id:bad-base64"),
            ("BUZZ_PUSH_TOKEN_KEYS", ""),
            ("BUZZ_PUSH_TOKEN_KEYS", "missing_separator"),
            ("BUZZ_PUSH_TOKEN_KEYS", "id:bad-base64"),
        ] {
            let mut env = base();
            env.insert(variable.into(), value.into());
            assert!(Config::from_map(&env).is_err());
        }
    }
}
