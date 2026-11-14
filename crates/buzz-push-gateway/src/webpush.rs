//! Web Push last hop: RFC 8030 delivery, RFC 8291 payload encryption and
//! RFC 8292 VAPID identification.
//!
//! Like the APNs transport, this one sends a single compiled-in payload
//! ([`WEBPUSH_WAKE_PAYLOAD`]). Nothing the relay sends can reach it; the
//! browser wakes its service worker, which fetches from its relay.

use std::{sync::Arc, time::Duration};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Nonce,
};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hkdf::Hkdf;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    pkcs8::DecodePrivateKey,
    PublicKey, SecretKey,
};
use reqwest::header::{AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use url::Url;

use crate::{
    apns::{DeliveryAttempt, DeliveryOutcome, PushTransport},
    model::WEBPUSH_WAKE_PAYLOAD,
};

/// Push services accepted when the operator configures none.
pub const DEFAULT_PUSH_SERVICE_HOSTS: &[&str] = &[
    "fcm.googleapis.com",
    "updates.push.services.mozilla.com",
    "web.push.apple.com",
    "*.notify.windows.com",
];

/// Longest subscription endpoint URL accepted, in bytes.
pub const MAX_SUBSCRIPTION_ENDPOINT_BYTES: usize = 2048;

/// RFC 8188 record size advertised in the content-coding header. The single
/// record (payload, delimiter and tag) is far smaller.
const RECORD_SIZE: u32 = 4096;

/// VAPID JWT lifetime. RFC 8292 allows at most 24 hours.
const VAPID_LIFETIME_SECONDS: i64 = 12 * 60 * 60;

/// Longest TTL sent to a push service: four weeks, which every major
/// service accepts.
const MAX_TTL_SECONDS: i64 = 28 * 24 * 60 * 60;

/// RFC 8030 topic: wakes waiting at the push service replace one another,
/// so a phone that was offline gets one wake, not one per message.
const WAKE_TOPIC: &str = "buzz-wake";

/// Web Push input or configuration failure. It carries no key material.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum WebPushError {
    /// The subscription is malformed or its push service isn't allowed.
    #[error("invalid web push subscription")]
    Subscription,
    /// The VAPID key or subject can't be used.
    #[error("invalid VAPID configuration")]
    Vapid,
    /// An allowlist entry is malformed.
    #[error("invalid push service allowlist")]
    Allowlist,
    /// Randomness or encryption failed.
    #[error("web push encryption failed")]
    Encryption,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostPattern {
    Exact(String),
    /// `*.suffix`: any subdomain of `suffix`, not `suffix` itself.
    Subdomain(String),
}

/// The push services a subscription may point at. Endpoints must be `https`
/// on an allowed host, so the gateway can't be steered at arbitrary URLs.
#[derive(Debug, Clone)]
pub struct PushServiceAllowlist {
    patterns: Vec<HostPattern>,
    #[cfg(test)]
    allow_loopback_http: bool,
}

impl PushServiceAllowlist {
    /// Build an allowlist of exact hosts and `*.suffix` patterns.
    pub fn new<'a>(entries: impl IntoIterator<Item = &'a str>) -> Result<Self, WebPushError> {
        let patterns = entries
            .into_iter()
            .map(|entry| {
                let entry = entry.trim().to_ascii_lowercase();
                let (wildcard, host) = match entry.strip_prefix("*.") {
                    Some(host) => (true, host.to_owned()),
                    None => (false, entry),
                };
                let valid = !host.is_empty()
                    && host.len() <= 253
                    && host.contains('.')
                    && host.split('.').all(|label| {
                        !label.is_empty()
                            && label.len() <= 63
                            && label
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                    });
                if !valid {
                    return Err(WebPushError::Allowlist);
                }
                Ok(if wildcard {
                    HostPattern::Subdomain(host)
                } else {
                    HostPattern::Exact(host)
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if patterns.is_empty() {
            return Err(WebPushError::Allowlist);
        }
        Ok(Self {
            patterns,
            #[cfg(test)]
            allow_loopback_http: false,
        })
    }

    /// Whether `url` is an endpoint this gateway may send to.
    pub fn allows(&self, url: &Url) -> bool {
        #[cfg(test)]
        if self.allow_loopback_http && is_loopback_http(url) {
            return true;
        }
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.port().is_some_and(|port| port != 443)
        {
            return false;
        }
        let Some(url::Host::Domain(host)) = url.host() else {
            return false;
        };
        let host = host.to_ascii_lowercase();
        self.patterns.iter().any(|pattern| match pattern {
            HostPattern::Exact(exact) => host == *exact,
            HostPattern::Subdomain(suffix) => host
                .strip_suffix(suffix.as_str())
                .is_some_and(|prefix| prefix.len() > 1 && prefix.ends_with('.')),
        })
    }

    #[cfg(test)]
    pub(crate) fn allowing_loopback_http(mut self) -> Self {
        self.allow_loopback_http = true;
        self
    }
}

#[cfg(test)]
fn is_loopback_http(url: &Url) -> bool {
    url.scheme() == "http" && matches!(url.host(), Some(url::Host::Ipv4(ip)) if ip.is_loopback())
}

/// A browser's push subscription (`PushSubscription.toJSON()`): where to
/// send, and the keys to encrypt to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    endpoint: Url,
    p256dh: PublicKey,
    auth: [u8; 16],
}

/// Custody form of a subscription, sealed with the token keyring.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredSubscription {
    endpoint: String,
    p256dh: String,
    auth: String,
}

impl Subscription {
    /// Validate a subscription as the browser reports it: the endpoint URL,
    /// and the base64url `p256dh` and `auth` keys.
    pub fn new(
        endpoint: &str,
        p256dh: &str,
        auth: &str,
        allowlist: &PushServiceAllowlist,
    ) -> Result<Self, WebPushError> {
        if endpoint.len() > MAX_SUBSCRIPTION_ENDPOINT_BYTES {
            return Err(WebPushError::Subscription);
        }
        let endpoint = Url::parse(endpoint).map_err(|_| WebPushError::Subscription)?;
        if !allowlist.allows(&endpoint) {
            return Err(WebPushError::Subscription);
        }
        let p256dh = URL_SAFE_NO_PAD
            .decode(p256dh.trim_end_matches('='))
            .ok()
            // Uncompressed points only: that is what RFC 8291 carries.
            .filter(|bytes| bytes.len() == 65 && bytes[0] == 0x04)
            .and_then(|bytes| PublicKey::from_sec1_bytes(&bytes).ok())
            .ok_or(WebPushError::Subscription)?;
        let auth = URL_SAFE_NO_PAD
            .decode(auth.trim_end_matches('='))
            .ok()
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .ok_or(WebPushError::Subscription)?;
        Ok(Self {
            endpoint,
            p256dh,
            auth,
        })
    }

    /// The push service URL.
    pub fn endpoint(&self) -> &Url {
        &self.endpoint
    }

    /// Bytes to seal for custody; [`Subscription::from_bytes`] reverses it.
    pub fn to_bytes(&self) -> Result<Vec<u8>, WebPushError> {
        let stored = StoredSubscription {
            endpoint: self.endpoint.as_str().to_owned(),
            p256dh: URL_SAFE_NO_PAD.encode(self.p256dh.to_sec1_bytes()),
            auth: URL_SAFE_NO_PAD.encode(self.auth),
        };
        serde_json::to_vec(&stored).map_err(|_| WebPushError::Subscription)
    }

    /// Read custody bytes, checking them against the current allowlist.
    pub fn from_bytes(
        bytes: &[u8],
        allowlist: &PushServiceAllowlist,
    ) -> Result<Self, WebPushError> {
        let stored: StoredSubscription =
            crate::strict_json::from_slice(bytes).map_err(|_| WebPushError::Subscription)?;
        Self::new(&stored.endpoint, &stored.p256dh, &stored.auth, allowlist)
    }
}

fn hkdf_expand<const N: usize>(
    salt: &[u8],
    ikm: &[u8],
    info: &[&[u8]],
) -> Result<[u8; N], WebPushError> {
    let mut okm = [0u8; N];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand_multi_info(info, &mut okm)
        .map_err(|_| WebPushError::Encryption)?;
    Ok(okm)
}

/// RFC 8291 `aes128gcm` encryption of `payload` to `subscription`, with the
/// sender's ephemeral key and salt given so tests can use the RFC's vector.
fn encrypt_with(
    payload: &[u8],
    subscription: &Subscription,
    sender: &SecretKey,
    salt: [u8; 16],
) -> Result<Vec<u8>, WebPushError> {
    let ua_public = subscription.p256dh.to_sec1_bytes();
    let as_public = sender.public_key().to_sec1_bytes();
    if ua_public.len() != 65 || as_public.len() != 65 {
        return Err(WebPushError::Encryption);
    }
    let shared =
        p256::ecdh::diffie_hellman(sender.to_nonzero_scalar(), subscription.p256dh.as_affine());
    // RFC 8291 §3.4: the input keying material binds both public keys and
    // the subscription's authentication secret.
    let ikm: [u8; 32] = hkdf_expand(
        &subscription.auth,
        shared.raw_secret_bytes().as_slice(),
        &[b"WebPush: info\0", &ua_public, &as_public],
    )?;
    // RFC 8188 §2.2–2.3.
    let cek: [u8; 16] = hkdf_expand(&salt, &ikm, &[b"Content-Encoding: aes128gcm\0"])?;
    let nonce: [u8; 12] = hkdf_expand(&salt, &ikm, &[b"Content-Encoding: nonce\0"])?;
    let mut record = Vec::with_capacity(payload.len() + 1);
    record.extend_from_slice(payload);
    // The last (and only) record ends with delimiter 0x02 and no padding.
    record.push(0x02);
    if record.len() + 16 > RECORD_SIZE as usize {
        return Err(WebPushError::Encryption);
    }
    let ciphertext = Aes128Gcm::new_from_slice(&cek)
        .map_err(|_| WebPushError::Encryption)?
        .encrypt(Nonce::from_slice(&nonce), record.as_slice())
        .map_err(|_| WebPushError::Encryption)?;
    let mut body = Vec::with_capacity(16 + 4 + 1 + as_public.len() + ciphertext.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(as_public.len() as u8);
    body.extend_from_slice(&as_public);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

/// RFC 8291 encryption with a fresh ephemeral key and salt.
fn encrypt(payload: &[u8], subscription: &Subscription) -> Result<Vec<u8>, WebPushError> {
    let sender = loop {
        let mut scalar = [0u8; 32];
        getrandom::fill(&mut scalar).map_err(|_| WebPushError::Encryption)?;
        // Out-of-range scalars (probability ~2^-32) are drawn again.
        if let Ok(key) = SecretKey::from_slice(&scalar) {
            break key;
        }
    };
    let mut salt = [0u8; 16];
    getrandom::fill(&mut salt).map_err(|_| WebPushError::Encryption)?;
    encrypt_with(payload, subscription, &sender, salt)
}

/// The gateway's VAPID identity (RFC 8292).
pub struct VapidKey {
    signing: SigningKey,
    public_key: String,
    subject: String,
}

impl std::fmt::Debug for VapidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VapidKey")
            .field("public_key", &self.public_key)
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

impl VapidKey {
    /// Load a P-256 private key from PEM (PKCS#8 `PRIVATE KEY` or SEC1
    /// `EC PRIVATE KEY`). `subject` is the contact push services may use:
    /// a `mailto:` or `https:` URL.
    pub fn from_pem(pem: &str, subject: &str) -> Result<Self, WebPushError> {
        let secret = SecretKey::from_pkcs8_pem(pem)
            .or_else(|_| SecretKey::from_sec1_pem(pem))
            .map_err(|_| WebPushError::Vapid)?;
        Self::from_secret(&secret, subject)
    }

    fn from_secret(secret: &SecretKey, subject: &str) -> Result<Self, WebPushError> {
        let subject_ok = Url::parse(subject).is_ok_and(|url| match url.scheme() {
            "mailto" => !url.path().is_empty(),
            "https" => url.host().is_some(),
            _ => false,
        });
        if !subject_ok {
            return Err(WebPushError::Vapid);
        }
        Ok(Self {
            signing: SigningKey::from(secret),
            public_key: URL_SAFE_NO_PAD.encode(secret.public_key().to_sec1_bytes()),
            subject: subject.to_owned(),
        })
    }

    /// The public key, base64url: the browser's `applicationServerKey`.
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// `Authorization` header value for a request to `endpoint`.
    fn authorization(&self, endpoint: &Url, now: i64) -> String {
        let header = URL_SAFE_NO_PAD.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = URL_SAFE_NO_PAD.encode(
            serde_json::json!({
                "aud": endpoint.origin().ascii_serialization(),
                "exp": now.saturating_add(VAPID_LIFETIME_SECONDS),
                "sub": self.subject,
            })
            .to_string(),
        );
        let signing_input = format!("{header}.{claims}");
        let signature: Signature = self.signing.sign(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
        format!("vapid t={signing_input}.{signature}, k={}", self.public_key)
    }
}

/// Classify a push service's response status (RFC 8030 §5–8).
pub fn classify(code: u16) -> DeliveryOutcome {
    match code {
        200..=202 => DeliveryOutcome::Accepted,
        // The subscription is gone for good.
        404 | 410 => DeliveryOutcome::InvalidEndpoint {
            unregistered_at: None,
        },
        // A VAPID problem is the gateway's, never the endpoint's: don't let it
        // invalidate subscriptions.
        401 | 403 => DeliveryOutcome::ConfigurationFault,
        429 | 500..=599 => DeliveryOutcome::Retry {
            retry_after_seconds: None,
        },
        _ => DeliveryOutcome::PermanentRequestFault,
    }
}

/// Web Push transport. `endpoint` bytes are a [`Subscription`]'s custody
/// form.
pub struct WebPushTransport {
    client: reqwest::Client,
    vapid: Arc<VapidKey>,
    allowlist: Arc<PushServiceAllowlist>,
    now: fn() -> i64,
}

impl WebPushTransport {
    /// Build a transport that signs with `vapid` and sends only to services
    /// on `allowlist`.
    pub fn new(
        vapid: Arc<VapidKey>,
        allowlist: Arc<PushServiceAllowlist>,
        now: fn() -> i64,
    ) -> Result<Self, WebPushError> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            // A push service answers; it never sends us elsewhere.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| WebPushError::Vapid)?;
        Ok(Self {
            client,
            vapid,
            allowlist,
            now,
        })
    }
}

#[async_trait]
impl PushTransport for WebPushTransport {
    async fn send(&self, attempt: DeliveryAttempt, endpoint: &[u8]) -> DeliveryOutcome {
        crate::metrics::record_webpush_send_attempt();
        let Ok(subscription) = Subscription::from_bytes(endpoint, &self.allowlist) else {
            return DeliveryOutcome::PermanentRequestFault;
        };
        let now = (self.now)();
        let ttl = attempt
            .expires_at
            .saturating_sub(now)
            .clamp(0, MAX_TTL_SECONDS);
        let Ok(body) = encrypt(WEBPUSH_WAKE_PAYLOAD, &subscription) else {
            return DeliveryOutcome::Retry {
                retry_after_seconds: None,
            };
        };
        let response = self
            .client
            .post(subscription.endpoint().clone())
            .header(
                AUTHORIZATION,
                self.vapid.authorization(subscription.endpoint(), now),
            )
            .header(CONTENT_ENCODING, "aes128gcm")
            .header(CONTENT_TYPE, "application/octet-stream")
            .header("TTL", ttl.to_string())
            .header("Urgency", "high")
            .header("Topic", WAKE_TOPIC)
            .body(body)
            .send()
            .await;
        let Ok(response) = response else {
            return DeliveryOutcome::Retry {
                retry_after_seconds: None,
            };
        };
        match classify(response.status().as_u16()) {
            DeliveryOutcome::Retry { .. } => DeliveryOutcome::Retry {
                retry_after_seconds: response
                    .headers()
                    .get("retry-after")
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<i64>().ok())
                    .map(|seconds| seconds.clamp(1, 3600)),
            },
            outcome => outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Bytes, extract::State, http::HeaderMap, routing::post, Router};
    use std::sync::Mutex;

    fn b64(value: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(value).unwrap()
    }

    // RFC 8291 Appendix A.
    const UA_PUBLIC: &str =
        "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
    const UA_PRIVATE: &str = "q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94";
    const AS_PRIVATE: &str = "yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw";
    const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";
    const SALT: &str = "DGv6ra1nlYgDCS1FRnbzlw";
    const PLAINTEXT: &[u8] = b"When I grow up, I want to be a watermelon";
    const BODY: &str = "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN";

    fn default_services() -> PushServiceAllowlist {
        PushServiceAllowlist::new(DEFAULT_PUSH_SERVICE_HOSTS.iter().copied()).unwrap()
    }

    fn loopback() -> PushServiceAllowlist {
        default_services().allowing_loopback_http()
    }

    fn rfc_subscription(endpoint: &str) -> Subscription {
        let list = PushServiceAllowlist::new(["push.example.net", "fcm.googleapis.com"]).unwrap();
        Subscription::new(endpoint, UA_PUBLIC, AUTH, &list).unwrap()
    }

    /// Decrypt as the browser does, with the user agent's private key.
    fn decrypt(body: &[u8], ua_private: &SecretKey, auth: &[u8]) -> Vec<u8> {
        let salt = &body[..16];
        assert_eq!(
            u32::from_be_bytes(body[16..20].try_into().unwrap()),
            RECORD_SIZE
        );
        let id_len = body[20] as usize;
        let as_public = PublicKey::from_sec1_bytes(&body[21..21 + id_len]).unwrap();
        let ciphertext = &body[21 + id_len..];
        let shared =
            p256::ecdh::diffie_hellman(ua_private.to_nonzero_scalar(), as_public.as_affine());
        let ua_public = ua_private.public_key().to_sec1_bytes();
        let ikm: [u8; 32] = hkdf_expand(
            auth,
            shared.raw_secret_bytes().as_slice(),
            &[b"WebPush: info\0", &ua_public, &as_public.to_sec1_bytes()],
        )
        .unwrap();
        let cek: [u8; 16] = hkdf_expand(salt, &ikm, &[b"Content-Encoding: aes128gcm\0"]).unwrap();
        let nonce: [u8; 12] = hkdf_expand(salt, &ikm, &[b"Content-Encoding: nonce\0"]).unwrap();
        let mut record = Aes128Gcm::new_from_slice(&cek)
            .unwrap()
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .unwrap();
        assert_eq!(record.pop(), Some(0x02), "last-record delimiter");
        record
    }

    #[test]
    fn encryption_matches_rfc_8291_appendix_a() {
        let sender = SecretKey::from_slice(&b64(AS_PRIVATE)).unwrap();
        let salt: [u8; 16] = b64(SALT).try_into().unwrap();
        let body = encrypt_with(
            PLAINTEXT,
            &rfc_subscription("https://push.example.net/push/JzLQ3raZJfFBR0aqvOMsLrt54w4rJUsV"),
            &sender,
            salt,
        )
        .unwrap();
        assert_eq!(URL_SAFE_NO_PAD.encode(&body), BODY);
    }

    #[test]
    fn fresh_encryption_decrypts_to_the_fixed_payload_only_for_the_subscriber() {
        let subscription = rfc_subscription("https://fcm.googleapis.com/fcm/send/abc");
        let ua_private = SecretKey::from_slice(&b64(UA_PRIVATE)).unwrap();
        let first = encrypt(WEBPUSH_WAKE_PAYLOAD, &subscription).unwrap();
        let second = encrypt(WEBPUSH_WAKE_PAYLOAD, &subscription).unwrap();
        assert_ne!(first[..16], second[..16], "a fresh salt each time");
        assert_ne!(
            first[21..86],
            second[21..86],
            "a fresh sender key each time"
        );
        assert_eq!(
            decrypt(&first, &ua_private, &b64(AUTH)),
            WEBPUSH_WAKE_PAYLOAD
        );
        assert_eq!(
            decrypt(&second, &ua_private, &b64(AUTH)),
            WEBPUSH_WAKE_PAYLOAD
        );
    }

    #[test]
    fn allowlist_admits_push_services_only() {
        let list = default_services();
        let allows = |url: &str| list.allows(&Url::parse(url).unwrap());
        for url in [
            "https://fcm.googleapis.com/fcm/send/abc",
            "https://updates.push.services.mozilla.com/wpush/v2/abc",
            "https://web.push.apple.com/abc",
            "https://wns2-par02p.notify.windows.com/w/?token=abc",
            "https://FCM.googleapis.com/fcm/send/abc",
            "https://fcm.googleapis.com:443/fcm/send/abc",
        ] {
            assert!(allows(url), "{url}");
        }
        for url in [
            "http://fcm.googleapis.com/fcm/send/abc",
            "https://fcm.googleapis.com:8443/fcm/send/abc",
            "https://user@fcm.googleapis.com/fcm/send/abc",
            "https://fcm.googleapis.com/fcm/send/abc#x",
            "https://notify.windows.com/w",
            "https://evilnotify.windows.com/w",
            "https://fcm.googleapis.com.example.org/abc",
            "https://example.org/fcm.googleapis.com",
            "https://127.0.0.1/abc",
            "https://[::1]/abc",
            "http://127.0.0.1:9/abc",
        ] {
            assert!(!allows(url), "{url}");
        }
        for bad in [
            "",
            "*.",
            "*",
            "localhost",
            "a..b",
            "exa mple.org",
            "*.*.org",
        ] {
            assert_eq!(
                PushServiceAllowlist::new([bad]).unwrap_err(),
                WebPushError::Allowlist,
                "{bad:?}"
            );
        }
        assert!(PushServiceAllowlist::new([]).is_err());
        let custom = PushServiceAllowlist::new(["push.example.org"]).unwrap();
        assert!(custom.allows(&Url::parse("https://push.example.org/x").unwrap()));
        assert!(!custom.allows(&Url::parse("https://fcm.googleapis.com/x").unwrap()));
    }

    #[test]
    fn subscriptions_are_validated_and_round_trip_through_custody() {
        let list = default_services();
        let endpoint = "https://fcm.googleapis.com/fcm/send/abc";
        let subscription = Subscription::new(endpoint, UA_PUBLIC, AUTH, &list).unwrap();
        assert_eq!(
            Subscription::from_bytes(&subscription.to_bytes().unwrap(), &list).unwrap(),
            subscription
        );
        // Padded base64url, as some browsers report it, is accepted.
        assert!(Subscription::new(endpoint, UA_PUBLIC, &format!("{AUTH}=="), &list).is_ok());
        let compressed = {
            let mut point = b64(UA_PUBLIC);
            point.truncate(33);
            point[0] = 0x02;
            URL_SAFE_NO_PAD.encode(point)
        };
        let long = format!(
            "https://fcm.googleapis.com/{}",
            "a".repeat(MAX_SUBSCRIPTION_ENDPOINT_BYTES)
        );
        for (endpoint, p256dh, auth) in [
            ("https://example.org/push", UA_PUBLIC, AUTH),
            (long.as_str(), UA_PUBLIC, AUTH),
            ("not a url", UA_PUBLIC, AUTH),
            (endpoint, compressed.as_str(), AUTH),
            (endpoint, "AAAA", AUTH),
            (endpoint, UA_PUBLIC, "BTBZMqHH6r4Tts7J_aSI"),
            (endpoint, UA_PUBLIC, "not base64!"),
        ] {
            assert_eq!(
                Subscription::new(endpoint, p256dh, auth, &list).unwrap_err(),
                WebPushError::Subscription,
                "{endpoint} {p256dh} {auth}"
            );
        }
        // Custody is re-checked against the current allowlist.
        let narrowed = PushServiceAllowlist::new(["web.push.apple.com"]).unwrap();
        assert!(Subscription::from_bytes(&subscription.to_bytes().unwrap(), &narrowed).is_err());
        assert!(Subscription::from_bytes(br#"{"endpoint":"x"}"#, &list).is_err());
    }

    fn vapid() -> VapidKey {
        let secret = SecretKey::from_slice(&b64(AS_PRIVATE)).unwrap();
        VapidKey::from_secret(&secret, "mailto:push@example.org").unwrap()
    }

    #[test]
    fn vapid_header_is_an_es256_jwt_for_the_endpoint_origin() {
        let key = vapid();
        let endpoint = Url::parse("https://fcm.googleapis.com/fcm/send/abc").unwrap();
        let header = key.authorization(&endpoint, 1_750_000_000);
        let (token, public) = header
            .strip_prefix("vapid t=")
            .and_then(|rest| rest.split_once(", k="))
            .unwrap();
        assert_eq!(public, key.public_key());
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let jose: serde_json::Value = serde_json::from_slice(&b64(parts[0])).unwrap();
        assert_eq!(jose, serde_json::json!({"typ": "JWT", "alg": "ES256"}));
        let claims: serde_json::Value = serde_json::from_slice(&b64(parts[1])).unwrap();
        assert_eq!(
            claims,
            serde_json::json!({
                "aud": "https://fcm.googleapis.com",
                "exp": 1_750_000_000 + VAPID_LIFETIME_SECONDS,
                "sub": "mailto:push@example.org",
            })
        );
        use p256::ecdsa::{signature::Verifier, VerifyingKey};
        let verifying = VerifyingKey::from_sec1_bytes(&b64(public)).unwrap();
        let signature = Signature::from_slice(&b64(parts[2])).unwrap();
        verifying
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .unwrap();
    }

    #[test]
    fn vapid_configuration_is_checked() {
        let secret = SecretKey::from_slice(&b64(AS_PRIVATE)).unwrap();
        for subject in ["https://example.org", "mailto:push@example.org"] {
            assert!(VapidKey::from_secret(&secret, subject).is_ok(), "{subject}");
        }
        for subject in ["", "push@example.org", "http://example.org", "mailto:"] {
            assert!(
                VapidKey::from_secret(&secret, subject).is_err(),
                "{subject}"
            );
        }
        assert!(VapidKey::from_pem("not a key", "mailto:push@example.org").is_err());
        let sec1 = include_str!("../tests/fixtures/vapid-test-sec1.pem");
        let pkcs8 = include_str!("../tests/fixtures/vapid-test-pkcs8.pem");
        let from_sec1 = VapidKey::from_pem(sec1, "mailto:push@example.org").unwrap();
        let from_pkcs8 = VapidKey::from_pem(pkcs8, "mailto:push@example.org").unwrap();
        assert_eq!(from_sec1.public_key(), from_pkcs8.public_key());
        assert!(!format!("{from_sec1:?}").contains("signing"));
    }

    #[test]
    fn push_service_statuses_map_onto_delivery_outcomes() {
        for code in [200, 201, 202] {
            assert_eq!(classify(code), DeliveryOutcome::Accepted, "{code}");
        }
        for code in [404, 410] {
            assert_eq!(
                classify(code),
                DeliveryOutcome::InvalidEndpoint {
                    unregistered_at: None
                },
                "{code}"
            );
        }
        for code in [401, 403] {
            assert_eq!(
                classify(code),
                DeliveryOutcome::ConfigurationFault,
                "{code}"
            );
        }
        for code in [429, 500, 502, 503] {
            assert_eq!(
                classify(code),
                DeliveryOutcome::Retry {
                    retry_after_seconds: None
                },
                "{code}"
            );
        }
        for code in [301, 400, 413] {
            assert_eq!(
                classify(code),
                DeliveryOutcome::PermanentRequestFault,
                "{code}"
            );
        }
    }

    /// A request the fake push service received.
    type Received = (HeaderMap, Vec<u8>);
    /// A status, and a `Retry-After` value, for the fake to answer with.
    type Reply = (u16, Option<&'static str>);

    #[derive(Clone, Default)]
    struct PushService {
        requests: Arc<Mutex<Vec<Received>>>,
        replies: Arc<Mutex<Vec<Reply>>>,
    }

    async fn receive(
        State(service): State<PushService>,
        headers: HeaderMap,
        body: Bytes,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        service
            .requests
            .lock()
            .unwrap()
            .push((headers, body.to_vec()));
        let (status, retry_after) = service.replies.lock().unwrap().remove(0);
        let status = axum::http::StatusCode::from_u16(status).unwrap();
        if status.is_redirection() {
            // Somewhere that would answer differently, were it followed.
            return (status, [("location", "/elsewhere")]).into_response();
        }
        match retry_after {
            Some(value) => (status, [("retry-after", value)]).into_response(),
            None => status.into_response(),
        }
    }

    fn fixed_now() -> i64 {
        1_750_000_000
    }

    #[tokio::test]
    async fn transport_sends_the_encrypted_wake_and_maps_replies() {
        let service = PushService::default();
        let app = Router::new()
            .route("/push/{id}", post(receive))
            .with_state(service.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/push/abc", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let allowlist = Arc::new(loopback());
        let transport =
            WebPushTransport::new(Arc::new(vapid()), allowlist.clone(), fixed_now).unwrap();
        let custody = Subscription::new(&endpoint, UA_PUBLIC, AUTH, &allowlist)
            .unwrap()
            .to_bytes()
            .unwrap();
        let attempt = DeliveryAttempt {
            request_id: uuid::Uuid::nil(),
            expires_at: fixed_now() + 90,
        };

        *service.replies.lock().unwrap() = vec![
            (201, None),
            (410, None),
            (429, Some("30")),
            (503, Some("99999")),
            (403, None),
            (302, None),
        ];
        let mut outcomes = Vec::new();
        for _ in 0..6 {
            outcomes.push(transport.send(attempt, &custody).await);
        }
        assert_eq!(
            outcomes,
            vec![
                DeliveryOutcome::Accepted,
                DeliveryOutcome::InvalidEndpoint {
                    unregistered_at: None
                },
                DeliveryOutcome::Retry {
                    retry_after_seconds: Some(30)
                },
                DeliveryOutcome::Retry {
                    retry_after_seconds: Some(3600)
                },
                DeliveryOutcome::ConfigurationFault,
                DeliveryOutcome::PermanentRequestFault,
            ]
        );

        let requests = service.requests.lock().unwrap();
        let ua_private = SecretKey::from_slice(&b64(UA_PRIVATE)).unwrap();
        for (headers, body) in requests.iter() {
            assert_eq!(headers["content-encoding"], "aes128gcm");
            assert_eq!(headers["ttl"], "90");
            assert_eq!(headers["urgency"], "high");
            assert_eq!(headers["topic"], WAKE_TOPIC);
            let authorization = headers["authorization"].to_str().unwrap();
            assert!(authorization.starts_with("vapid t="), "{authorization}");
            assert!(authorization.ends_with(&format!(", k={}", vapid().public_key())));
            assert_eq!(decrypt(body, &ua_private, &b64(AUTH)), WEBPUSH_WAKE_PAYLOAD);
        }
    }

    /// Sends one wake to a real subscription: `PushSubscription.toJSON()`
    /// from a browser, in `BUZZ_PUSH_LIVE_WEBPUSH_SUBSCRIPTION`, subscribed
    /// with the public key of `BUZZ_PUSH_LIVE_VAPID_KEY_PATH`.
    #[tokio::test]
    #[ignore = "requires a browser push subscription and its VAPID key"]
    async fn live_probe_delivers_one_wake() {
        #[derive(Deserialize)]
        struct Keys {
            p256dh: String,
            auth: String,
        }
        #[derive(Deserialize)]
        struct Json {
            endpoint: String,
            keys: Keys,
        }
        let json: Json = serde_json::from_str(
            &std::env::var("BUZZ_PUSH_LIVE_WEBPUSH_SUBSCRIPTION")
                .expect("set BUZZ_PUSH_LIVE_WEBPUSH_SUBSCRIPTION to PushSubscription.toJSON()"),
        )
        .unwrap();
        let pem = std::fs::read_to_string(
            std::env::var("BUZZ_PUSH_LIVE_VAPID_KEY_PATH")
                .expect("set BUZZ_PUSH_LIVE_VAPID_KEY_PATH to the VAPID private key PEM"),
        )
        .unwrap();
        let vapid = Arc::new(VapidKey::from_pem(&pem, "mailto:push@example.org").unwrap());
        // Loopback http too, for a local stand-in push service.
        let allowlist = Arc::new(loopback());
        let custody = Subscription::new(
            &json.endpoint,
            &json.keys.p256dh,
            &json.keys.auth,
            &allowlist,
        )
        .unwrap()
        .to_bytes()
        .unwrap();
        let transport =
            WebPushTransport::new(vapid, allowlist, || chrono::Utc::now().timestamp()).unwrap();
        let outcome = transport
            .send(
                DeliveryAttempt {
                    request_id: uuid::Uuid::new_v4(),
                    expires_at: chrono::Utc::now().timestamp() + 300,
                },
                &custody,
            )
            .await;
        eprintln!("live Web Push outcome: {outcome:?}");
        assert_eq!(outcome, DeliveryOutcome::Accepted);
    }

    #[tokio::test]
    async fn transport_refuses_custody_outside_the_allowlist_and_expired_wakes_get_ttl_zero() {
        let service = PushService::default();
        let app = Router::new()
            .route("/push/{id}", post(receive))
            .with_state(service.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}/push/abc", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let custody = Subscription::new(&endpoint, UA_PUBLIC, AUTH, &loopback())
            .unwrap()
            .to_bytes()
            .unwrap();
        let attempt = DeliveryAttempt {
            request_id: uuid::Uuid::nil(),
            expires_at: fixed_now() - 5,
        };

        let strict =
            WebPushTransport::new(Arc::new(vapid()), Arc::new(default_services()), fixed_now)
                .unwrap();
        assert_eq!(
            strict.send(attempt, &custody).await,
            DeliveryOutcome::PermanentRequestFault
        );
        assert_eq!(
            strict.send(attempt, b"garbage").await,
            DeliveryOutcome::PermanentRequestFault
        );
        assert!(service.requests.lock().unwrap().is_empty());

        *service.replies.lock().unwrap() = vec![(201, None)];
        let loose =
            WebPushTransport::new(Arc::new(vapid()), Arc::new(loopback()), fixed_now).unwrap();
        assert_eq!(
            loose.send(attempt, &custody).await,
            DeliveryOutcome::Accepted
        );
        assert_eq!(service.requests.lock().unwrap()[0].0["ttl"], "0");
    }
}
