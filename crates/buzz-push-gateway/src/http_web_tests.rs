//! Browser installations through the public router: enrollment, delegation,
//! delivery, rotation and revocation, with an in-memory authority store and a
//! recording Web Push transport. No external service is used.
use super::web::{WebEnrollTranscript, WebRotateTranscript};
use super::*;
use crate::{
    authority::MemoryAuthorityStore,
    grant::GrantKey,
    http_delivery_tests::{request as delivery_request, signed_header, DIRECT_URL},
    token::TokenKey,
    webpush::{PushServiceAllowlist, VapidKey, DEFAULT_PUSH_SERVICE_HOSTS},
};
use axum::{body::Body, http::Request};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nostr::Keys;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use std::sync::Mutex;
use tower::ServiceExt;

const ORIGIN: &str = "https://app.example.org";
const ENDPOINT: &str = "https://fcm.googleapis.com/fcm/send/first";
const ROTATED: &str = "https://fcm.googleapis.com/fcm/send/second";
// RFC 8291 Appendix A's user agent keys stand in for a browser's.
const P256DH: &str =
    "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4";
const AUTH: &str = "BTBZMqHH6r4Tts7J_aSIgg";

fn fixed_now() -> i64 {
    1_750_000_000
}

/// Records the custody bytes of each send.
#[derive(Default)]
struct Recording(Mutex<Vec<Vec<u8>>>);

#[async_trait::async_trait]
impl PushTransport for Recording {
    async fn send(&self, _: DeliveryAttempt, endpoint: &[u8]) -> DeliveryOutcome {
        self.0.lock().unwrap().push(endpoint.to_vec());
        DeliveryOutcome::Accepted
    }
}

fn allowlist() -> PushServiceAllowlist {
    PushServiceAllowlist::new(DEFAULT_PUSH_SERVICE_HOSTS.iter().copied()).unwrap()
}

fn state(webpush: bool) -> (AppState, Arc<Recording>) {
    let sends = Arc::new(Recording::default());
    let vapid = VapidKey::from_pem(
        include_str!("../tests/fixtures/vapid-test-pkcs8.pem"),
        "mailto:push@example.org",
    )
    .unwrap();
    let state = AppState {
        grant_keyring: Arc::new(
            GrantKeyring::new(vec![GrantKey::new("test", &[1; 32]).unwrap()]).unwrap(),
        ),
        authority: Arc::new(MemoryAuthorityStore::default()),
        token_keyring: Arc::new(
            TokenKeyring::new(vec![TokenKey::new("test", &[2; 32]).unwrap()]).unwrap(),
        ),
        application: None,
        webpush: webpush.then(|| {
            Arc::new(WebPushRuntime {
                vapid: Arc::new(vapid),
                allowlist: Arc::new(allowlist()),
                transport: sends.clone(),
            })
        }),
        max_grant_lifetime_seconds: 86_400,
        max_installation_lifetime_seconds: 86_400,
        endpoint_quota_window_seconds: 60,
        endpoint_quota_max_deliveries: 10,
        now: fixed_now,
        accepting: Arc::new(AtomicBool::new(true)),
        cors_origins: vec![axum::http::HeaderValue::from_static(ORIGIN)],
    };
    (state, sends)
}

/// A browser: its installation key and the gateway it talks to.
struct Browser {
    app: Router,
    key: SigningKey,
}

impl Browser {
    fn public_key(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.key.verifying_key().to_sec1_point(false).as_bytes())
    }

    fn sign<T: serde::Serialize>(&self, domain: &str, value: &T) -> String {
        let signed = transcript(domain, value).unwrap();
        let signature: Signature = self.key.sign(signed.as_bytes());
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, serde_json::Value) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    async fn post(
        &self,
        path: &str,
        body: impl serde::Serialize,
    ) -> (StatusCode, serde_json::Value) {
        self.send(
            Request::post(path)
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&body).unwrap()))
                .unwrap(),
        )
        .await
    }

    async fn challenge(&self) -> (uuid::Uuid, String) {
        let (status, body) = self
            .post("/v1/installations/challenges", serde_json::json!({"v": 1}))
            .await;
        assert_eq!(status, StatusCode::OK);
        (
            body["challenge_id"].as_str().unwrap().parse().unwrap(),
            body["challenge"].as_str().unwrap().to_owned(),
        )
    }

    fn subscription(endpoint: &str) -> WebSubscription {
        WebSubscription {
            endpoint: endpoint.to_owned(),
            keys: WebSubscriptionKeys {
                p256dh: P256DH.to_owned(),
                auth: AUTH.to_owned(),
            },
        }
    }

    async fn enroll_request(&self, endpoint: &str) -> WebEnrollRequest {
        let challenge = self.challenge().await;
        self.enroll_request_with(endpoint, challenge, fixed_now() + 3600)
    }

    fn enroll_request_with(
        &self,
        endpoint: &str,
        (challenge_id, challenge): (uuid::Uuid, String),
        expires_at: i64,
    ) -> WebEnrollRequest {
        let mut r = WebEnrollRequest {
            v: 1,
            challenge_id,
            challenge,
            public_key: self.public_key(),
            subscription: Self::subscription(endpoint),
            endpoint_epoch: 1,
            expires_at,
            signature: String::new(),
        };
        r.signature = self.sign(
            "buzz.push.enroll-web.v1",
            &WebEnrollTranscript {
                v: r.v,
                audience: WEB_ENROLL_AUDIENCE,
                challenge_id: r.challenge_id,
                challenge: &r.challenge,
                public_key: &r.public_key,
                endpoint: &r.subscription.endpoint,
                p256dh: &r.subscription.keys.p256dh,
                auth: &r.subscription.keys.auth,
                endpoint_epoch: r.endpoint_epoch,
                expires_at: r.expires_at,
            },
        );
        r
    }

    async fn delegate(
        &self,
        handle: uuid::Uuid,
        relay: &Keys,
        endpoint_epoch: i64,
        generation: i64,
    ) -> (StatusCode, serde_json::Value) {
        let (challenge_id, challenge) = self.challenge().await;
        let mut r = DelegationRequest {
            v: 1,
            challenge_id,
            challenge,
            installation_handle: handle,
            endpoint_epoch,
            generation,
            relay_pubkey: relay.public_key().to_hex(),
            not_before: fixed_now(),
            expires_at: fixed_now() + 600,
            assertion: String::new(),
        };
        r.assertion = self.sign(
            "buzz.push.delegate.v1",
            &DelegateTranscript {
                v: r.v,
                audience: DELEGATE_AUDIENCE,
                challenge_id: r.challenge_id,
                challenge: &r.challenge,
                installation_handle: r.installation_handle,
                endpoint_epoch: r.endpoint_epoch,
                generation: r.generation,
                relay_pubkey: &r.relay_pubkey,
                not_before: r.not_before,
                expires_at: r.expires_at,
            },
        );
        self.post("/v1/delegations", r).await
    }

    async fn rotate(&self, handle: uuid::Uuid, endpoint: &str) -> (StatusCode, serde_json::Value) {
        let (challenge_id, challenge) = self.challenge().await;
        let mut r = WebRotateEndpointRequest {
            v: 1,
            challenge_id,
            challenge,
            installation_handle: handle,
            endpoint_epoch: 1,
            new_endpoint_epoch: 2,
            subscription: Self::subscription(endpoint),
            signature: String::new(),
        };
        r.signature = self.sign(
            "buzz.push.rotate-endpoint-web.v1",
            &WebRotateTranscript {
                v: r.v,
                audience: WEB_ROTATE_ENDPOINT_AUDIENCE,
                challenge_id: r.challenge_id,
                challenge: &r.challenge,
                installation_handle: r.installation_handle,
                endpoint_epoch: r.endpoint_epoch,
                new_endpoint_epoch: r.new_endpoint_epoch,
                endpoint: &r.subscription.endpoint,
                p256dh: &r.subscription.keys.p256dh,
                auth: &r.subscription.keys.auth,
            },
        );
        self.post("/v1/installations/web/endpoint", r).await
    }

    /// One relay delivery with `grant`, as the relay sends it.
    async fn deliver(&self, relay: &Keys, grant: &str) -> StatusCode {
        let body = serde_json::to_vec(&serde_json::json!({
            "v": 1, "endpoint_grant": grant, "request_id": uuid::Uuid::new_v4(),
            "expires_at": fixed_now() + 60,
        }))
        .unwrap();
        let auth = signed_header(relay, DIRECT_URL, "POST", &body);
        self.app
            .clone()
            .oneshot(delivery_request(DIRECT_URL, None, auth, body))
            .await
            .unwrap()
            .status()
    }
}

fn browser(state: AppState, seed: u8) -> Browser {
    let (app, _) = router(state);
    Browser {
        app,
        key: SigningKey::from_slice(&[seed; 32]).unwrap(),
    }
}

fn sent_endpoint(sends: &Recording, index: usize) -> String {
    Subscription::from_bytes(&sends.0.lock().unwrap()[index], &allowlist())
        .unwrap()
        .endpoint()
        .to_string()
}

#[tokio::test]
async fn browser_installation_enrolls_delegates_receives_rotates_and_revokes() {
    let (state, sends) = state(true);
    let alice = browser(state.clone(), 7);
    let relay = Keys::generate();

    // The page subscribes with the gateway's VAPID key.
    let (status, body) = alice
        .send(Request::get("/v1/webpush/key").body(Body::empty()).unwrap())
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["public_key"],
        state.webpush.as_ref().unwrap().vapid.public_key()
    );

    // Enrollment, and a replay of the same request after a lost response.
    let enroll = alice.enroll_request(ENDPOINT).await;
    let (status, enrolled) = alice.post("/v1/installations/web", &enroll).await;
    assert_eq!(status, StatusCode::CREATED, "{enrolled}");
    let handle: uuid::Uuid = enrolled["installation_handle"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        alice.post("/v1/installations/web", &enroll).await,
        (StatusCode::CREATED, enrolled.clone())
    );
    // A "replay" carrying other subscription keys is not the same request.
    let mut rekeyed = alice.enroll_request_with(
        ENDPOINT,
        (enroll.challenge_id, enroll.challenge.clone()),
        enroll.expires_at,
    );
    rekeyed.subscription.keys.auth = URL_SAFE_NO_PAD.encode([9; 16]);
    rekeyed.signature = alice.sign(
        "buzz.push.enroll-web.v1",
        &WebEnrollTranscript {
            v: 1,
            audience: WEB_ENROLL_AUDIENCE,
            challenge_id: rekeyed.challenge_id,
            challenge: &rekeyed.challenge,
            public_key: &rekeyed.public_key,
            endpoint: &rekeyed.subscription.endpoint,
            p256dh: &rekeyed.subscription.keys.p256dh,
            auth: &rekeyed.subscription.keys.auth,
            endpoint_epoch: 1,
            expires_at: rekeyed.expires_at,
        },
    );
    assert_eq!(
        alice.post("/v1/installations/web", &rekeyed).await,
        (
            StatusCode::CONFLICT,
            serde_json::json!({"error": "installation_conflict"})
        )
    );

    // Refusals: a challenge already spent, a lifetime over the gateway's
    // limit, a tampered request, an endpoint off the allowlist, and the same
    // subscription under another key.
    let bob = browser(state.clone(), 8);
    let spent = bob.enroll_request_with(
        "https://fcm.googleapis.com/fcm/send/bob",
        (enroll.challenge_id, enroll.challenge.clone()),
        fixed_now() + 3600,
    );
    assert_eq!(
        bob.post("/v1/installations/web", &spent).await.0,
        StatusCode::NOT_FOUND
    );
    let too_long = bob.enroll_request_with(
        "https://fcm.googleapis.com/fcm/send/bob",
        bob.challenge().await,
        fixed_now() + state.max_installation_lifetime_seconds + 1,
    );
    assert_eq!(
        bob.post("/v1/installations/web", &too_long).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut tampered = alice.enroll_request(ENDPOINT).await;
    tampered.expires_at -= 1;
    assert_eq!(
        alice.post("/v1/installations/web", &tampered).await,
        (
            StatusCode::UNAUTHORIZED,
            serde_json::json!({"error": "invalid_signature"})
        )
    );
    let off_list = alice.enroll_request("https://push.example.org/x").await;
    assert_eq!(
        alice.post("/v1/installations/web", &off_list).await.0,
        StatusCode::BAD_REQUEST
    );
    let mallory = browser(state.clone(), 9);
    let stolen = mallory.enroll_request(ENDPOINT).await;
    assert_eq!(
        mallory.post("/v1/installations/web", &stolen).await,
        (
            StatusCode::CONFLICT,
            serde_json::json!({"error": "installation_conflict"})
        )
    );
    // Another key can't act for Alice's installation.
    assert_eq!(
        mallory.delegate(handle, &relay, 1, 1).await.0,
        StatusCode::UNAUTHORIZED
    );

    // Delegation, then a wake reaches Alice's subscription.
    let (status, delegated) = alice.delegate(handle, &relay, 1, 1).await;
    assert_eq!(status, StatusCode::CREATED, "{delegated}");
    let grant = delegated["endpoint_grant"].as_str().unwrap().to_owned();
    assert_eq!(alice.deliver(&relay, &grant).await, StatusCode::OK);
    assert_eq!(sent_endpoint(&sends, 0), ENDPOINT);

    // The APNs rotation route can't put a token on a browser installation.
    let (challenge_id, challenge) = alice.challenge().await;
    let mut apns_rotate = RotateEndpointRequest {
        v: 1,
        challenge_id,
        challenge,
        installation_handle: handle,
        endpoint_epoch: 1,
        new_endpoint_epoch: 2,
        endpoint: "ab".repeat(32),
        assertion: String::new(),
    };
    apns_rotate.assertion = alice.sign(
        "buzz.push.rotate-endpoint.v1",
        &RotateTranscript {
            v: 1,
            audience: ROTATE_ENDPOINT_AUDIENCE,
            challenge_id: apns_rotate.challenge_id,
            challenge: &apns_rotate.challenge,
            installation_handle: handle,
            endpoint_epoch: 1,
            new_endpoint_epoch: 2,
            endpoint: &apns_rotate.endpoint,
        },
    );
    assert_eq!(
        alice.post("/v1/installations/endpoint", &apns_rotate).await,
        (
            StatusCode::NOT_FOUND,
            serde_json::json!({"error": "not_authorized"})
        )
    );

    // pushsubscriptionchange: the new subscription replaces the old one, the
    // old grant stops working, and a fresh delegation reaches the new one.
    assert_eq!(alice.rotate(handle, ROTATED).await.0, StatusCode::OK);
    assert_eq!(alice.deliver(&relay, &grant).await, StatusCode::NOT_FOUND);
    let (status, delegated) = alice.delegate(handle, &relay, 2, 2).await;
    assert_eq!(status, StatusCode::CREATED, "{delegated}");
    let grant = delegated["endpoint_grant"].as_str().unwrap().to_owned();
    assert_eq!(alice.deliver(&relay, &grant).await, StatusCode::OK);
    assert_eq!(sent_endpoint(&sends, 1), ROTATED);

    // Revoking the delegation stops delivery.
    let (challenge_id, challenge) = alice.challenge().await;
    let mut revoke = RevokeDelegationRequest {
        v: 1,
        challenge_id,
        challenge,
        installation_handle: handle,
        relay_pubkey: relay.public_key().to_hex(),
        generation: 2,
        assertion: String::new(),
    };
    revoke.assertion = alice.sign(
        "buzz.push.revoke-delegation.v1",
        &RevokeDelegationTranscript {
            v: 1,
            audience: REVOKE_DELEGATION_AUDIENCE,
            challenge_id: revoke.challenge_id,
            challenge: &revoke.challenge,
            installation_handle: handle,
            relay_pubkey: &revoke.relay_pubkey,
            generation: 2,
        },
    );
    assert_eq!(
        alice.post("/v1/delegations/revoke", &revoke).await.0,
        StatusCode::OK
    );
    assert_eq!(alice.deliver(&relay, &grant).await, StatusCode::NOT_FOUND);

    // Revoking the installation, and repeating it after a lost response.
    let (challenge_id, challenge) = alice.challenge().await;
    let mut revoke = RevokeInstallationRequest {
        v: 1,
        challenge_id,
        challenge,
        installation_handle: handle,
        endpoint_epoch: 2,
        new_endpoint_epoch: 3,
        assertion: String::new(),
    };
    let sign_revoke = |r: &RevokeInstallationRequest| {
        alice.sign(
            "buzz.push.revoke-installation.v1",
            &RevokeInstallationTranscript {
                v: 1,
                audience: REVOKE_INSTALLATION_AUDIENCE,
                challenge_id: r.challenge_id,
                challenge: &r.challenge,
                installation_handle: handle,
                endpoint_epoch: 2,
                new_endpoint_epoch: 3,
            },
        )
    };
    revoke.assertion = sign_revoke(&revoke);
    assert_eq!(
        alice.post("/v1/installations/revoke", &revoke).await.0,
        StatusCode::OK
    );
    let (challenge_id, challenge) = alice.challenge().await;
    revoke.challenge_id = challenge_id;
    revoke.challenge = challenge;
    revoke.assertion = sign_revoke(&revoke);
    assert_eq!(
        alice.post("/v1/installations/revoke", &revoke).await.0,
        StatusCode::OK
    );
    assert_eq!(
        alice.delegate(handle, &relay, 3, 3).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(sends.0.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn browser_routes_answer_cors_preflights_for_configured_origins_only() {
    let (state, _) = state(true);
    let alice = browser(state, 7);
    let preflight = |path: &str, origin: &str| {
        Request::options(path)
            .header("origin", origin)
            .header("access-control-request-method", "POST")
            .header("access-control-request-headers", "content-type")
            .body(Body::empty())
            .unwrap()
    };
    for path in [
        "/v1/installations/challenges",
        "/v1/installations/web",
        "/v1/installations/web/endpoint",
        "/v1/webpush/key",
        "/v1/delegations",
        "/v1/delegations/revoke",
        "/v1/installations/revoke",
    ] {
        let response = alice
            .app
            .clone()
            .oneshot(preflight(path, ORIGIN))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            ORIGIN,
            "{path}"
        );
        let response = alice
            .app
            .clone()
            .oneshot(preflight(path, "https://other.example.org"))
            .await
            .unwrap();
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin"),
            "{path}"
        );
    }
    for path in [
        "/v1/installations",
        "/v1/installations/endpoint",
        DELIVERY_PATH,
    ] {
        let response = alice
            .app
            .clone()
            .oneshot(preflight(path, ORIGIN))
            .await
            .unwrap();
        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin"),
            "{path}"
        );
    }
    // Actual responses carry the header too.
    let response = alice
        .app
        .clone()
        .oneshot(
            Request::get("/v1/webpush/key")
                .header("origin", ORIGIN)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()["access-control-allow-origin"], ORIGIN);
}

#[tokio::test]
async fn web_routes_without_web_push_answer_transport_unavailable() {
    let (state, _) = state(false);
    let alice = browser(state, 7);
    let unavailable = (
        StatusCode::NOT_FOUND,
        serde_json::json!({"error": "transport_unavailable"}),
    );
    assert_eq!(
        alice
            .send(Request::get("/v1/webpush/key").body(Body::empty()).unwrap())
            .await,
        unavailable
    );
    let enroll = alice.enroll_request(ENDPOINT).await;
    assert_eq!(
        alice.post("/v1/installations/web", &enroll).await,
        unavailable
    );
    assert_eq!(alice.rotate(uuid::Uuid::nil(), ROTATED).await, unavailable);
}

#[tokio::test]
async fn web_installation_whose_transport_was_removed_is_a_configuration_fault() {
    let (state, sends) = state(true);
    let alice = browser(state.clone(), 7);
    let relay = Keys::generate();
    let (_, enrolled) = alice
        .post(
            "/v1/installations/web",
            alice.enroll_request(ENDPOINT).await,
        )
        .await;
    let handle = enrolled["installation_handle"]
        .as_str()
        .unwrap()
        .parse()
        .unwrap();
    let (_, delegated) = alice.delegate(handle, &relay, 1, 1).await;
    let grant = delegated["endpoint_grant"].as_str().unwrap().to_owned();
    // The same authority store, behind a gateway without Web Push.
    let restarted = Browser {
        app: router(AppState {
            webpush: None,
            ..state
        })
        .0,
        key: alice.key.clone(),
    };
    assert_eq!(
        restarted.deliver(&relay, &grant).await,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(sends.0.lock().unwrap().is_empty());
    // Nor can it act for the installation.
    assert_eq!(
        restarted.delegate(handle, &relay, 1, 2).await,
        (
            StatusCode::NOT_FOUND,
            serde_json::json!({"error": "transport_unavailable"})
        )
    );
    // The request id was released, so a configured gateway delivers.
    assert_eq!(alice.deliver(&relay, &grant).await, StatusCode::OK);
}

/// Signatures made by Web Crypto (Node's `crypto.subtle`, ECDSA P-256 with
/// SHA-256), one with a high `s`: browsers don't normalize it.
#[test]
fn web_crypto_signatures_verify_whatever_their_s() {
    let key = InstallationKey::from_base64url(
        "BDkTUPcjWAQkwjQS7WjTP1t5j5Zi7T2TP3SYu2zLFw0nTEGKmxGcK7wpGnWxu2vhHphPcbTAPnQ5NLQdfxJD07c",
    )
    .unwrap();
    let message = b"buzz.push.delegate.v1\n{\"v\":1}";
    for signature in [
        "eg3M3Wj6MVx_HuW667L3HVYlisAS6gQ5iDDRgnIylGt78qMzV0yJpR0etJTOzmbrhLmT_dQxVv6U5YAoiUvpVQ",
        "Myg8QsA8InQ_j90G2t9fqdT5gizxYlXmCfodoM4-VnXK8Irzchil75S7qsKEmXRjyNr0ZFPe9-zHm8upZqJkug",
    ] {
        assert!(key.verify(message, signature), "{signature}");
        assert!(!key.verify(b"another message", signature));
    }
    assert!(!key.verify(message, "not base64!"));
    assert!(!key.verify(message, &URL_SAFE_NO_PAD.encode([0; 64])));
    // Key ids are domain separated from App Attest's, a plain SHA-256.
    use sha2::Digest;
    assert_eq!(key.id().len(), 32);
    assert_ne!(key.id(), sha2::Sha256::digest(key.to_sec1()).to_vec());
    for bad in ["", "AAAA", &URL_SAFE_NO_PAD.encode([4; 65])] {
        assert!(InstallationKey::from_base64url(bad).is_err(), "{bad}");
    }
}
