//! Browser installation routes: Web Push enrollment, subscription
//! replacement, and the VAPID key. Delegation and revocation are shared with
//! APNs installations and live in the parent module.
use super::*;
#[derive(serde::Serialize)]
pub(super) struct WebEnrollTranscript<'a> {
    pub(super) v: u8,
    pub(super) audience: &'a str,
    pub(super) challenge_id: uuid::Uuid,
    pub(super) challenge: &'a str,
    pub(super) public_key: &'a str,
    pub(super) endpoint: &'a str,
    pub(super) p256dh: &'a str,
    pub(super) auth: &'a str,
    pub(super) endpoint_epoch: i64,
    pub(super) expires_at: i64,
}
/// Browser enrollment: the web counterpart of [`enroll`], with the
/// installation's own P-256 key in place of App Attest.
pub(super) async fn enroll_web(State(s): State<AppState>, body: Bytes) -> Response {
    let Some(webpush) = s.webpush.as_ref() else {
        return transport_unavailable();
    };
    let r: WebEnrollRequest = match crate::strict_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    let now = (s.now)();
    if r.v != WIRE_VERSION
        || r.endpoint_epoch != 1
        || r.expires_at <= now
        || r.expires_at > now.saturating_add(s.max_installation_lifetime_seconds)
    {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let (Ok(subscription), Ok(key), Some(challenge)) = (
        Subscription::new(
            &r.subscription.endpoint,
            &r.subscription.keys.p256dh,
            &r.subscription.keys.auth,
            &webpush.allowlist,
        ),
        InstallationKey::from_base64url(&r.public_key),
        decode_challenge(&r.challenge),
    ) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let t = WebEnrollTranscript {
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
    };
    let Some(signed) = transcript("buzz.push.enroll-web.v1", &t) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if !key.verify(signed.as_bytes(), &r.signature) {
        return error(StatusCode::UNAUTHORIZED, "invalid_signature");
    }
    let key_id = key.id();
    let public_key = key.to_sec1();
    let fingerprint = subscription.fingerprint();
    let Ok(custody) = subscription.to_bytes() else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    // A replay of a request that already succeeded returns its installation,
    // as for APNs. The key id is a digest of the key, so a match is this
    // key's installation; it must also hold these subscription keys, or the
    // gateway would go on encrypting to others.
    match s
        .authority
        .matching_installation(&key_id, fingerprint, r.endpoint_epoch, r.expires_at, now)
        .await
    {
        Ok(Some(existing))
            if s.token_keyring
                .open(Transport::WebPush, &existing.token_ciphertext)
                .is_ok_and(|stored| stored == custody) =>
        {
            return (
                StatusCode::CREATED,
                Json(InstallationEnrollResponse {
                    installation_handle: existing.id,
                    endpoint_epoch: existing.endpoint_epoch,
                    expires_at: existing.expires_at,
                }),
            )
                .into_response();
        }
        Ok(Some(_)) => return installation_conflict(),
        Ok(None) => {}
        Err(e) => return authority_error(e),
    }
    if let Err(e) = s
        .authority
        .consume_challenge(r.challenge_id, challenge, now)
        .await
    {
        return authority_error(e);
    }
    let Ok(ciphertext) = s.token_keyring.seal(Transport::WebPush, &custody) else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    let id = uuid::Uuid::new_v4();
    let n = NewInstallation {
        id,
        transport: Transport::WebPush,
        app_attest_key_id: key_id,
        app_attest_public_key: public_key,
        assertion_counter: 0,
        token_ciphertext: ciphertext,
        token_fingerprint: fingerprint,
        endpoint_epoch: 1,
        expires_at: r.expires_at,
    };
    if let Err(e) = s.authority.create_installation(n, now).await {
        return authority_error(e);
    }
    (
        StatusCode::CREATED,
        Json(InstallationEnrollResponse {
            installation_handle: id,
            endpoint_epoch: 1,
            expires_at: r.expires_at,
        }),
    )
        .into_response()
}

#[derive(serde::Serialize)]
pub(super) struct WebRotateTranscript<'a> {
    pub(super) v: u8,
    pub(super) audience: &'a str,
    pub(super) challenge_id: uuid::Uuid,
    pub(super) challenge: &'a str,
    pub(super) installation_handle: uuid::Uuid,
    pub(super) endpoint_epoch: i64,
    pub(super) new_endpoint_epoch: i64,
    pub(super) endpoint: &'a str,
    pub(super) p256dh: &'a str,
    pub(super) auth: &'a str,
}
/// Replace a browser installation's subscription, as [`rotate_endpoint`]
/// does an APNs token.
pub(super) async fn rotate_web_endpoint(State(s): State<AppState>, body: Bytes) -> Response {
    let Some(webpush) = s.webpush.as_ref() else {
        return transport_unavailable();
    };
    let r: WebRotateEndpointRequest = match crate::strict_json::from_slice(&body) {
        Ok(r) => r,
        Err(_) => return error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    if r.v != WIRE_VERSION
        || r.endpoint_epoch < 1
        || r.new_endpoint_epoch != r.endpoint_epoch.saturating_add(1)
    {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Ok(subscription) = Subscription::new(
        &r.subscription.endpoint,
        &r.subscription.keys.p256dh,
        &r.subscription.keys.auth,
        &webpush.allowlist,
    ) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    let t = WebRotateTranscript {
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
    };
    let installation = match verify_installation_assertion(
        &s,
        r.installation_handle,
        AssertionChallenge {
            id: r.challenge_id,
            text: &r.challenge,
        },
        &r.signature,
        "buzz.push.rotate-endpoint-web.v1",
        &t,
        false,
    )
    .await
    {
        Ok(installation) => installation,
        Err(e) => return e,
    };
    // A browser subscription can't replace an APNs token, even if a genuine
    // app signed this transcript.
    if installation.transport != Transport::WebPush {
        return error(StatusCode::NOT_FOUND, "not_authorized");
    }
    let Ok(ciphertext) = subscription.to_bytes().map_err(|_| ()).and_then(|bytes| {
        s.token_keyring
            .seal(Transport::WebPush, &bytes)
            .map_err(|_| ())
    }) else {
        return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    };
    match s
        .authority
        .rotate_endpoint(
            r.installation_handle,
            r.endpoint_epoch,
            r.new_endpoint_epoch,
            ciphertext,
            subscription.fingerprint(),
        )
        .await
    {
        Ok(()) => (StatusCode::OK, Json(MutationResponse { status: "rotated" })).into_response(),
        Err(e) => authority_error(e),
    }
}

/// The VAPID public key a browser subscribes with.
pub(super) async fn webpush_key(State(s): State<AppState>) -> Response {
    match s.webpush.as_ref() {
        Some(webpush) => Json(WebPushKeyResponse {
            public_key: webpush.vapid.public_key().to_owned(),
        })
        .into_response(),
        None => transport_unavailable(),
    }
}
