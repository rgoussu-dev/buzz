//! Closed wire types for the stateful gateway.

use serde::{Deserialize, Serialize};

pub const MAX_REQUEST_BYTES: usize = 8 * 1024;
/// Maximum decoded Apple App Attest object accepted by the verifier.
pub const MAX_APP_ATTESTATION_BYTES: usize = 16 * 1024;
/// Enrollment carries the maximum App Attest object as standard base64 plus a
/// bounded APNs endpoint and the closed JSON envelope. Other gateway requests
/// remain subject to `MAX_REQUEST_BYTES`.
pub const MAX_ENROLL_REQUEST_BYTES: usize =
    MAX_APP_ATTESTATION_BYTES.div_ceil(3) * 4 + MAX_ENDPOINT_HEX_BYTES * 2 + 1024;
pub const MAX_GRANT_BYTES: usize = 4096;
pub const MAX_ENDPOINT_HEX_BYTES: usize = 512;
pub const APNS_RECONNECT_PAYLOAD: &[u8] =
    br#"{"aps":{"alert":{"body":"Reconnect to your relay now"},"sound":"default","mutable-content":1}}"#;
/// The only Web Push application body, encrypted to the browser (RFC 8291).
/// Like [`APNS_RECONNECT_PAYLOAD`], it carries nothing from the relay.
pub const WEBPUSH_WAKE_PAYLOAD: &[u8] = br#"{"v":1}"#;
pub const WIRE_VERSION: u8 = 1;

/// Relay request. It deliberately has no application-payload field:
/// the gateway emits one compiled-in APNs reconnect payload for every delivery.
/// `endpoint_grant` is opaque authenticated ciphertext minted by the gateway
/// sealing key and persisted with the relay-owned lease.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryRequest {
    pub v: u8,
    pub endpoint_grant: String,
    pub request_id: uuid::Uuid,
    pub expires_at: i64,
}

/// Opaque delivery capability plaintext. It contains no APNs token: the random
/// delegation id resolves through durable authority state, while the remaining
/// fields are authenticated fences that make stale or cross-relay use fail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointGrant {
    pub v: u8,
    pub delegation_id: uuid::Uuid,
    pub relay_pubkey: String,
    pub endpoint_epoch: i64,
    pub generation: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationChallengeRequest {
    pub v: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallationChallengeResponse {
    pub challenge_id: uuid::Uuid,
    pub challenge: String,
    pub expires_at: i64,
}

/// Direct app enrollment. `attestation` is Apple's CBOR object and `key_id` is
/// the App Attest key identifier, both base64 encoded. The attested key is the
/// installation authority; no second application signing key is introduced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallationEnrollRequest {
    pub v: u8,
    pub challenge_id: uuid::Uuid,
    pub challenge: String,
    pub key_id: String,
    pub attestation: String,
    pub endpoint: String,
    pub endpoint_epoch: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct InstallationEnrollResponse {
    pub installation_handle: uuid::Uuid,
    pub endpoint_epoch: i64,
    pub expires_at: i64,
}

/// A browser push subscription: the `endpoint` and `keys` of
/// `PushSubscription.toJSON()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSubscription {
    pub endpoint: String,
    pub keys: WebSubscriptionKeys,
}

/// The subscription's encryption keys, base64url as browsers report them.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebSubscriptionKeys {
    pub p256dh: String,
    pub auth: String,
}

/// Browser enrollment. `public_key` is the installation's Web Crypto P-256
/// key (uncompressed SEC1, base64url); it is the installation authority, as
/// the App Attest key is for APNs. `signature` is that key's ECDSA P-256
/// SHA-256 signature (raw `r || s`, base64url) over the request transcript.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebEnrollRequest {
    pub v: u8,
    pub challenge_id: uuid::Uuid,
    pub challenge: String,
    pub public_key: String,
    pub subscription: WebSubscription,
    pub endpoint_epoch: i64,
    pub expires_at: i64,
    pub signature: String,
}

/// Replace a browser installation's subscription
/// (`pushsubscriptionchange`), signed like [`WebEnrollRequest`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebRotateEndpointRequest {
    pub v: u8,
    pub challenge_id: uuid::Uuid,
    pub challenge: String,
    pub installation_handle: uuid::Uuid,
    pub endpoint_epoch: i64,
    pub new_endpoint_epoch: i64,
    pub subscription: WebSubscription,
    pub signature: String,
}

/// The gateway's VAPID public key: the browser's `applicationServerKey`.
#[derive(Debug, Clone, Serialize)]
pub struct WebPushKeyResponse {
    pub public_key: String,
}

/// `assertion` is an App Attest assertion for an APNs installation, and the
/// installation key's signature (as in [`WebEnrollRequest`]) for a browser
/// one. The same holds for the rotate and revoke requests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationRequest {
    pub v: u8,
    pub challenge_id: uuid::Uuid,
    pub challenge: String,
    pub installation_handle: uuid::Uuid,
    pub endpoint_epoch: i64,
    pub generation: i64,
    pub relay_pubkey: String,
    pub not_before: i64,
    pub expires_at: i64,
    pub assertion: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DelegationResponse {
    pub endpoint_grant: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateEndpointRequest {
    pub v: u8,
    pub challenge_id: uuid::Uuid,
    pub challenge: String,
    pub installation_handle: uuid::Uuid,
    pub endpoint_epoch: i64,
    pub new_endpoint_epoch: i64,
    pub endpoint: String,
    pub assertion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeDelegationRequest {
    pub v: u8,
    pub challenge_id: uuid::Uuid,
    pub challenge: String,
    pub installation_handle: uuid::Uuid,
    pub relay_pubkey: String,
    pub generation: i64,
    pub assertion: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeInstallationRequest {
    pub v: u8,
    pub challenge_id: uuid::Uuid,
    pub challenge: String,
    pub installation_handle: uuid::Uuid,
    pub endpoint_epoch: i64,
    pub new_endpoint_epoch: i64,
    pub assertion: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MutationResponse {
    pub status: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "status", deny_unknown_fields)]
pub enum DeliveryResponse {
    Accepted,
    InvalidEndpoint {
        generation: i64,
        invalid_at: Option<i64>,
    },
    Retry {
        retry_after_seconds: Option<i64>,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub error: &'static str,
}
