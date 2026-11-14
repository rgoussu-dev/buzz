# Buzz push notes

Push is experimental. These notes capture current decisions; we will write a
stable specification after validating the design through launch and use.
[NIP-PL](nips/NIP-PL.md) is background, not the current Buzz contract.

- Relays advertise `buzz-push-v1`, never `nip-pl`. Updated clients require it.
- Compatible changes keep the capability name. Incompatible behavior that
  clients must distinguish gets a new version.
- Each gateway serves one server-configured Apple application and APNs transport.
  Enrollment, transcripts, grants, leases and discovery have no application-profile
  selector. The relay advertises transport classes in `class_support`.
- Existing grants and pending enrollment records are not migrated. The new client
  uses separate Keychain records and enrolls again. Keep old production push
  disabled so released clients never acquire legacy push authority.
- Stop old gateway replicas before cutover. The gateway migration requires an
  empty authority store because endpoint fingerprints changed. The relay migration
  requires no active legacy leases. Neither migration deletes that state.
- Publish the matching gateway image and chart, update deployment configuration,
  then enable the new relay capability. Verify enrollment, delivery, renewal and
  revocation on a physical device before production activation.

## Channel identifier grammar

Relays advertise `h_grammar: "uuid-v4-lowercase"`. Mobile also accepts
`uuid-lowercase`, which drops the UUID version and variant restriction so
UUIDv5 starter channels can be subscribed. Against a `uuid-v4-lowercase` relay,
mobile checks positive and ignore channel filters before enrollment or
publication. It keeps the desired filters and rechecks relay capabilities every
five minutes rather than sending a lease the relay would reject.

Do not change the relay advertisement until mobile builds that only parse
`uuid-v4-lowercase` have drained. Those builds parse the descriptor before
renewal, opt-out and revocation, so a new grammar would leave their existing
leases active until expiry.

## Workflow owner attribution

The relay signs workflow messages. Their first `p` tag,
`["p", <owner>, "", "owner"]`, names the workflow owner so clients can show
who owns the message. On an event marked `["buzz:workflow", "true"]` that tag
is attribution, not a mention: `#p` filters (live, history through the mention
index, and push leases), operator listeners and the push hellthread gate all
skip it, so the owner is not notified by every run of their workflow. When a
workflow mentions its owner, the relay adds a plain `["p", <owner>]`, which
notifies them like any mention. Mobile's Activity feed, unread mention priority
and in-app notification rule apply the same rule.

## Web Push installations

A relay started with `BUZZ_PUSH_WEBPUSH_ENABLED=true` (which requires
`BUZZ_PUSH_ENABLED=true`) adds `"webpush": ["default"]` to `class_support`
and accepts leases with `"transport": "webpush"`. It is a compatible
addition: `buzz-push-v1` is unchanged, and clients that know only `apns`
keep working. Set it only when the relay's gateway has Web Push configured.

A gateway with Web Push configured also enrolls browsers. They follow the
same installation, delegation and lease model as the iOS app, with two
differences: the endpoint is a Web Push subscription, and a non-extractable
Web Crypto ECDSA P-256 key stands in for App Attest.

- `GET /v1/webpush/key` returns `{"public_key": "<base64url>"}`, the VAPID
  key to pass as `applicationServerKey`.
- `POST /v1/installations/web` enrolls:
  `{v, challenge_id, challenge, public_key, subscription: {endpoint, keys: {p256dh, auth}}, endpoint_epoch: 1, expires_at, signature}`.
  `public_key` is the installation key's raw (uncompressed) export,
  base64url. The response is the same as for `POST /v1/installations`.
- `POST /v1/installations/web/endpoint` replaces the subscription after
  `pushsubscriptionchange`:
  `{v, challenge_id, challenge, installation_handle, endpoint_epoch, new_endpoint_epoch, subscription, signature}`.
- `POST /v1/delegations`, `/v1/delegations/revoke` and
  `/v1/installations/revoke` take the same bodies as for iOS; `assertion`
  is the installation key's signature.

Each signature is Web Crypto's `ECDSA`/`SHA-256` output (raw `r || s`),
base64url, over `<domain>\n<JSON>`. The JSON object has exactly these keys,
in this order, and no whitespace (`JSON.stringify` of an object literal
written in this order):

| Request | Domain | JSON keys |
|---|---|---|
| Enroll | `buzz.push.enroll-web.v1` | `v`, `audience` (`https://push.buzz.xyz/v1/installations/web`), `challenge_id`, `challenge`, `public_key`, `endpoint`, `p256dh`, `auth`, `endpoint_epoch`, `expires_at` |
| Replace subscription | `buzz.push.rotate-endpoint-web.v1` | `v`, `audience` (`https://push.buzz.xyz/v1/installations/web/endpoint`), `challenge_id`, `challenge`, `installation_handle`, `endpoint_epoch`, `new_endpoint_epoch`, `endpoint`, `p256dh`, `auth` |
| Delegate | `buzz.push.delegate.v1` | `v`, `audience` (`https://push.buzz.xyz/v1/delegations`), `challenge_id`, `challenge`, `installation_handle`, `endpoint_epoch`, `generation`, `relay_pubkey`, `not_before`, `expires_at` |
| Revoke delegation | `buzz.push.revoke-delegation.v1` | `v`, `audience` (`https://push.buzz.xyz/v1/delegations/revoke`), `challenge_id`, `challenge`, `installation_handle`, `relay_pubkey`, `generation` |
| Revoke installation | `buzz.push.revoke-installation.v1` | `v`, `audience` (`https://push.buzz.xyz/v1/installations/revoke`), `challenge_id`, `challenge`, `installation_handle`, `endpoint_epoch`, `new_endpoint_epoch` |

Every request takes a fresh challenge from
`POST /v1/installations/challenges`; it is the replay fence, as a browser
key has no counter. The wake a browser receives is the fixed payload
`{"v":1}`, encrypted to its subscription (RFC 8291). Browser routes answer
CORS for `BUZZ_PUSH_CORS_ORIGINS`.
