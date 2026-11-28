# This fork

`rgoussu-dev/buzz` is a fork of [`block/buzz`](https://github.com/block/buzz).
It carries a few server-side features that a web client (a PWA) needs and
upstream does not have yet, and it publishes its own relay and push gateway
images. Every feature is off by default and generic: a relay or gateway built
from this fork and configured like upstream's behaves like upstream's.

## What the fork adds

| Feature | Where | Turned on by | Documented in |
|---|---|---|---|
| Web Push in the push gateway: a `web` installation platform, browser enrollment with a Web Crypto key, RFC 8291/8292 delivery. iOS (APNs) becomes optional, so a gateway can serve browsers alone | `crates/buzz-push-gateway` | `BUZZ_PUSH_VAPID_KEY_PATH`, `BUZZ_PUSH_VAPID_SUBJECT`, `BUZZ_PUSH_CORS_ORIGINS` | [push-gateway-deployment.md](push-gateway-deployment.md#web-push-optional), [buzz-push.md](buzz-push.md#web-push-installations) |
| The relay advertises `webpush` in NIP-11 `class_support` and accepts browser leases | `crates/buzz-relay` | `BUZZ_PUSH_WEBPUSH_ENABLED=true` (needs `BUZZ_PUSH_ENABLED=true`) | [buzz-push.md](buzz-push.md#web-push-installations) |
| A forge token hop: two forwarded endpoints so a web page can use GitHub's device flow, advertised in NIP-11 as `buzz_forge_hops` | `crates/buzz-relay` | `BUZZ_FORGE_HOPS` | [forge-hop.md](forge-hop.md) |
| Partial fetch for git clients: upload-pack advertises `filter` and `allow-reachable-sha1-in-want` | `crates/buzz-relay` | always on | [git-on-object-storage.md](git-on-object-storage.md) |
| buzz-acp gives an agent the diff messages (kind 40008) of the thread it is asked about | `crates/buzz-acp` | always on | — |

The designs were written as proposals for upstream, in
[`rgoussu-dev/buzz-mobile`](https://github.com/rgoussu-dev/buzz-mobile)
(`docs/decisions/web-push.md`, `docs/proposals/`). Each can still be sent
upstream as it is.

## Images

[`fork-images.yml`](../.github/workflows/fork-images.yml) builds two images for
`linux/amd64` and pushes them to the fork owner's GHCR namespace:

- `ghcr.io/<owner>/buzz`: the relay (`Dockerfile`, target `runtime`).
- `ghcr.io/<owner>/buzz-push-gateway`: the gateway (`Dockerfile.push-gateway`).

| Event | Tags |
|---|---|
| push to `main` | `main`, `sha-<7>`, `main-<commit UTC>-<7>` |
| pull request from a branch of this repository | `pr-<number>` |
| manual run (`workflow_dispatch`) | `<branch>`, `sha-<7>` |

Each run's summary lists `tag@sha256:…` references to pin a deployment to. The
workflow does not run in `block/buzz`, does not qualify a source against CI and
does not attest provenance: it is for an operator deploying their own fork.

To use it:

1. Enable GitHub Actions on the fork. Upstream's own workflows then run too;
   most skip or fail outside `block/buzz` (they publish to its registry or need
   its secrets). Disable the ones you don't want under **Actions** (each
   workflow's menu has **Disable workflow**); `Fork images` needs none of them.
2. After the first run, make the two packages public (**Packages → Package
   settings → Change visibility**), or give the deployment a registry login.

## Database migrations

Fork migrations are numbered from `9001`, in both `migrations/` and
`crates/buzz-push-gateway/migrations/`, so an upstream migration never takes a
number the fork used. SQLx applies whatever is pending, in version order, and
does not require a gap-free history, so a database that ran `9001` still takes
upstream's next `01xx`.

One thing to check when syncing: if upstream changes the
`push_gateway_installations.platform` check again (a migration that drops and
re-adds it without `'web'`), add a fork migration after it that re-admits
`'web'`, or a database with browser installations refuses the upstream one.

## Keeping up with upstream

`main` carries the fork's commits on top of upstream's, so GitHub's **Sync
fork** merges instead of fast-forwarding. Conflicts are most likely in
`crates/buzz-push-gateway/src/{http,config,main}.rs`, where the fork adds a
platform next to upstream's iOS and Android. After a sync, run:

```bash
cargo test -p buzz-push-gateway
cargo test -p buzz-relay --lib push_lease nip11 forge_hop
```
