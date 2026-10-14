# Possums intake: disposable synthetic deployment

This public repository is reserved for the measured Tinfoil configuration and release evidence of **one disposable synthetic-only ledger instance**. The application source and container image remain private. Public configuration and release measurements do not make private application code independently inspectable.

## Authorized scope

- CPU-only Tinfoil instance: **2 CPUs / 8192 MB**.
- **No persistent volume**: fresh temporary fake accounting state on each start; restarts lose it.
- Genuine restricted PocketBase operator dashboard and authenticated custom accounting endpoints.
- No gateway integration, real funds, payment data, customer data or live telemetry export.
- No production activation, automatic updates or inference replay.

## Release admission

A repository existing is not a deployed service. Before deployment, require exact-current-main successful application checks, independently matching fresh native Linux image builds, actual image qualification, digest-preserving private registry publication, and the public immutable configuration's successful measured and signed release. Keep release automation explicitly gated. Do not deploy a placeholder image digest, an unpublished tag, or an unverified release.

`tinfoil-config.yml` now pins the operator-accepted synthetic image and verified public CVM manifest. No measured release or instance exists yet; configuration and this README are not deployment evidence.

## Explicit synthetic release authorization

`templates/synthetic-config.yml.in` and `scripts/synthetic-release.py` prepare the supported vendor measurement flow. The operator authorized synthetic-only activation after the image copy. The dispatch-only workflow still defaults publication authorization to false and requires exact owner, source, immutable tag and first-attempt evidence. Production delivery remains disabled.

The public workflow cannot inspect private application CI. Its committed `accepted-image.json` must be an operator-trusted handoff of the accepted publication receipt's exact three fields: `publicSourceSHA`, `imageDigest`, and `archiveSHA`. Recheck the private source, independent native Linux builds, actual image fixtures and private registry evidence before committing those pins and creating an immutable public tag.

The native Linux A/B jobs and actual image fixtures passed. The private image copy completed, but its workflow's post-copy check failed with an unknown cause. Passive owner-side package reads independently confirmed private visibility, source-repository linkage and the matching tagged manifest identifier. The operator explicitly accepted the published image on that evidence; a raw registry-manifest read and actual runtime pull remain unqualified. No copy was replayed. This scoped trust decision does not qualify runtime identity, transport or durability.

The adapter rejects malformed/non-standard JSON, bounds subprocess output and cleanup, keeps credentials in process environment rather than arguments, and preserves known publication evidence through later failures. Publication is one attempt with passive reconciliation only: no retry, overwrite, delete or rollback. The parent must verify the actual completed signed run and downloaded asset hashes before separately admitting the one instance. Offline fixtures do not qualify vendor measurement, signed releases or runtime behavior.

Run the offline suite in the pinned application environment:

`nix shell --offline --inputs-from ../possums-intake nixpkgs#python3 --command env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_*.py'`

## Measurement output boundary (unqualified Linux hypothesis)

The first `v0.1.0` measurement attempt failed with a closed cause-unknown diagnostic; signing/publication were skipped. No raw vendor output was retained and this patch does not establish its cause. Keep that tag unchanged; no rerun or copy retry is authorized.

The adapter now grants only its host-owned output group access (`0770` plus numeric `--group-add`), restoring the mode after restrictive umasks. Vendor default root/HOME, dropped capabilities, no-new-privileges, read-only root and tmpfs mounts remain unchanged. Offline tests qualify arguments and host permissions, not Linux DAC or vendor compatibility. The local daemon reported Linux, but the pinned image was not confirmed cached with a compatible root user; no container probe or pull was performed.

Before a separately approved new immutable release attempt, run this explicit credential-free DAC fixture on the GitHub-hosted Linux runner **with the same pinned SDK image already cached**. It uses only the existing local Unix socket, refuses missing images/non-root defaults/translated mount ownership, never pulls, disables networking and overrides the SDK entrypoint. Root with zero effective capabilities must fail to write `0700`, then succeed with `0770` and the host supplementary group. JSON reports only closed results; this is not measurement, signing, publication or proof of the previous failure's cause.

`env PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_synthetic_release.py --linux-output-probe`

No token or signing permission is needed. Linux kernel reproduction and actual pinned vendor invocation remain open; the fixture does not authorize either a workflow dispatch or another measurement attempt.

## Secrets and access

Grant the Tinfoil GitHub App access to this repository. Keep credential values outside Git, configuration, command arguments and chat. Use dedicated synthetic-only operator/accounting credentials and narrowly scoped private-image credentials through supported private setup channels. Do not reuse gateway credentials.

Tinfoil-managed secrets are accessible to platform infrastructure during deployment. This disposable test does not qualify customer-controlled encrypted storage, verified gateway-to-ledger transport, production durability or financial restore.
