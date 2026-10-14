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

`tinfoil-config.yml` now pins the operator-accepted synthetic image and verified public CVM manifest. `v0.1.1` completed measurement, signing and publication through the historical adapter. Tinfoil rejected that workflow because it did not use its official build action. The official-action `v0.1.2` release also passed independent completed-run, exact-source/signature/config and downloaded-asset verification. The operator subsequently created one intake instance with `possums.dev` attached. Passive status reported it failed; the dashboard established HTTP 404 at legacy CVM image download. Configuration, signed publication and domain attachment are not running-service evidence.

## Explicit synthetic release authorization

`templates/synthetic-config.yml.in` and `scripts/synthetic-release.py` guard the operator handoff. The active workflow uses the genuine official `tinfoilsh/measure-image-action@f2ec2fdf4510459730f0a5158c5817f5361e9461` (v0.13.2), matching the sibling Possums publication workflow. That action performs measurement, attestation and the sole release creation; the adapter's historical measure/manifest/publish commands are not active workflow steps. The operator authorized synthetic-only activation after the image copy. The dispatch-only workflow still defaults publication authorization to false and requires exact owner, source, immutable tag and first-attempt evidence. Production delivery remains disabled.

The public workflow cannot inspect private application CI. Its committed `accepted-image.json` must be an operator-trusted handoff of the accepted publication receipt's exact three fields: `publicSourceSHA`, `imageDigest`, and `archiveSHA`. Recheck the private source, independent native Linux builds, actual image fixtures and private registry evidence before committing those pins and creating an immutable public tag.

The native Linux A/B jobs and actual image fixtures passed. The private image copy completed, but its workflow's post-copy check failed with an unknown cause. Passive owner-side package reads independently confirmed private visibility, source-repository linkage and the matching tagged manifest identifier. The operator explicitly accepted the published image on that evidence; a raw registry-manifest read and actual runtime pull remain unqualified. No copy was replayed. This scoped trust decision does not qualify runtime identity, transport or durability.

The operator explicitly selected the sibling's CI trust boundary for the official action: an ephemeral repository-scoped `GITHUB_TOKEN` on a GitHub-hosted runner. The pinned action interpolates that token into Docker arguments and its inner checkout uses default credential persistence; the outer `persist-credentials: false` does not override it. This scoped CI exception does not permit runtime/admin/private-registry credentials in arguments or artifacts, reuse gateway secrets, or establish that vendor output is content-free. Vendor steps also have opaque diagnostics and release-absence handling; our typed public absence guard runs first and rejects anything except an observed HTTP 404. No fake or skipped action is used.

One explicit dispatch on a fresh immutable tag is admitted; no rerun, retry, overwrite, delete or rollback after uncertain effects. Preserve `v0.1.0`, `v0.1.1` and `v0.1.2`; the CVM syntax correction requires a new reviewed source/tag. The parent must independently verify the actual completed signed run, exact tag/source/certificate, manifest/config and downloaded asset hashes before deployment. Official-action publication occurs before this post-run acceptance: failed acceptance does not undo an observed release. Its default `target_commitish=main` is metadata, not source authority; the tag, run and signature must still match the exact reviewed SHA. Offline fixtures do not qualify vendor execution or runtime behavior.

Applicable privacy authority: [intake scope](../possums-intake/PRIVACY.md#authority-and-scope), [forbidden defaults](../possums-intake/PRIVACY.md#forbidden-collection-and-defaults), and the sibling's [data boundaries](../possums/PRIVACY.md#data-handling-boundaries). This CI-only decision changes no accounting, runtime collection, storage or one-instance limits.

Run the offline suite in the pinned application environment:

`nix shell --offline --inputs-from ../possums-intake nixpkgs#python3 --command env PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s scripts -p 'test_*.py'`

## CVM syntax correction and existing-instance deployment

The sibling Possums configuration uses a plain version in `cvm-version`. Intake's digest-qualified `0.14.7@sha256:…` measured successfully but the legacy deployment path used it literally in a raw-image filename and returned HTTP 404. The correction retains version **0.14.7**, changing only to `cvm-version: 0.14.7`; image, CPU/memory/GPU, secrets, scratch, egress and telemetry settings are unchanged. Negative tests reject the former digest-qualified value and unsupported versions.

The CVM public manifest remains independently bound to SHA-256 `12177f4b55676a58eeb11051ed1087fc0c3cef10fc465c0fdc5ee51ec3b464b7` and must pass supported `gh attestation verify` for `tinfoilsh/cvmimage`. Compare the new signed deployment's CVM hashes to that verified public manifest; the digest belongs in acceptance evidence, not the version field. Successful measurement does not establish runtime image availability.

Reuse the sibling's qualified CLI **0.19.0** route for the existing failed instance: `container deploy`, not CLI 0.18.9's obsolete `relaunch` route. Reverify the reused temporary binary against its published checksum; no global installation change. One operator-authorized deploy with the new exact tag, `--mark-latest false`, `--debug false` and the existing domain/secret bindings is permitted after release acceptance. No create, extra instance, volume, gateway update, deployment replay or production activation. Preserve observed acceptance through later startup failure and reconcile passively before any further mutation.

## Historical adapter measurement output boundary

The first `v0.1.0` measurement attempt failed with a closed cause-unknown diagnostic; signing/publication were skipped. No raw vendor output was retained and this patch does not establish its cause. Keep that tag unchanged; no rerun or copy retry is authorized.

The adapter now grants only its host-owned output group access (`0770` plus numeric `--group-add`), restoring the mode after restrictive umasks. Vendor default root/HOME, dropped capabilities, no-new-privileges, read-only root and tmpfs mounts remain unchanged. Offline tests qualify arguments and host permissions, not Linux DAC or vendor compatibility. The later GitHub-hosted Linux DAC fixture passed: root with no effective capabilities could not write host-owned `0700`, but could write `0770` with the supplementary group. That qualifies the boundary, not the original failure cause. The subsequent `v0.1.1` adapter measurement succeeded.

Before a separately approved new immutable release attempt, run this explicit credential-free DAC fixture on the GitHub-hosted Linux runner **with the same pinned SDK image already cached**. It uses only the existing local Unix socket, refuses missing images/non-root defaults/translated mount ownership, never pulls, disables networking and overrides the SDK entrypoint. Root with zero effective capabilities must fail to write `0700`, then succeed with `0770` and the host supplementary group. JSON reports only closed results; this is not measurement, signing, publication or proof of the previous failure's cause.

`env PYTHONDONTWRITEBYTECODE=1 python3 scripts/test_synthetic_release.py --linux-output-probe`

No token or signing permission is needed. This retained historical adapter fixture does not qualify the official action, whose mount/output handling differs, or authorize another workflow dispatch.

## Secrets and access

Grant the Tinfoil GitHub App access to this repository. Keep runtime, admin and private-registry credential values outside Git, configuration, command arguments and chat. The sole CI-token exception for the pinned official action is disclosed above. Use dedicated synthetic-only operator/accounting credentials and narrowly scoped private-image credentials through supported private setup channels. Do not reuse gateway credentials.

Tinfoil-managed secrets are accessible to platform infrastructure during deployment. This disposable test does not qualify customer-controlled encrypted storage, verified gateway-to-ledger transport, production durability or financial restore.
