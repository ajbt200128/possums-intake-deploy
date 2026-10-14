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

The retained `tinfoil-config.yml` and `accepted-image.json` pin the historical operator-accepted synthetic image and CVM **0.14.7**, not the new diagnostic candidate below. `v0.1.1` completed measurement, signing and publication through the historical adapter. Tinfoil rejected that workflow because it did not use its official build action. The official-action `v0.1.2` release also passed independent completed-run, exact-source/signature/config and downloaded-asset verification. The operator subsequently created one intake instance with `possums.dev` attached. Passive status reported it failed; the dashboard established HTTP 404 at legacy CVM image download. Configuration, signed publication and domain attachment are not running-service evidence.

## Planned diagnostic candidate: CVM 0.14.14

**Template/helper adaptation only; no new image handoff, publication or runtime qualification.** The candidate accepts only plain `cvm-version: 0.14.14`, rejecting old versions, release candidates, 0.15, digest-qualified values and filenames. It adds exactly `LEDGER_SYNTHETIC_STARTUP_DIAGNOSTICS: 'true'` with telemetry still disabled and an exec healthcheck: `['CMD', '/proc/1/exe', 'synthetic-healthcheck']`, interval `10s`, timeout `3s`, retries `1`, start period `5s`. That single bootstrap grace is not an init/retry/replay mechanism. UID/GID 65532, read-only root, 128 MB tmpfs, three secret names and CPU2/memory8192/GPU0 remain unchanged; no volume, debug, port, DNS, network or privilege additions.

Parent-provided evidence: supported `gh attestation verify` enforced the source/tag and `.github/workflows/release.yml` signer for **both** public `tinfoilsh/cvmimage` v0.14.14 manifest and checksums, source `ad1a411ed483ac249237bbaf11376dd1c2e9cc30`. The locally inspected manifest bytes hash to SHA-256 `2036e7dee124eb7feb0b3741a382be06aa85a7c4685587becd18f6974f8c8d28`; the helper now requires its exact version/root/kernel/initrd/raw values, not merely digest-shaped strings. This packet did not repeat remote verification. Template SHA-256 is `3ed591c27450d56887aabdb74ae466154c0da12d75b973ac20fd8dadb46b78e5`.

Tagged-source compatibility evidence: the parent-downloaded `containers.go` from [the exact CVM source](https://github.com/tinfoilsh/cvmimage/tree/ad1a411ed483ac249237bbaf11376dd1c2e9cc30) maps all five healthcheck fields directly into Moby `container.HealthConfig`, polls boot health every five seconds and exposes the last unhealthy healthcheck log in boot detail. Its `go.mod` pins `tinfoil-config` v0.1.17, Moby API v1.55.0 and client v0.5.1. The locally inspected shared config types support these exact YAML fields; validation requires a manifest digest only from v0.15.0, so plain 0.14.14 is supported. The pinned measurement SDK cmdline, VM shape (three base disks, **not** volumes), v0.0.4 firmware hash, exact config/image binding and signature/run/source/archive/nonreplay gates are unchanged. A new manifest mismatch must stop acceptance, not weaken these requirements.

Safe capture is limited by the [intake temporary startup exception](../possums-intake/PRIVACY.md#temporary-synthetic-startup-diagnostic-exception) and [local startup evidence](../possums-intake/docs/synthetic-startup.md#temporary-startup-healthcheck-diagnostics), plus the gateway's [forbidden telemetry](../possums/PRIVACY.md#telemetry-permitted-signals-and-forbidden-data) and [processor/retention boundaries](../possums/PRIVACY.md#processors-retention-access-and-shutdown). Only the bounded, owner-only replaceable fixed startup record and closed five-field healthcheck projection are intended for deliberate native health capture; no raw errors, credentials, request collection or export. The pre-bind failed-start hold is bounded to 120 seconds and joins on SIGTERM; healthcheck/status remain passive and cannot initialize the ledger or retry work. Parent-reported Linux ARM64 image healthcheck/negative/SIGTERM checks are local evidence, **not native AMD64 or Tinfoil proof**. Native startup retrieval/history, platform access/retention and actual safe capture remain unqualified. Application health cannot repair a certificate failure that precedes application startup; readiness/provenance do not establish runtime attestation verification.

The root config and receipt deliberately remain untouched and cannot pass the new candidate guard. Parent must first accept a **new native AMD64 image publication receipt**, render both handoff files from that evidence, independently review, and admit a fresh immutable release/tag. Preserve historical tags/releases. Any later separately authorized live attempt remains limited to the **one existing** 2-CPU/8192-MB no-volume/no-debug synthetic instance, a ten-minute live cap, no DNS changes, no production diagnostic activation and no automatic deployment retry. Nothing in this offline patch initiates or authorizes those operations.

## Explicit synthetic release authorization

`templates/synthetic-config.yml.in` and `scripts/synthetic-release.py` guard the operator handoff. The active workflow uses the genuine official `tinfoilsh/measure-image-action@f2ec2fdf4510459730f0a5158c5817f5361e9461` (v0.13.2), matching the sibling Possums publication workflow. That action performs measurement, attestation and the sole release creation; the adapter's historical measure/manifest/publish commands are not active workflow steps. The operator authorized synthetic-only activation after the image copy. The dispatch-only workflow still defaults publication authorization to false and requires exact owner, source, immutable tag and first-attempt evidence. Production delivery remains disabled.

The public workflow cannot inspect private application CI. Its committed `accepted-image.json` must be an operator-trusted handoff of the accepted publication receipt's exact three fields: `publicSourceSHA`, `imageDigest`, and `archiveSHA`. Recheck the private source, independent native Linux builds, actual image fixtures and private registry evidence before committing those pins and creating an immutable public tag.

The native Linux A/B jobs and actual image fixtures passed. The private image copy completed, but its workflow's post-copy check failed with an unknown cause. Passive owner-side package reads independently confirmed private visibility, source-repository linkage and the matching tagged manifest identifier. The operator explicitly accepted the published image on that evidence; a raw registry-manifest read and actual runtime pull remain unqualified. No copy was replayed. This scoped trust decision does not qualify runtime identity, transport or durability.

The operator explicitly selected the sibling's CI trust boundary for the official action: an ephemeral repository-scoped `GITHUB_TOKEN` on a GitHub-hosted runner. The pinned action interpolates that token into Docker arguments and its inner checkout uses default credential persistence; the outer `persist-credentials: false` does not override it. This scoped CI exception does not permit runtime/admin/private-registry credentials in arguments or artifacts, reuse gateway secrets, or establish that vendor output is content-free. Vendor steps also have opaque diagnostics and release-absence handling; our typed public absence guard runs first and rejects anything except an observed HTTP 404. No fake or skipped action is used.

One explicit dispatch on a fresh immutable tag is admitted; no rerun, retry, overwrite, delete or rollback after uncertain effects. Preserve `v0.1.0`, `v0.1.1` and `v0.1.2`; the CVM syntax correction requires a new reviewed source/tag. The parent must independently verify the actual completed signed run, exact tag/source/certificate, manifest/config and downloaded asset hashes before deployment. Official-action publication occurs before this post-run acceptance: failed acceptance does not undo an observed release. Its default `target_commitish=main` is metadata, not source authority; the tag, run and signature must still match the exact reviewed SHA. Offline fixtures do not qualify vendor execution or runtime behavior.

Applicable privacy authority: [intake scope](../possums-intake/PRIVACY.md#authority-and-scope), [forbidden defaults](../possums-intake/PRIVACY.md#forbidden-collection-and-defaults), and the sibling's [data boundaries](../possums/PRIVACY.md#data-handling-boundaries). This CI-only decision changes no accounting, runtime collection, storage or one-instance limits.

Run the offline suite with the already-cached pinned Python 3.14.7 (no installation/bootstrap):

`env PYTHONDONTWRITEBYTECODE=1 /nix/store/0kcws5blwbdyxqxjd1w8hjipz61xny3k-python3-3.14.7/bin/python3 -m unittest discover -s scripts -p 'test_*.py'`

Candidate offline evidence: **70 tests passed** with cached Python 3.14.7; `git diff --check` passed. Coverage includes exact template/opt-in/exec/grace bytes, every changed CVM hash (including wrong root with matching cmdline), wrong versions, exact config/image and source/archive handoff, committed bytes, owner/current-main/lightweight-tag/attempt-one, verifier arguments, signed manifest/run/artifact shape, passive status and nonreplay. Synthetic fixtures are not signatures, vendor execution, native AMD64 acceptance or runtime evidence.

## Dashboard workflow naming and sibling comparison

The genuine publisher is now `.github/workflows/tinfoil-release.yml`, named **Tinfoil Release**, matching the exact missing filename reported by the dashboard. The initial `.yaml` rename misread the screenshot's extension and was corrected without publication or deployment. Its guards, inputs, pinned official action and permissions are unchanged. Future run/certificate verification requires this exact new workflow path; there is no old-path fallback. Historical releases through `v0.1.3` retain their original `tinfoil-release-publish.yml` signer identity and must be verified using their immutable historical source. Renaming does not rewrite releases, fix registry authorization, or establish dashboard detection until read back.

The sibling deliberately retains two workflows: `tinfoil-release.yml` dispatches its private image/reproducibility pipeline, and `tinfoil-release-publish.yml` measures/signs/publishes. Intake has no need for that extra dispatcher: the public config repository uses an explicitly reviewed private-image handoff and one manual publisher. Do not copy its automatic main pipeline or private CI assumptions into this public repository.

Other relevant differences are intentional or remain qualification gaps:

- Same official measurement, checkout and attestation pins; intake explicitly declines latest promotion. Intake's serialized manual first-attempt/current-main/owner gates and bounded job are retained.
- Sibling publication also grants `packages: write` and `actions: read` and fetches full Git history for its private build correlation. Intake does not copy those permissions or claim public CI can inspect private application runs. These CI permissions do not grant Tinfoil runtime access to the private image.
- At the naming change, sibling selected CVM **0.14.12** and intake retained independently verified **0.14.7**. That rename was not a CVM upgrade or evidence that all newer platform behavior was qualified; the later candidate is scoped above.
- Sibling config has gateway-specific egress, attestation socket and executable healthcheck; historical intake had no explicit healthcheck. Intake still has no inference/telemetry egress or socket consumer and a different port/command/user/scratch profile. The candidate's app-specific healthcheck does not copy gateway commands or secrets; runtime readiness remains unqualified.
- Both use CPU2/memory8192, digest-bound images, read-only roots, tmpfs and runtime secret names. Application image, secret names, network needs and accounting/storage boundaries are separate.

The dashboard subsequently reported a private-image authorization refusal for `v0.1.3`; ledger startup was not established. Correct registry access through private setup and obtain explicit authorization before another deployment. No release dispatch, registry mutation, restart, deploy or additional resource is part of this naming change.

## Historical CVM 0.14.7 syntax correction and existing-instance deployment

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
