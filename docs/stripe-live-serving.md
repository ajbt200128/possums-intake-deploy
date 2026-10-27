# Live Stripe setup and serving profiles — local source only

## Authority and evidence boundary

The goal is operator-authorized **real Stripe checkout**, not merely delivery of
Stripe-capable source. The intake authority/configuration record is
[the live activation work record](../../possums-intake/docs/stripe-live-activation.md).
This packet adds two closed configuration profiles and offline tests only. It
performs no credential/environment-value inspection, provider/cloud call, charge,
root rendering, commit/push, image build, measurement, signing, publication or
deployment. The parent independently reviews and qualifies the actual diff.
`tinfoil-config.yml`, `accepted-image.json`, unrelated README changes, historical
templates/profile pins, historical documents and controllers are untouched.
Source availability is not setup completion, live activation or provider/native
runtime acceptance. The latest source-delivery authority is not activation
permission; operator-controlled admission remains separate.

Preserve the existing disk/key, accounts, balances, holds, replay evidence,
credentials, active/previous/draft website publication and tested gateway
contract. No disk allocation/initialization, ledger reset/replacement, restore,
synthetic-to-live relabeling, automatic migration/recovery or mutation replay is
authorized by these profiles. Existing native administration remains selected;
its trusted mutation authority is not a financial restore guarantee. Failed or
unknown operations require passive reconciliation, never a repeat inferred safe
from an error or missing receipt. Do not inspect/adapt historical controllers or
use a disposable sandbox supervisor for this ledger.

## Exact new profiles

Both templates retain CVM/image placeholders, CPU2/memory8192/GPU0, one `ledger`
volume owned by 65532 and mounted `ledger:/state`, UID/GID65532, read-only root,
restart `no` and the existing 128 MiB `/tmp` tmpfs. Both require exactly **four
disks** in the manifest. The shim shape is unchanged; setup starts no application
listener. No secret values belong in YAML, commands, notes or diagnostics.

### `persistent-live-payments-init`

Template: `templates/persistent-live-payments-init-config.yml.in`.
SHA-256: `52009f1d7376260b500761fc7bc2c53142cb360b0ccad11c665ceee5b7816af1`.
It is byte-derived from `persistent-website-init` / `persistent-ledger-upgrade`,
changing only container name and command:

- Container: `intake-persistent-live-payments-init`.
- Command: `['live-payments-init', '--state', '/state/ledger', '--tinfoil-volume', 'ledger']`.
- Entire environment: `OTEL_SDK_DISABLED: 'true'`.
- Only secret-name reference: `LEDGER_VOLUME_KEY_B64`.

This requests **existing-only unlock**, opening an initialized ledger and adding
only absent live payment-v2 tables. It is not disk/ledger initialization. Exact
already-live state is validated by the application; mixed/partial/synthetic state
must refuse without reset or relabeling. Do not use idempotent source behavior as
permission to replay a failed/unknown operation. No listener, healthcheck,
operator flag, admin/operator credentials, Stripe/provider inputs, startup
diagnostic opt-in, payment submission or website publication is added.

### `persistent-live-stripe-serve`

Template: `templates/persistent-live-stripe-serve-config.yml.in`.
SHA-256: `7e71fd63db75a232ec8e8eb5d10b45b437bd66cbeec7c99ff65d15d33e37848e`.
It is an exact clone of `persistent-observed-serve` except for the explicit
`--stripe-live` flag and the four Stripe input bindings below. Container name,
passive healthcheck and all storage/security settings remain unchanged.

Command: `['serve', '--state', '/state/ledger', '--tinfoil-volume', 'ledger', '--operator', '--stripe-live', '--listen', '0.0.0.0:8090']`.

The entire nonsecret environment is:

- `OTEL_SDK_DISABLED: 'false'`
- `INTAKE_METRICS_ENDPOINT: 'https://api.honeycomb.io/v1/metrics'`
- `INTAKE_METRICS_ENVIRONMENT: 'production'`
- `INTAKE_METRICS_SLOT: 'intake-01'`
- `STRIPE_LIVE_TAX_CODE: 'txcd_10103000'`
- `STRIPE_RETURN_ORIGIN: 'https://possums.dev'`

Secret-name references are exactly `LEDGER_VOLUME_KEY_B64`, `LEDGER_ADMIN_KEY`,
`INTAKE_METRICS_HONEYCOMB_API_KEY`, `STRIPE_LIVE_API_KEY` and
`STRIPE_LIVE_WEBHOOK_SECRET`. The first three and all metrics environment entries
are unchanged. Stripe values are runtime-private inputs, not repository values.
Operator-reported project-secret creation is not proof of runtime resolution,
key permissions or signature compatibility; qualify those separately without
reading values into agent/tool history.

The tax code and HTTPS return origin are the explicit operator selections, not
locally inferred legal/tax authority. Tax is added on top of fixed credit
principal; tax never becomes inference credit. Purchase/provider link and sale
share the immutable 20-day checkout-initiation cutoff. Local deletion neither
erases SQLite/WAL/snapshot copies nor deletes Stripe/card-network/tax records.
The flag selects the reviewed live runtime; environment presence alone does not
enable payments. Serve never creates payment schema or resets credentials. It
can perform ordinary supported database/maintenance writes: this is not a
read-only diagnostic phase. Pre-v2 binaries reject v2 payment state; old-binary
rollback after setup is not an approved recovery path.

## Mandatory separate root-render / commit / sign cycles

The profiles cannot be selected only by dispatching a different phase against
one unchanged root. `Live.__init__` calls `config_gate` before source/vendor
boundaries: committed root YAML must exactly match the selected template, image
receipt and verified CVM pin. `committed_files` then requires exact HEAD bytes and
regular file modes for root/receipt, source/tests/workflow and **all** templates.
The workflow phase choices and native syntax-probe literal append setup then
serving in the same order as `PROFILES`; defaults remain disposable/publish false.

Under separately admitted operator control, not as actions of this packet:

1. Coordinate/still the existing writer and qualify the exact private image,
   source, native Linux mount/image behavior and independently matching artifacts.
   Admit the unchanged target/disk/key and existing initialized state. Privately
   resolve only the required setup binding; do not initialize or reset storage.
2. **Setup cycle:** render the root for `persistent-live-payments-init`, review
   and commit that exact root and accepted receipt with the required sources,
   then qualify provenance/crypto and separately sign/publish the exact setup
   phase through existing protected gates. Exact current-main/lightweight-tag,
   owner, first-attempt, absence and no-replay requirements stay intact.
3. After separate execution authority, perform one stopped-service setup on the
   preserved ledger. Require supported passive successful process completion;
   Running/healthy is not setup evidence. Failed/unknown completion stops the
   sequence for passive reconciliation, without retry or a serving admission.
4. **Serving cycle:** independently render the root for
   `persistent-live-stripe-serve`, review and commit the changed root, then
   qualify and separately sign/publish that exact serving phase against its new
   exact public source. Reuse an accepted private image only if its exact source,
   receipt/artifact and all required gates qualify for both commands. The setup
   signature does not authorize serving, and the previous phase's public SHA
   cannot stand in for the new committed root.
5. Re-admit the original target/disk/key, private live input bindings and launch
   gates before one separately authorized serving activation. Preserve uncertain
   outcomes; configuration readiness is not payment/funding evidence. Do not
   create a Checkout, charge, test delivery or replay to diagnose status.

The adapter has distinct locally authored notes for both new phases; historical
note bytes are unchanged. These branches do not change the active workflow's
pinned official action: it owns measurement/publication and does not consume the
adapter's historical manifest/notes command. No source/crypto gate is weakened.

## Qualification still owned by the parent

Offline Python tests cover exact templates/inputs/hashes, historical pins,
committed fixtures, literal phase lists, root/phase substitution and mutation
refusal before boundaries, four-disk manifests and phase-specific note bytes.
The native probe merely gains both phase names; this packet does **not** run it,
fetch modules, build packages or establish actual decoder/native acceptance.
Separate exact-source native Linux qualification, matching builds, provenance,
signing and operator activation remain mandatory.

Local source checks passed: **105 Python discovery tests**, zero failures/errors/
skips, under the already-installed pinned Python 3.14.7 with
`PYTHONDONTWRITEBYTECODE=1 OTEL_SDK_DISABLED=true GOPROXY=off GOSUMDB=off`.
The already-installed pinned Go 1.27.2 `gofmt` check and `git diff --check` passed;
all nine historical templates plus root/receipt matched HEAD bytes. Test output
was discarded transiently and reduced to closed counts/results, not saved as
raw logs or artifacts. Native host history is a separate persistence boundary.

Parent independently reran all **105 offline tests** with zero failures/errors/
skips and verified all nine historical templates, root/receipt bytes and the
preexisting unrelated README digest unchanged. Actual pinned Go decoder
qualification passed all eleven profiles: v0.1.14 rejects persistent bindings
with positive controls; v0.1.16 and runtime v0.1.17 accept the exact owner/binding
with negative controls. The helper reported removal of its owned temporary
module/build cache. These are local syntax results, not native Linux workload,
mount, image or runtime acceptance.

Independent complete read-only source/configuration review found **no material
correctness, privacy, admission or test-coverage blocker** in this packet. It
verified template hashes, historical preservation, exact clone inputs and
unchanged admission gates; it did not execute tests or runtime operations. The
operator separately reconfirmed that other intake deployment writers are paused.
No commit, signed release or activation success is established by these checks.

The intake work record distinguishes authored SDK fixtures from actual provider
acceptance. Actual live key scope/project-secret resolution, nested Product/tax
expansion, canonical captured evidence, hosted guest/minimal-address/Link/3DS
behavior and webhook delivery/signatures remain separate qualification gates.
Operator-selected classification/registration assessment is not independent
legal verification. Active durable customer notices and exact operator-approved
publication/support/refund/public terms remain launch gates; never overwrite
operator Lisp code or mistake embedded notices for publication acceptance.

Privacy contracts: [intake live direction](../../possums-intake/PRIVACY.md#subsequent-live-stripe-payment-direction),
[intake forbidden defaults](../../possums-intake/PRIVACY.md#forbidden-collection-and-defaults),
[intake export/failure rules](../../possums-intake/PRIVACY.md#export-retention-and-failure-behavior),
[gateway data boundaries](../../possums/PRIVACY.md#data-handling-boundaries),
[gateway forbidden telemetry](../../possums/PRIVACY.md#telemetry-permitted-signals-and-forbidden-data)
and [processor/retention controls](../../possums/PRIVACY.md#processors-retention-access-and-shutdown).
Only the existing approved aggregate metrics configuration is retained: no new
error-family enablement, native/payment activity counters, logs, traces, content,
identifiers, amounts, raw exceptions or telemetry retries/spool. No telemetry
delivery is established. Platform-managed disk-key custody, operator access,
provider retention and native host history remain separate boundaries; no
whole-process transience, runtime identity or durability claim follows.

## Published response-budget correction — signing/activation still pending

This latest **accepted-image/root configuration-source packet** supersedes the
older root-untouched/source-only statements above for this published packet
only; those statements remain historical. This packet makes local file changes
only, not a runtime change or exercise of commit/publication/activation authority.

Accepted private main is `b8d9ce20661b70170f451be3978ecd44e51df5da` (normal
PR14 merge). Source CI **40451722504**, attempt 1, passed all ten steps; fresh
native qualification **40452535012**, attempt 1, passed source/A/B/compare with
distinct builders. Parent independently verified actual A/B report ZIPs, file
hashes/inventories and the supported build gate's mandatory native, synthetic and
startup cases. These are fresh builds of this source, not reuse of an older
candidate's evidence merely because the reproduced image digest is identical.
Browser inside the image remains **`not_run`**; previous-release compatibility
remains **`unknown`**.

The published image is
`sha256:c815d18028e35970ef16d1a9b41287360d87bd04bf1c792efc806588e305f7f0`;
archive SHA-256 is
`605466bc4c610c346ed4c30aca662d8cfabfd50db0fd948a3b2b6290bf0b3a37`.
Read-only CI **40453053512** passed five validation steps with publication
skipped, zero publication steps and zero artifacts. Actual protected publication
**40453310204**, attempt 1, passed five validation and eleven publication steps,
including actual archive/full-image/raw-registry-digest checks, owned auth
cleanup and receipt publication. Parent independently verified the public
package and its complete twelve-version, one-page inventory: baseline retained
and exactly one current-source-tag version matched this image. The operator
waived the **entire package-to-source association check**, including repository
ID/name/private projection; no package repository link was inspected, verified
or required. Private source identity/current-main, native build, signature,
image/archive digest and disk/activation guards remain mandatory. No permission
or visibility-setting change is part of this packet.

`accepted-image.json` copies the actual parent-verified canonical three-field
receipt (`archiveSHA`, `imageDigest`, `publicSourceSHA`) byte for byte, with no
extra fields. File SHA-256:
`e5bb1996194c17cc0a4667a024efc07649e4ad05ac66670129ddc402f1fea08e`.
The parent verified the actual receipt ZIP and extracted file; the full image
archive was **not downloaded/rehashed locally**. Protected CI's actual archive
gate passed; that is not a claim of a local full-archive hash.

Root is freshly rendered from the unchanged
`persistent-live-stripe-serve-config.yml.in` template hash
`7e71fd63db75a232ec8e8eb5d10b45b437bd66cbeec7c99ff65d15d33e37848e`,
substituting only CVM **0.14.14** and the accepted image digest. New root SHA-256:
`8380f9282262d07ae33dbcf63d56e9b25aa6dc22ce1711df0821534d56dd6f7c`.
Against the preceding root, only its image-digest line changes. All templates,
helper/source/tests/workflows/controllers and preexisting README/cache bytes
remain unchanged. Existing approved four metric families/configuration and
secret-name references remain unchanged; no telemetry expansion or export is
performed by this packet.

The application correction gives Go's actual serving HTTP server a finite
**30-second `WriteTimeout`**, with response headroom beyond the existing provider
windows, and preserves the four known live-context/live-URL/tax/tax-completion
constraints through the website's closed diagnostic projection. This does not
add blanket interception of uncaught SDK timeouts or guarantee response delivery.
Existing SDK timeout behavior, provider timeouts and zero-retry behavior,
accounting, authentication and privacy rules are unchanged. The original HTTP
502's cause and provider-creation outcome remain **unknown**, not proven timeout
or no-effect evidence.

Before any activation, require parent independent review, exact-current-main
public source, a fresh immutable protected signed release, actual downloaded-byte
and supported cryptographic acceptance, and **one NEW separately reviewed,
exclusive one-use existing-only replacement controller**. Preserve the v25
baseline/state/site and the consumed v24/v25 activation receipts; neither old
receipt authorizes replay. Re-admit the same **8,000,000,000-byte existing disk**,
key, instance/host/domain, CPU2/memory8192/GPU0, CC true/debug false and current
secret names. No new resources, resize, reset, initialization, restore, credential
or account mutation, gateway work or automatic mutation retry is authorized here.
Ordinary serve may perform supported database/maintenance writes: it is **not
read-only**. Platform-managed key custody/decryption, beta volume rollback
limits, native/platform retention and unknown financial preservation remain
explicit boundaries; no safe financial restore or preservation receipt follows.

The original unpaid USD 5 initiation is unknown and **must remain unreplayed**.
Only after a qualified replacement may the parent conduct the separately
authorized **one distinct unpaid USD 5 initiation**; no card entry, Pay submission
or payment. No browser, hosted Checkout, funding or fresh runtime-attestation
acceptance is established by this packet. Runtime attestation remains unverified;
the operator accepted the current platform-plus-WebPKI trust boundary only.
