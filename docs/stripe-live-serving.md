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
