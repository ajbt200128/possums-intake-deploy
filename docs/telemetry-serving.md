# Operational serving with approved aggregate metrics

## Selected profile; activation is separate

`persistent-observed-serve` is the canonical profile for the next and future
operational serving deployments, after the parent admits the exact source,
image, release and target. This local source/test packet does not publish an
image, measure/sign a release, create a secret, deploy, start the configured
service or export metrics. `accepted-image.json` and `tinfoil-config.yml` are not
changed here. Do not treat this profile's existence as activation evidence.

All eight historical profile entries and their template bytes/hashes remain
frozen and telemetry-off. In particular, historical `persistent-serve` and
`persistent-diagnostic-serve` are not the default choice for future operational
serving. Never accidentally select bootstrap, ledger init/replace/upgrade or
website setup as a serving update. Init, disposable and local qualification
remain telemetry-off. The workflow's `disposable` choice default and false
publication default are intentionally unchanged: operational selection must be
explicit, not an automatic workflow activation.

The new template SHA-256 is
`621d71a185b11f293f1b1a425172102448f57314a337ee2cceb24391ce500ce7`.
It is an exact structural clone of frozen `persistent-serve`, changing only the
closed environment block and adding one secret-name reference. It keeps CVM
0.14.14, CPU2/memory8192/GPU0, one `ledger` volume owned by 65532 and mounted at
`/state`, UID/GID65532, read-only root, restart `no`, 128 MiB tmpfs and the same
passive healthcheck. Its four-disk manifest requirement remains exact.
The ordinary command is `serve --state /state/ledger --tinfoil-volume ledger --operator --listen 0.0.0.0:8090`.
It requests no initialization, schema setup, reset, credential creation/upsert or
Stripe activation. Ordinary supported database/maintenance writes can occur;
this is not a read-only inspection or a durability/rollback/old-release
compatibility guarantee.

## Closed deployment inputs and private key prerequisite

Exactly four nonsecret environment entries are selected:

- `OTEL_SDK_DISABLED: 'false'`
- `INTAKE_METRICS_ENDPOINT: 'https://api.honeycomb.io/v1/metrics'`
- `INTAKE_METRICS_ENVIRONMENT: 'production'`
- `INTAKE_METRICS_SLOT: 'intake-01'`

The secret-name references are exactly `LEDGER_VOLUME_KEY_B64`,
`LEDGER_ADMIN_KEY` and the new `INTAKE_METRICS_HONEYCOMB_API_KEY`. No secret value,
generic `OTEL_*` input other than the switch, raw header, dataset setting or key
value belongs in YAML. Do not reuse a gateway key. The application image's
`OTEL_SDK_DISABLED=true` default remains unchanged; this explicit container
environment overrides it only for the selected serving deployment.

The operator reports privately creating the dedicated Honeycomb ingestion key
under `INTAKE_METRICS_HONEYCOMB_API_KEY`. That report is not credential evidence:
the latest parent name-only preflight has not established a unique binding.
Parent must verify secret-name metadata only before activation; this source
refinement performs no platform/secret inspection and establishes no permissions
or destination access. Never provide values in chat, arguments,
repositories, diagnostics or raw headers; agents must not create/read the secret.
Runtime validation accepts only a bounded 16–128-character ingestion key in its
closed character set. Metadata presence alone does not qualify permissions or
destination access.

## Runtime scope and privacy limits

Use the existing runtime implementation unchanged. These four production
**gauges only** are eligible for release:

- `possums.intake.http.requests`: complete non-overlapping five-minute custom
  accounting terminal counts by closed status class.
- `possums.intake.http.latency.bucket`: the same complete population in exclusive
  coarse latency bins, not individual latency samples or overlapping histograms.
- `possums.intake.process.cpu`: complete one-minute process CPU-core means.
- `possums.intake.process.rss`: complete one-minute approximate process RSS means.

CPU/RSS require six valid ten-second readings; they are not host/enclave capacity
measurements. The resource fields are fixed service name, deployment environment
and `possums.infrastructure.slot=intake-01`: an infrastructure slot, not an
account/customer/host identifier. Sparse windows still permit timing correlation;
aggregation is minimization, not anonymity.

Production `possums.intake.interface.errors` stays statically **off** pending
boundary/ownership coverage qualification; do not enable it or claim export.
No native activity/success, payment/financial counters, logs, traces, content,
identifiers or amounts are added. Native SDK logging and AuthAlert login-origin
recording remain off. No Collector, automatic resource discovery or telemetry
retry/spool is added. Missing/invalid configuration or SDK construction failure
disables only telemetry, never accounting. Incomplete/invalid/lost data is
unavailable, not healthy zero; configuration/health does not guarantee delivery.

Applicable contracts: [intake metrics scope](../../possums-intake/PRIVACY.md#first-telemetry-scope-metrics-only),
[intake forbidden defaults](../../possums-intake/PRIVACY.md#forbidden-collection-and-defaults),
[intake export/failure rules](../../possums-intake/PRIVACY.md#export-retention-and-failure-behavior),
[gateway forbidden telemetry](../../possums/PRIVACY.md#telemetry-permitted-signals-and-forbidden-data),
[gateway aggregation](../../possums/PRIVACY.md#aggregation-is-necessary-not-sufficient)
and [processor/retention controls](../../possums/PRIVACY.md#processors-retention-access-and-shutdown).
Honeycomb is outside the enclave. Provider-default retention is accepted, not an
exact-day guarantee. Actual intake key permissions, destination, effective
retention and delivery remain unqualified; platform/network/history retention
is a separate boundary. Local template tests are not synthetic OTLP wire or
runtime evidence; the parent must bind existing private source/wire/runtime
privacy qualification to the exact candidate image before activation.

## Local qualification and remaining gates

Run Python discovery only with the existing pinned Python and
`PYTHONDONTWRITEBYTECODE=1 OTEL_SDK_DISABLED=true GOPROXY=off GOSUMDB=off`.
The default suite mocks provider/vendor boundaries; it never starts the actual
configured service. It checks exact clone/hash/rendering, frozen historical
entries, closed env/secret names, tamper refusal, phase substitution, receipt and
four-disk/source/crypto/once-only guards, and phase-specific release notes.
Historical release-note bytes remain unchanged; new notes state configuration
opt-in without claiming telemetry delivery. The active workflow still uses the
pinned official action, not the adapter's historical manifest/notes command.

The existing `tests/vendor-config/main.go` phase loop now includes all nine
profiles directly, including `persistent-observed-serve` alongside (not replacing)
both historical serving profiles. The normal `qualify()` pipeline in
`scripts/qualify-vendor-config.py` therefore covers the new template without a
special driver, fixture substitution or module-cache copying. Every existing
`Decode(WorkloadMode)` condition is preserved: synthetic baseline acceptance,
persistent-binding-removal positive controls, old v0.1.14 binding rejection,
action v0.1.16 and exact-CVM runtime v0.1.17 acceptance, exact volume/OwnerIDs/mount
checks and unknown-field/incorrect-binding-field/invalid-owner negatives.
This is syntax qualification only, not a service/exporter execution or inspection
of the SDK's decoded environment representation.

After separate operator approval for bounded checksum-pinned public dependency
downloads, the parent ran the existing qualifier with already-installed Go
1.27.2. All nine profiles passed the expected matrix: v0.1.14 persistent-binding
rejection and v0.1.16/v0.1.17 acceptance. Owned temporary cache removal was
confirmed; no toolchain installation, measurement, service or exporter execution
occurred. Neither manual workflow invokes this qualifier automatically; future
template changes still require explicit native qualification.

The earlier special adapter stopped before Go execution on unavailable cached
modules; that established neither a pinned toolchain failure nor acceptance.
The adapter, its CLI mode and cache-specific diagnostic/tests were removed.
The parent also confirmed that the three public module sources were absent from
the pinned Go cache before requesting the separate download approval. This was
an explicitly authorized qualification run, not a silent network fallback for
the offline application checks.

Local refinement evidence: **102 public Python tests passed** under existing
pinned Python 3.14.7 with the offline/test-process switches above. This includes a
small source regression requiring the native phase literal to contain all nine
profiles; it does not run Go or substitute for native parser acceptance. The
existing pinned Go 1.27.2 scoped `gofmt` check and diff whitespace check passed.
No runtime/export evidence follows from these checks; unrelated historical
LSP findings are outside this refinement.

Parent retains publication/signing/deployment authority after exact source/native
matching-build/provenance/privacy/crypto/target/private-secret gates. Unknown
mutation outcomes require passive reconciliation, never automatic replay. Real
Stripe charges remain off: Stripe keys were also absent at parent preflight;
separate SDK/provider/legal/public tax/pricing/refund/retention terms and active
publication gates remain. Gateway integration was operator-reported tested;
this packet neither edits nor retests it. No new resource, reset, inference,
actual export, financial rollback or historical-release compatibility follows.
