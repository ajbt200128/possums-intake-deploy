# Live Stripe serving: explicit public-address egress

## Source finding, not a provider-outcome finding

The parent-qualified source-only fixture used the actual supported
`github.com/tinfoilsh/tinfoil-config v0.1.17` decoder in `WorkloadMode`. Its ten
cases passed. The selected signed configuration (SHA-256
`8380f9282262d07ae33dbcf63d56e9b25aa6dc22ce1711df0821534d56dd6f7c`)
decoded to **zero declared networks and zero attached container networks**, with
the sole container selected as shim upstream. Declaring an open network without
attaching it still supplied no container egress; undeclared attachments were
refused. These are existing parent-produced local decoder results inspected for
this packet, not a new execution or runtime forwarding measurement.

The parent associated public CVM tag **v0.14.14** with source
[`ad1a411ed483ac249237bbaf11376dd1c2e9cc30`](https://github.com/tinfoilsh/cvmimage/tree/ad1a411ed483ac249237bbaf11376dd1c2e9cc30).
Its container attachment ordering selects an attached nonclosed network first
with gateway priority 100; the closed shim network has priority 0. There is no
ordinary-network fallback for a shim-only container. Website health can therefore
coexist with absent Stripe egress. This establishes a **source egress omission**,
not the cause of either original request failure, provider acceptance, a charge,
a refund or any other financial outcome. Public tag/source association is not
fresh runtime attestation.

The two existing purchase attempts remain unknown and **must never be replayed**.
The prior v0.1.26 replacement allowance is consumed and must never be reused. A
future activation requires fresh exact-source signed-release admission and its
own new activation receipt; no prior replacement or unknown purchase result is
permission to repeat work. This packet performs local source/test/doc changes
only. The parent owns review, publication/signing and any separately admitted
single replacement.

## Small authorized configuration delta

`templates/persistent-live-stripe-egress-serve-config.yml.in` is an exact clone of
the frozen live-Stripe serving template with only:

- Root `networks` containing one `public-egress` network with `egress: open`, after
  `gpus: 0` so `cvm-version` remains the first field.
- The sole existing container's `networks: [public-egress]` attachment.

Template SHA-256:
`f135d7d6cafa2ddda365a9258a75a380861e6dc2a7b7b72a21a6051627eb56ef`.
`tinfoil-config.yml` renders these exact bytes with the unchanged accepted-image
receipt and CVM **0.14.14**. The accepted image, archive and application source
are unchanged; no rebuild or image copy follows from this configuration packet.

The operator explicitly selected **open public-address egress**, not a hostname
or Stripe/Honeycomb destination allowlist. This is broader than the fixed
application destinations: compromised workload code could reach other public
addresses. The platform firewall excludes nonpublic ranges under the inspected
source contract; actual installed enforcement and future runtime forwarding are
not established by these local tests. No inbound ports, listeners, TLS weakening,
proxy changes or retries are added.

CPU2 / memory8192 / GPU0, four-disk measurement expectation, CVM version, the one
encrypted existing `ledger` volume with owner 65532, UID/GID65532, original
instance/host/domain selection, command, operator/site state, secret-name inputs,
passive synthetic healthcheck, tmpfs, restart `no` and read-only root remain
unchanged. There are no backups, restore/reset, initialization, allocation,
credential creation/upsert/reset or financial-state edits. Existing-only serving
can perform normal supported database/maintenance writes; it is not read-only.
Platform-managed key custody and encrypted-volume rollback limits remain trust
boundaries. Preserve all existing state and replay evidence.

## Frozen helper and official workflow

The eleven historical templates and `scripts/synthetic-release.py` remain byte
identical. The frozen helper SHA-256 remains
`29c7e27e148043fa813d5a8857421ffd34704060f32e7881c3bd4b9424b91175`.
The small `scripts/stripe-egress-release.py` guard verifies that hash **before
executing those bytes**, using an isolated normal module with the original
`__file__`, no bytecode cache and no mutation of its globals or profile table.
The semantic phase remains **`persistent-live-stripe-serve`**: no new workflow,
phase alias, substituted event, environment rewrite or publication helper fork.

The new pure renderer requires the exact new template hash, CVM pin, existing
three-field receipt validation and exactly one occurrence of each placeholder.
Root admission is exact rendered-byte equality, not a permissive YAML parser.
The guard reuses the original context, public evidence and committed-file gates:
owner, current main, lightweight tag, actual source/run/attempt 1, typed release
absence and receipt binding remain required. It also requires Git HEAD byte
equality and mode 100644 for the new guard, its test and the new template. Other
legacy phases delegate to the unchanged helper CLI with unmodified arguments
and context. New-variant commands are limited to `guard` and offline `status`.
Unexpected errors and interruption produce closed locally authored diagnostics;
no exception text, values, inferred HTTP statuses or tracebacks are emitted.

The only workflow edit changes the guard command. Workflow identity, inputs,
permissions, attempt guards, pinned checkout and official Tinfoil action remain
unchanged. The official action still owns measurement and the sole release-create
operation. Historical controllers/helpers and unrelated README/cache state are
not edited. No package/repository-association gate or private repository link is
introduced.

## Privacy and evidence limits

Egress may also enable delivery of the **already-configured approved aggregate
metrics**. It adds no metric family, exporter, endpoint, log/trace collection,
diagnostics infrastructure or replay policy. Metrics delivery is unproven; the
existing off switch and aggregate privacy controls remain unchanged. No provider,
HTTP, browser, authentication, secret-value, inference or telemetry probe was run.

Applicable privacy policy sections remain intake **Authority and scope**,
**Forbidden collection and defaults**, **Export, retention and failure behavior**,
and gateway **Data handling boundaries** and **Processors, retention, access and
shutdown**. No private repository link is needed for this public source packet.
No content, credentials, account/payment/session identifiers, amounts, raw
exceptions, logs or diagnostic artifacts are added. Native host history,
platform/network metadata, provider retention and managed-key custody remain
separate persistence/trust boundaries. Current-state platform observations and
ordinary WebPKI assumptions are not runtime attestation or financial receipts.

Local evidence actually run for this packet: **117 offline Python discovery
tests passed** under the already-installed pinned Python 3.14.7 (`-B`), including
the retained 105 tests and 12 new egress tests. They inject process/network
boundaries, cover exact rendering and mutation refusals, unchanged source/public
admission, new-file modes/bytes, pre-execution helper hashing, unchanged legacy
delegation and closed hostile-error/interrupt handling. Pinned Go 1.27.2 `gofmt`
check and `git diff --check` also passed. No dependencies were downloaded or
installed. The maintained Go syntax qualifier now names twelve fixtures and adds
explicit JSON-projected assertions for the new variant's sole open network and
sole attachment, retaining the old eleven fixtures and old-decoder binding
refusal/positive controls. **The updated actual Go decoder qualifier was not run
in this packet**; its pinned native execution remains parent-owned. No runtime
forwarding, provider reachability, financial preservation receipt, Checkout or
provider outcome, measurement/signing, deployment or activation is established.
