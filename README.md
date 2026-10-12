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

No deployable `tinfoil-config.yml` or release exists yet. Add them only after these gates pass; this README is not deployment evidence.

## Secrets and access

Grant the Tinfoil GitHub App access to this repository. Keep credential values outside Git, configuration, command arguments and chat. Use dedicated synthetic-only operator/accounting credentials and narrowly scoped private-image credentials through supported private setup channels. Do not reuse gateway credentials.

Tinfoil-managed secrets are accessible to platform infrastructure during deployment. This disposable test does not qualify customer-controlled encrypted storage, verified gateway-to-ledger transport, production durability or financial restore.
