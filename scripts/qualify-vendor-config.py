#!/usr/bin/env python3
"""Explicit pinned-decoder qualification; never measurement or publication.

qualify uses the existing Go 1.27.2 compiler and downloads checksum-pinned PUBLIC
Go modules into an owned temporary cache. It installs no toolchain, supplies no
token and executes no workload. status is offline and initiates no qualification.
"""
import importlib.util
import json
from pathlib import Path
import shutil
import signal
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("vendor_fixture_release", ROOT / "scripts/synthetic-release.py")
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
r.FAILURES.update({
    "vendor_toolchain": ("vendor_fixture_toolchain", "existing_go_1_27_2_only", "Use the existing pinned Go 1.27.2 compiler; do not install or auto-upgrade a toolchain."),
    "vendor_decoder": ("vendor_fixture_decoder", "checksum_pinned_actual_decoders_and_exact_fixture_results", "Decoder qualification is incomplete; underlying cause unknown. Inspect the pinned fixtures and dependency availability privately. Do not measure or publish."),
    "cleanup": ("vendor_fixture_cleanup", "joined_owned_temporary_module_cache_removal", "Owned cache cleanup is unconfirmed; inspect it privately. Do not rerun qualification to clean up."),
})


def qualify():
    workspace = Path(tempfile.mkdtemp(prefix="possums-vendor-decoder."))
    primary = None
    results = []
    module_started = False
    # The shared bounded runner strips the inherited environment. These are only
    # public build/cache settings; no credentials or runtime configuration enter.
    prefix = ["env", "HOME=" + str(workspace), "GOENV=off", "GOWORK=off", "GOTOOLCHAIN=local",
              "GOMODCACHE=" + str(workspace / "modules"), "GOCACHE=" + str(workspace / "build-cache"),
              "GOPATH=" + str(workspace / "gopath"), "GOPROXY=https://proxy.golang.org", "GOSUMDB=sum.golang.org",
              "GOFLAGS=-buildvcs=false -trimpath", "OTEL_SDK_DISABLED=true", "go"]
    try:
        version = r.checked_command(prefix + ["version"], "vendor_toolchain", timeout=15, process_group=True)
        r.require(version.startswith(b"go version go1.27.2 "), "vendor_toolchain")
        module = str(ROOT / "tests/vendor-config")
        module_started = True
        for mod, version, behavior in (("old.mod", "v0.1.14", "reject"), ("go.mod", "v0.1.16", "accept"),
                                       ("runtime.mod", "v0.1.17", "accept")):
            selected = r.checked_command(prefix + ["-C", module, "list", "-mod=readonly", "-modfile=" + mod,
                                                   "-m", "github.com/tinfoilsh/tinfoil-config"], "vendor_decoder", timeout=180, process_group=True)
            r.require(selected == ("github.com/tinfoilsh/tinfoil-config " + version + "\n").encode(), "vendor_decoder")
            raw = r.checked_command(prefix + ["-C", module, "run", "-mod=readonly", "-modfile=" + mod,
                                              ".", behavior, str(ROOT)], "vendor_decoder", timeout=180, process_group=True)
            r.require(r.decode(raw, "vendor_decoder") == {"stage": "vendor_config_decoder", "passed": True,
                      "measurement": False, "runtime_verified": False}, "vendor_decoder")
            results.append({"config_version": version, "persistent_behavior": behavior, "passed": True})
    except (Exception, KeyboardInterrupt) as error:
        primary = error if isinstance(error, r.Stop) else r.Stop("vendor_decoder")
    if primary is not None and (primary.process_cleanup_failed or primary.code == "process_cleanup"):
        primary.cleanup_failed = True
        raise primary  # Leader join alone cannot establish descendant completion.
    try:
        # Go module directories are intentionally read-only; Go owns their cleanup.
        if module_started:
            r.checked_command(prefix + ["clean", "-modcache"], "cleanup", timeout=60, process_group=True)
        r.safe("cleanup", lambda: shutil.rmtree(workspace))
    except (Exception, KeyboardInterrupt) as error:
        cleanup = error if isinstance(error, r.Stop) else r.Stop("cleanup")
        if primary is None:
            primary = cleanup
        else:
            primary.cleanup_failed = True
            primary.cleanup_status = cleanup.status
            primary.process_cleanup_failed |= cleanup.process_cleanup_failed or cleanup.code == "process_cleanup"
    if primary is not None:
        raise primary
    return {"stage": "vendor_config_decoder", "cases": results, "owned_cache_removed": True,
            "measurement": False, "runtime_verified": False}


def main(args):
    r.require(args in (["status"], ["qualify"]), "arguments")
    if args == ["status"]:
        return {"offline": True, "qualification_started": False, "measurement": False, "runtime_verified": False}
    return r.safe("vendor_decoder", qualify)


def cli(args):
    try:
        result = r.safe("vendor_decoder", lambda: main(args))
        r.safe("presentation", lambda: print(json.dumps(result)))
        return 0
    except r.Stop as error:
        try:
            print(json.dumps(r.diagnostic(error)))
        except (Exception, KeyboardInterrupt):
            pass
        return 1


def interrupt(signum, frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    sys.exit(cli(sys.argv[1:]))
