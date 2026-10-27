#!/usr/bin/env python3
"""Exact live-Stripe egress guard; frozen legacy release machinery is unchanged.

Only guard reads public evidence. status is offline. Other legacy phases delegate
unchanged; measurement/publication remain owned by the pinned official action.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import signal
import sys

ROOT = Path(__file__).resolve().parent.parent
HELPER_HASH = "29c7e27e148043fa813d5a8857421ffd34704060f32e7881c3bd4b9424b91175"
PHASE = "persistent-live-stripe-serve"
EGRESS_TEMPLATE_NAME = "persistent-live-stripe-egress-serve-config.yml.in"
EGRESS_TEMPLATE_HASH = "f135d7d6cafa2ddda365a9258a75a380861e6dc2a7b7b72a21a6051627eb56ef"
NEW_FILES = ("scripts/stripe-egress-release.py", "scripts/test_stripe_egress_release.py",
             "templates/" + EGRESS_TEMPLATE_NAME)
# The helper cannot author diagnostics until its bytes have been verified.
LOAD_FAILURE = {"code": "SYNTHETIC_SOURCE", "stage": "public_source",
                "constraint": "hash_verified_frozen_release_helper", "cause": "unknown_or_unconfirmed",
                "outcome": "no_effect", "next_step": "Review the frozen helper pin privately; do not publish or retry."}


class HelperUnavailable(Exception):
    pass


def load_helper(root=ROOT):
    try:
        path = root / "scripts/synthetic-release.py"
        if path.is_symlink() or not path.is_file():
            raise HelperUnavailable
        with path.open("rb") as stream:
            raw = stream.read((8 << 20) + 1)
        if hashlib.sha256(raw).hexdigest() != HELPER_HASH:
            raise HelperUnavailable
        spec = importlib.util.spec_from_file_location("stripe_egress_legacy_release", path)
        if spec is None:
            raise HelperUnavailable
        helper = importlib.util.module_from_spec(spec)
        # Execute the verified bytes, not a second file read or cached bytecode.
        exec(compile(raw, str(path), "exec"), helper.__dict__)
        return helper
    except (Exception, KeyboardInterrupt):
        raise HelperUnavailable from None


def render(h, template, receipt, cvm, phase=PHASE):
    h.require(type(phase) is str and phase == PHASE, "config")
    h.require(h.sha(template) == EGRESS_TEMPLATE_HASH and h.pin(cvm, h.CVM), "config")
    receipt = h.receipt_gate(json.dumps(receipt).encode())
    h.require(template.count(b"@CVM_PIN@") == template.count(b"@IMAGE_DIGEST@") == 1, "config")
    return template.replace(b"@CVM_PIN@", cvm.encode()).replace(b"@IMAGE_DIGEST@", receipt["imageDigest"].encode())


def config_gate(h, root, template, receipt, phase=PHASE):
    match = re.match(rb"cvm-version: (0\.14\.14)\n", root)
    if match is None:
        raise h.Stop("config")
    h.require(root == render(h, template, receipt, match[1].decode(), phase), "config")


def guard(h, root=ROOT, *, env=None, get=None, run=None):
    def check():
        current = dict(h.os.environ) if env is None else env
        event = h.decode(h.read_file(Path(current.get("GITHUB_EVENT_PATH", "")), "source"), "source")
        receipt = h.receipt_gate(h.read_file(root / "accepted-image.json", "receipt", 4096))
        config = h.read_file(root / "tinfoil-config.yml", "config", 4096)
        phase = current.get("RELEASE_STORAGE_PHASE")
        if type(phase) is not str or phase != PHASE:
            raise h.Stop("config")
        template = h.read_file(root / "templates" / EGRESS_TEMPLATE_NAME, "config")
        config_gate(h, config, template, receipt, phase)
        _, commit = h.context_gate(current, event)
        runner = h.checked_command if run is None else run
        h.committed_files(root, commit, run=runner)
        for name in NEW_FILES:
            mode = runner(["git", "ls-tree", "HEAD", "--", name], "source")
            h.require(mode.startswith(b"100644 blob ") and mode.rstrip().endswith(b"\t" + name.encode()), "source")
            h.require(h.read_file(root / name, "source") == runner(["git", "show", "HEAD:" + name], "source"), "source")
        h.public_gate(current, event, receipt, h.public_get if get is None else get)
        return {"passed": True, "stage": "guard", "runtime_verified": False}
    return h.safe("source", check)


def cli(args):
    h = None
    try:
        h = load_helper()
        if args == ["status"]:
            return h.cli(args)
        phase = h.os.environ.get("RELEASE_STORAGE_PHASE")
        if phase in h.PROFILES and phase != PHASE:
            return h.cli(args)
        h.require(args == ["guard"], "arguments")
        result = guard(h)
        h.safe("presentation", lambda: print(json.dumps(result)))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        failure = LOAD_FAILURE if h is None else h.diagnostic(
            error if isinstance(error, h.Stop) else h.Stop("source" if args == ["guard"] else "arguments"))
        try:
            print(json.dumps(failure))
        except (Exception, KeyboardInterrupt):
            pass  # An unusable stdout cannot carry a diagnostic; no raw stderr.
        return 1


def interrupt(signum, frame):
    raise KeyboardInterrupt


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    sys.exit(cli(sys.argv[1:]))
