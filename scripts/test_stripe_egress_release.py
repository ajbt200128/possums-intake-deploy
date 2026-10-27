"""Offline egress-variant regressions; no decoder, provider or live gate calls."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import test_synthetic_release as legacy

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("stripe_egress_release", ROOT / "scripts/stripe-egress-release.py")
if spec is None or spec.loader is None:
    raise RuntimeError("EGRESS_TEST_SOURCE_UNAVAILABLE")
e = importlib.util.module_from_spec(spec)
spec.loader.exec_module(e)
NETWORK = b"networks:\n  public-egress:\n    egress: open\n"
ATTACHMENT = b"    networks: [public-egress]\n"
NEW_FILES = ("scripts/stripe-egress-release.py", "scripts/test_stripe_egress_release.py",
             "templates/persistent-live-stripe-egress-serve-config.yml.in")


class Checks(unittest.TestCase):
    def setUp(self):
        self.h = e.load_helper()
        self.template = (ROOT / "templates" / e.EGRESS_TEMPLATE_NAME).read_bytes()
        self.receipt = legacy.receipt()
        self.env = legacy.environment()
        self.env["RELEASE_STORAGE_PHASE"] = e.PHASE
        self.event = legacy.event()
        self.event["inputs"]["expected_storage_phase"] = e.PHASE
        self.api = legacy.PublicAPI()
        self.network = patch.object(self.h.urllib.request, "build_opener", side_effect=AssertionError("offline"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.process = patch.object(self.h.subprocess, "Popen", side_effect=AssertionError("offline"))
        self.process.start()
        self.addCleanup(self.process.stop)

    def refuses(self, code, operation):
        with self.assertRaises(self.h.Stop) as caught:
            operation()
        self.assertEqual(caught.exception.code, code)

    def fixture(self, root):
        names = ("accepted-image.json", "tinfoil-config.yml", "scripts/synthetic-release.py",
                 "scripts/test_synthetic_release.py", self.h.WORKFLOW) + NEW_FILES + tuple(
                     "templates/" + item[0] for item in self.h.PROFILES.values())
        for name in names:
            target = root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes((ROOT / name).read_bytes())
        (root / "accepted-image.json").write_bytes(json.dumps(self.receipt).encode())
        (root / "tinfoil-config.yml").write_bytes(e.render(self.h, self.template, self.receipt, legacy.CVM))
        (root / "event.json").write_bytes(json.dumps(self.event).encode())
        self.env["GITHUB_EVENT_PATH"] = str(root / "event.json")
        committed = {name: (root / name).read_bytes() for name in names}
        self.commands = []

        def run(args, code):
            self.commands.append(args)
            if args == ["git", "rev-parse", "HEAD"]:
                return (legacy.PUBLIC + "\n").encode()
            if args[:4] == ["git", "ls-tree", "HEAD", "--"] and args[4] in committed:
                return b"100644 blob " + b"a" * 40 + b"\t" + args[4].encode() + b"\n"
            if args[:2] == ["git", "show"] and args[2].startswith("HEAD:"):
                return committed[args[2][5:]]
            raise AssertionError("unexpected offline command")
        return run

    def guard(self, root, run):
        return e.guard(self.h, root, env=self.env, get=self.api, run=run)

    def test_template_is_only_two_network_insertions(self):
        old = (ROOT / "templates/persistent-live-stripe-serve-config.yml.in").read_bytes()
        self.assertEqual(self.template, old.replace(b"gpus: 0\n", b"gpus: 0\n" + NETWORK).replace(
            b"  - name: intake-persistent\n", b"  - name: intake-persistent\n" + ATTACHMENT))
        self.assertEqual(self.h.sha(self.template), e.EGRESS_TEMPLATE_HASH)

    def test_exact_render_and_committed_root_receipt(self):
        expected = self.template.replace(b"@CVM_PIN@", legacy.CVM.encode()).replace(
            b"@IMAGE_DIGEST@", self.receipt["imageDigest"].encode())
        self.assertEqual(e.render(self.h, self.template, self.receipt, legacy.CVM), expected)
        e.config_gate(self.h, expected, self.template, self.receipt)
        actual_receipt = self.h.receipt_gate((ROOT / "accepted-image.json").read_bytes())
        e.config_gate(self.h, (ROOT / "tinfoil-config.yml").read_bytes(), self.template, actual_receipt)

    def test_both_network_parts_and_every_other_byte_are_required(self):
        raw = e.render(self.h, self.template, self.receipt, legacy.CVM)
        changed = [raw.replace(NETWORK, b""), raw.replace(ATTACHMENT, b""),
                   raw.replace(b"egress: open", b"egress: closed"),
                   raw.replace(b"egress: open", b"egress: allowlist\n    allow: [api.stripe.com]"),
                   raw.replace(b"    egress: open\n", b"    egress: open\n  extra:\n    egress: open\n"),
                   raw.replace(b"[public-egress]", b"[public-egress, extra]"),
                   raw.replace(b"'serve'", b"'init'"), raw.replace(b"ledger:/state", b"ledger:/other"),
                   raw.replace(b"LEDGER_ADMIN_KEY", b"OTHER_KEY"), raw.replace(b"cpus: 2", b"cpus: 4"),
                   raw.replace(b"memory: 8192", b"memory: 4096"), raw.replace(b"gpus: 0", b"gpus: 1"),
                   raw.replace(b"owner: 65532", b"owner: 0"), raw.replace(b"read_only: true", b"read_only: false"),
                   raw.replace(b"restart: 'no'", b"restart: always"),
                   raw.replace(b"possums-intake-synthetic@", b"other-image@"),
                   raw.replace(b"sha256:" + b"b" * 64, b"sha256:" + b"c" * 64),
                   raw.replace(b"0.14.14", b"0.14.15"), raw + b"extra: true\n"]
        for value in changed:
            with self.subTest(value=changed.index(value)):
                self.refuses("config", lambda: e.config_gate(self.h, value, self.template, self.receipt))

    def test_bad_template_cvm_phase_and_receipt_refused(self):
        for template in (self.template + b"\n", self.template.replace(b"egress: open", b"egress: closed"),
                         self.template.replace(b"@CVM_PIN@", b"@CVM_PIN@@CVM_PIN@"),
                         self.template.replace(b"@IMAGE_DIGEST@", b"")):
            self.refuses("config", lambda: e.render(self.h, template, self.receipt, legacy.CVM))
        for cvm in ("0.14.13", "0.15.0", "0.14.14\n", "0.14.14@sha256:" + "a" * 64):
            self.refuses("config", lambda: e.render(self.h, self.template, self.receipt, cvm))
        for phase in ("disposable", "persistent-serve", None, "unknown"):
            self.refuses("config", lambda: e.render(self.h, self.template, self.receipt, legacy.CVM, phase))
        self.refuses("receipt", lambda: e.render(self.h, self.template, {**self.receipt, "extra": True}, legacy.CVM))
        # Even a future hash-pin edit cannot waive the single-placeholder rule.
        for token in (b"@CVM_PIN@", b"@IMAGE_DIGEST@"):
            changed = self.template.replace(token, token + token)
            with patch.object(e, "EGRESS_TEMPLATE_HASH", self.h.sha(changed)):
                self.refuses("config", lambda: e.render(self.h, changed, self.receipt, legacy.CVM))

    def test_guard_reuses_all_committed_and_public_checks_without_mutating_helper(self):
        before = copy.deepcopy((self.h.PROFILES, self.h.FAILURES, self.h.ROOT, self.h.WORKFLOW))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.fixture(root)
            with patch.object(self.h, "context_gate", wraps=self.h.context_gate) as context, \
                 patch.object(self.h, "public_gate", wraps=self.h.public_gate) as public, \
                 patch.object(self.h, "committed_files", wraps=self.h.committed_files) as committed:
                self.assertTrue(self.guard(root, run)["passed"])
            self.assertGreaterEqual(context.call_count, 1)
            public.assert_called_once_with(self.env, self.event, self.receipt, self.api)
            committed.assert_called_once_with(root, legacy.PUBLIC, run=run)
        for name in NEW_FILES:
            self.assertIn(["git", "ls-tree", "HEAD", "--", name], self.commands)
            self.assertIn(["git", "show", "HEAD:" + name], self.commands)
        self.assertEqual(before, (self.h.PROFILES, self.h.FAILURES, self.h.ROOT, self.h.WORKFLOW))

    def test_each_new_file_requires_git_mode_and_head_bytes_before_public_reads(self):
        for name in NEW_FILES:
            for fault in ("mode", "bytes"):
                with self.subTest(name=name, fault=fault), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    base = self.fixture(root)
                    self.api.calls.clear()
                    def changed(args, code):
                        value = base(args, code)
                        if fault == "mode" and args == ["git", "ls-tree", "HEAD", "--", name]:
                            return value.replace(b"100644", b"100755")
                        if fault == "bytes" and args == ["git", "show", "HEAD:" + name]:
                            return value + b"\n"
                        return value
                    self.refuses("source", lambda: self.guard(root, changed))
                    self.assertEqual(self.api.calls, [])

    def test_context_negatives_refuse_before_public_reads(self):
        mutations = (("SYNTHETIC_RELEASE_ENABLED", "false", "disabled"),
                     ("RELEASE_PUBLISH", "false", "disabled"), ("GITHUB_EVENT_NAME", "push", "source"),
                     ("GITHUB_ACTOR", "other", "source"), ("GITHUB_RUN_ATTEMPT", "2", "source"),
                     ("GITHUB_REF", "refs/heads/main", "source"),
                     ("RELEASE_STORAGE_PHASE", "persistent-serve", "config"))
        for key, value, code in mutations:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run = self.fixture(root)
                with patch.dict(self.env, {key: value}):
                    self.refuses(code, lambda: self.guard(root, run))
                self.assertEqual(self.api.calls, [])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.fixture(root)
            (root / "event.json").write_text(json.dumps({**self.event, "ref": "main"}))
            self.refuses("source", lambda: self.guard(root, run))
            self.assertEqual(self.api.calls, [])

    def test_missing_public_read_token_refuses_without_a_network_request(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.fixture(root)
            with patch.dict(self.h.os.environ, {}, clear=True), \
                 patch.object(self.h.urllib.request, "build_opener") as opener:
                self.refuses("transport", lambda: e.guard(
                    self.h, root, env=self.env, get=self.h.public_get, run=run))
                opener.assert_not_called()

    def test_current_main_lightweight_tag_attempt_absence_and_receipt_unchanged(self):
        changes = (("/git/ref/heads/main", (200, {"object": {"type": "commit", "sha": "c" * 40}}), "source"),
                   ("/git/ref/tags/" + legacy.TAG, (200, {"object": {"type": "tag", "sha": legacy.PUBLIC}}), "source"),
                   ("/actions/runs/123", (200, {**self.api.values["/actions/runs/123"][1], "run_attempt": 2}), "invocation"),
                   ("/releases/tags/" + legacy.TAG, (200, {}), "absence"),
                   ("/releases/tags/" + legacy.TAG, (403, None), "absence"))
        for path, value, code in changes:
            with self.subTest(path=path, code=code), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                run = self.fixture(root)
                with patch.dict(self.api.values, {path: value}):
                    self.refuses(code, lambda: self.guard(root, run))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = self.fixture(root)
            with patch.dict(self.env, {"RELEASE_PRIVATE_SHA": "e" * 40}):
                changed_event = copy.deepcopy(self.event)
                changed_event["inputs"]["expected_private_source"] = "e" * 40
                (root / "event.json").write_text(json.dumps(changed_event))
                self.refuses("receipt", lambda: self.guard(root, run))

    def test_loader_hash_refuses_before_exec_and_has_normal_file_identity(self):
        self.assertEqual(Path(self.h.__file__), ROOT / "scripts/synthetic-release.py")
        self.assertEqual(self.h.ROOT, ROOT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "scripts").mkdir()
            (root / "scripts/synthetic-release.py").write_text("raise RuntimeError('hostile')\n")
            with patch("builtins.exec") as execute:
                with self.assertRaises(e.HelperUnavailable) as caught:
                    e.load_helper(root)
            self.assertEqual(caught.exception.args, ())
            execute.assert_not_called()

    def test_cli_status_offline_unknown_arguments_and_legacy_exact_delegation(self):
        with patch.object(e, "load_helper", return_value=self.h), patch.object(self.h, "public_get") as get, \
             patch.object(self.h, "checked_command") as run, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(e.cli(["status"]), 0)
            get.assert_not_called()
            run.assert_not_called()
        for phase in self.h.PROFILES:
            if phase == e.PHASE:
                continue
            for args in (["guard"], ["render", "receipt.json", legacy.CVM, phase]):
                env = {"RELEASE_STORAGE_PHASE": phase}
                with patch.object(e, "load_helper", return_value=self.h), \
                     patch.dict(self.h.os.environ, env, clear=True), patch.object(self.h, "cli", return_value=17) as delegated:
                    self.assertEqual(e.cli(args), 17)
                    delegated.assert_called_once_with(args)
                    self.assertIs(delegated.call_args.args[0], args)
                    self.assertEqual(dict(self.h.os.environ), env)
        with patch.object(e, "load_helper", return_value=self.h), \
             patch.dict(self.h.os.environ, {"RELEASE_STORAGE_PHASE": e.PHASE}, clear=True), \
             patch.object(self.h, "public_get") as get, patch.object(self.h, "checked_command") as run:
            for args in ([legacy.SECRET], [], ["measure"], ["publish"]):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(e.cli(args), 1)
                self.assertEqual(json.loads(output.getvalue())["code"], "SYNTHETIC_ARGUMENTS")
                self.assertNotIn(legacy.SECRET, output.getvalue())
            get.assert_not_called()
            run.assert_not_called()

    def test_unexpected_and_interrupt_diagnostics_are_closed_including_loader(self):
        for failure in (RuntimeError(legacy.SECRET), KeyboardInterrupt(legacy.SECRET)):
            for boundary in ("load_helper", "guard"):
                output = io.StringIO()
                with patch.object(e, "load_helper", return_value=self.h), \
                     patch.dict(self.h.os.environ, {"RELEASE_STORAGE_PHASE": e.PHASE}, clear=True), \
                     patch.object(e, boundary, side_effect=failure), contextlib.redirect_stdout(output):
                    self.assertEqual(e.cli(["guard"]), 1)
                value = json.loads(output.getvalue())
                self.assertEqual(value["code"], "SYNTHETIC_SOURCE")
                self.assertEqual(value["cause"], "unknown_or_unconfirmed")
                self.assertNotIn(legacy.SECRET, output.getvalue())


if __name__ == "__main__":
    unittest.main()
