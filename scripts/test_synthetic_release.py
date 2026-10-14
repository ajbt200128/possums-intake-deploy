"""Offline public-adapter checks: fake control plane, no Docker/GitHub/inference.

Protocol-shaped manifest/certificate fixtures reflect the parent-inspected pinned
vendor SDK and gh verification JSON. They are NOT signatures or runtime evidence.
The dispatch fixture uses a short tag; full GITHUB_REF and API refs are authority.
"""
import base64
import contextlib
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/synthetic-release.py"
spec = importlib.util.spec_from_file_location("synthetic_release", SCRIPT)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
SECRET = "SYNTHETIC_HOSTILE_CREDENTIAL_SENTINEL"
PUBLIC = "a" * 40
PRIVATE = "96fc6cae0bc65716bba38b6235c71d2d9f1082f0"
TAG = "v1.2.3"
CVM = "0.14.7@sha256:" + "c" * 64


def receipt():
    return {"publicSourceSHA": PRIVATE, "imageDigest": "sha256:" + "b" * 64, "archiveSHA": "d" * 64}


def environment():
    return {"SYNTHETIC_RELEASE_ENABLED": "true", "RELEASE_PUBLISH": "true",
            "GITHUB_REPOSITORY": r.REPO, "GITHUB_REPOSITORY_OWNER": r.OWNER,
            "GITHUB_ACTOR": r.OWNER, "GITHUB_TRIGGERING_ACTOR": r.OWNER,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF_TYPE": "tag",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_REF_NAME": TAG,
            "GITHUB_REF": "refs/tags/" + TAG, "GITHUB_SHA": PUBLIC,
            "RELEASE_PUBLIC_SHA": PUBLIC, "RELEASE_PRIVATE_SHA": PRIVATE,
            "RELEASE_IMAGE_DIGEST": receipt()["imageDigest"], "GITHUB_RUN_ID": "123"}


def event():
    return {"ref": TAG, "repository": {"full_name": r.REPO}, "sender": {"login": r.OWNER},
            "inputs": {"publish": "true", "expected_public_commit": PUBLIC,
                       "expected_private_source": PRIVATE, "expected_image_digest": receipt()["imageDigest"]}}


class PublicAPI:
    def __init__(self):
        self.calls = []
        self.values = {
            "": (200, {"full_name": r.REPO, "private": False, "default_branch": "main"}),
            "/git/ref/heads/main": (200, {"object": {"type": "commit", "sha": PUBLIC}}),
            "/git/ref/tags/" + TAG: (200, {"object": {"type": "commit", "sha": PUBLIC}}),
            "/releases/tags/" + TAG: (404, None),
            "/actions/runs/123": (200, {"repository": {"full_name": r.REPO},
                "head_repository": {"full_name": r.REPO}, "path": r.WORKFLOW,
                "event": "workflow_dispatch", "head_sha": PUBLIC, "head_branch": TAG,
                "run_attempt": 1, "id": 123, "actor": {"login": r.OWNER},
                "triggering_actor": {"login": r.OWNER}, "status": "in_progress", "conclusion": None})}

    def __call__(self, path):
        self.calls.append(path)
        value = self.values[path]
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)


def manifest(config):
    hashes = {"version": "v0.14.7", "root": "1" * 64, "kernel": "2" * 64,
              "initrd": "3" * 64, "raw": "4" * 64}
    return {"snp_measurement": "5" * 96,
            "tdx_measurement": {"rtmr1": "6" * 96, "rtmr2": "7" * 96},
            "firmware": {"sev_snp": {"type": "ovmf", "version": "v0.0.4", "sha256": r.FIRMWARE_HASH}},
            "vm_shape": {"cpus": 2, "memory_mb": 8192, "gpus": 0, "disks": 3},
            "cmdline": "readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 "
                       "root=/dev/mapper/root roothash=" + hashes["root"] + " tinfoil-config-hash=" + r.sha(config),
            "hashes": hashes, "config": base64.b64encode(config).decode()}


def verified_statement(value, digest):
    return [{"verificationResult": {"statement": {"predicateType": r.PREDICATE, "predicate": value,
        "subject": [{"name": "tinfoil-deployment.json", "digest": {"sha256": digest}}]},
        "signature": {"certificate": {
            "subjectAlternativeName": f"https://github.com/{r.REPO}/{r.WORKFLOW}@refs/tags/{TAG}",
            "buildSignerDigest": PUBLIC, "sourceRepositoryDigest": PUBLIC,
            "sourceRepositoryRef": "refs/tags/" + TAG, "runnerEnvironment": "github-hosted",
            "runInvocationURI": f"https://github.com/{r.REPO}/actions/runs/123/attempts/1"}}}}]


class Checks(unittest.TestCase):
    def setUp(self):
        # Any accidentally unmocked remote request or vendor command fails offline.
        self.network = patch.object(r.urllib.request, "build_opener", side_effect=AssertionError("offline"))
        self.network.start()
        self.addCleanup(self.network.stop)
        self.template = (ROOT / "templates/synthetic-config.yml.in").read_bytes()
        self.config = r.render(self.template, receipt(), CVM)

    def refuses(self, code, operation, outcome="no_effect"):
        with self.assertRaises(r.Stop) as caught:
            operation()
        detail = r.diagnostic(caught.exception)
        self.assertEqual(detail["code"], "SYNTHETIC_" + code.upper())
        self.assertEqual(detail["outcome"], outcome)
        self.assertNotIn(SECRET, json.dumps(detail))
        return caught.exception

    def test_receipt_accepts_current_and_future_delivery_source(self):
        for source in (PRIVATE, "e" * 40):
            value = receipt()
            value["publicSourceSHA"] = source
            self.assertEqual(r.receipt_gate(json.dumps(value)), value)
        self.assertFalse(hasattr(r, "PRIVATE_SOURCE"))

    def test_receipt_exact_fields_duplicate_and_hostile_bytes(self):
        values = [None, True, [], SECRET, {**receipt(), "credentials": SECRET},
                  {k: v for k, v in receipt().items() if k != "archiveSHA"}]
        for value in values:
            with self.subTest(value_type=type(value).__name__):
                self.refuses("receipt", lambda: r.receipt_gate(json.dumps(value)))
        for raw in (b'{"publicSourceSHA":"x","publicSourceSHA":"y"}', b"{", SECRET.encode(), b"\xff"):
            self.refuses("receipt", lambda: r.receipt_gate(raw))

    def test_receipt_each_pin_is_canonical_nonzero_string(self):
        for field in receipt():
            for bad in (None, True, 123, [], SECRET, "0" * (40 if field == "publicSourceSHA" else 64),
                        "sha256:" + "0" * 64, "A" * 64, "sha256:" + "b" * 63):
                value = receipt()
                value[field] = bad
                with self.subTest(field=field, bad_type=type(bad).__name__):
                    self.refuses("receipt", lambda: r.receipt_gate(json.dumps(value)))

    def test_decode_rejects_all_non_json_constants_at_every_depth(self):
        for constant in ("NaN", "Infinity", "-Infinity"):
            for raw in (constant, '{"value":' + constant + '}',
                        '{"nested":[{"value":' + constant + ',"hostile":"' + SECRET + '"}]}'):
                for code in ("receipt", "transport", "manifest", "signature", "source"):
                    error = self.refuses(code, lambda: r.decode(raw, code))
                    self.assertEqual(error.args, ())
                    self.assertIsNone(error.__cause__)
                    self.assertNotIn(SECRET, repr(vars(error)))
        self.refuses("receipt", lambda: r.decode('{"a":1,"a":2}', "receipt"))

    def test_receipt_real_cli_non_json_constants_are_private(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "receipt.json"
            for constant in ("NaN", "Infinity", "-Infinity"):
                for raw in (constant, '{"nested":[{"value":' + constant + ',"hostile":"' + SECRET + '"}]}',
                            json.dumps(receipt()).replace('"' + PRIVATE + '"', constant)):
                    path.write_text(raw)
                    result = subprocess.run([sys.executable, str(SCRIPT), "render", str(path), CVM],
                                            capture_output=True, timeout=10,
                                            env={"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"})
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stderr, b"")
                    self.assertEqual(json.loads(result.stdout)["code"], "SYNTHETIC_RECEIPT")
                    self.assertNotIn(SECRET.encode(), result.stdout)
                    self.assertNotIn(constant.encode(), result.stdout)

    def test_fixed_template_and_config_binding(self):
        self.assertEqual(r.sha(self.template), r.TEMPLATE_HASH)
        self.assertNotIn(b"@CVM_PIN@", self.config)
        self.assertIn((r.IMAGE + "@" + receipt()["imageDigest"]).encode(), self.config)
        r.config_gate(self.config, self.template, receipt())
        for bad in (self.template + b"\n", self.template.replace(b"8192", b"4096")):
            self.refuses("config", lambda: r.render(bad, receipt(), CVM))
        for bad in ("0.14.7@sha256:" + "0" * 64, CVM.replace("0.14.7", "0.14.10"), SECRET, None):
            self.refuses("config", lambda: r.render(self.template, receipt(), bad))
        for bad in (self.config + b"\n", self.config.replace(b"8192", b"4096"), self.config.replace(b"b" * 64, b"e" * 64)):
            self.refuses("config", lambda: r.config_gate(bad, self.template, receipt()))

    def test_template_scope_exactly_three_names_no_volumes(self):
        text = self.config.decode()
        self.assertIn("cpus: 2\nmemory: 8192\ngpus: 0", text)
        self.assertIn("command: ['synthetic-serve', '--listen', '0.0.0.0:8090']", text)
        self.assertIn("read_only: true", text)
        self.assertIn("rw,nosuid,nodev,size=128m,mode=1777", text)
        self.assertIn("user: '65532:65532'", text)
        self.assertIn("OTEL_SDK_DISABLED: 'true'", text)
        self.assertEqual([line.strip() for line in text.splitlines() if line.strip().startswith("- LEDGER_")],
                         ["- LEDGER_ADMIN_KEY", "- LEDGER_OPERATOR_EMAIL", "- LEDGER_OPERATOR_PASSWORD"])
        for forbidden in ("volumes:", "models:", "debug:", "cvm_admin", "devices:", "attested-keys", "healthPolicy", "ports:"):
            self.assertNotIn(forbidden, text)

    def test_context_protocol_short_and_full_tag(self):
        for ref in (TAG, "refs/tags/" + TAG):
            payload = event()
            payload["ref"] = ref
            self.assertEqual(r.context_gate(environment(), payload), (TAG, PUBLIC))
        self.assertEqual(r.public_gate(environment(), event(), receipt(), PublicAPI()), (TAG, PUBLIC))

    def test_context_owner_tag_source_ref_attempt_activation_refusals(self):
        cases = {"SYNTHETIC_RELEASE_ENABLED": ("false", True, None), "RELEASE_PUBLISH": ("false", True),
                 "GITHUB_REPOSITORY": ("other/repo",), "GITHUB_REPOSITORY_OWNER": ("other",),
                 "GITHUB_ACTOR": ("other",), "GITHUB_TRIGGERING_ACTOR": ("other",),
                 "GITHUB_EVENT_NAME": ("push",), "GITHUB_REF_TYPE": ("branch",),
                 "GITHUB_RUN_ATTEMPT": ("2", 1, True), "GITHUB_REF_NAME": ("v01.2.3", "latest", "v1.2.3-rc1", SECRET),
                 "GITHUB_REF": ("refs/heads/" + TAG, TAG), "GITHUB_SHA": ("b" * 40,),
                 "RELEASE_PUBLIC_SHA": (SECRET, True), "GITHUB_RUN_ID": ("0", "0123", True)}
        for key, values in cases.items():
            for bad in values:
                env = environment()
                env[key] = bad
                with self.subTest(key=key):
                    self.refuses("disabled" if key in ("SYNTHETIC_RELEASE_ENABLED", "RELEASE_PUBLISH") else "source",
                                 lambda: r.context_gate(env, event()))

    def test_context_malformed_event_and_string_boolean(self):
        for value in (None, True, [], {}, {**event(), "repository": SECRET}, {**event(), "sender": []},
                      {**event(), "inputs": None}, {**event(), "ref": "main"}):
            self.refuses("source", lambda: r.context_gate(environment(), value))
        for field, bad in (("publish", True), ("expected_public_commit", "e" * 40),
                           ("expected_private_source", "e" * 40), ("expected_image_digest", SECRET)):
            value = event()
            value["inputs"][field] = bad
            self.refuses("source", lambda: r.context_gate(environment(), value))

    def test_public_receipt_expected_source_and_image(self):
        for field in ("publicSourceSHA", "imageDigest"):
            value = receipt()
            value[field] = "e" * 40 if field == "publicSourceSHA" else "sha256:" + "e" * 64
            self.refuses("receipt", lambda: r.public_gate(environment(), event(), value, PublicAPI()))

    def test_public_main_and_existing_lightweight_tag(self):
        for path in ("/git/ref/heads/main", "/git/ref/tags/" + TAG):
            for value in ({"object": {"type": "tag", "sha": PUBLIC}}, {"object": {"type": "commit", "sha": "e" * 40}},
                          {"object": None}, {"object": SECRET}):
                api = PublicAPI()
                api.values[path] = 200, value
                self.refuses("source", lambda: r.public_gate(environment(), event(), receipt(), api))
        api = PublicAPI()
        api.values["/git/ref/tags/" + TAG] = 404, None
        self.refuses("transport", lambda: r.public_gate(environment(), event(), receipt(), api))

    def test_exact_current_invocation(self):
        for key, bad in (("head_sha", "e" * 40), ("head_branch", "main"), ("run_attempt", True),
                         ("run_attempt", 2), ("id", "123"), ("event", "push"), ("path", "wrong.yml"),
                         ("repository", None), ("head_repository", {"full_name": "other/repo"}),
                         ("actor", {"login": "other"}), ("triggering_actor", []),
                         ("status", "completed"), ("conclusion", "success")):
            api = PublicAPI()
            api.values["/actions/runs/123"][1][key] = bad
            with self.subTest(field=key):
                self.refuses("invocation", lambda: r.public_gate(environment(), event(), receipt(), api))

    def test_completed_run_not_claimed_mid_job(self):
        api = PublicAPI()
        self.refuses("invocation", lambda: r.public_gate(environment(), event(), receipt(), api, completed=True))
        run = api.values["/actions/runs/123"][1]
        run.update(status="completed", conclusion="success")
        r.public_gate(environment(), event(), receipt(), api, completed=True)
        self.assertNotIn("/releases/tags/" + TAG, api.calls)
        run["conclusion"] = "failure"
        self.refuses("invocation", lambda: r.public_gate(environment(), event(), receipt(), api, completed=True))

    def test_real_absence_requires_public_repository_and_typed_404(self):
        r.absence_gate(PublicAPI(), TAG)
        for field, bad in (("private", True), ("private", 0), ("full_name", "other/repo"), ("default_branch", "other")):
            api = PublicAPI()
            api.values[""][1][field] = bad
            self.refuses("absence", lambda: r.absence_gate(api, TAG))
        for status in (200, 401, 403, 500, "404", True):
            api = PublicAPI()
            api.values["/releases/tags/" + TAG] = status, {"draft": True}
            self.refuses("absence", lambda: r.absence_gate(api, TAG))
        api = PublicAPI()
        api.values[""] = 404, None
        error = self.refuses("transport", lambda: r.absence_gate(api, TAG))
        self.assertEqual(error.status, 404)

    def test_committed_bytes_sha_and_file_modes_without_git_mutations(self):
        names = ("accepted-image.json", "tinfoil-config.yml", "templates/synthetic-config.yml.in", "scripts/synthetic-release.py", "scripts/test_synthetic_release.py", r.WORKFLOW)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents = {name: name.encode() for name in names}
            for name, data in contents.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_bytes(data)
            def git(args, code):
                self.assertEqual(code, "source")
                if args[1] == "rev-parse":
                    return (PUBLIC + "\n").encode()
                if args[1] == "ls-tree":
                    return ("100644 blob " + "a" * 40 + "\t" + args[-1] + "\n").encode()
                self.assertEqual(args[:2], ["git", "show"])
                return contents[args[-1].removeprefix("HEAD:")]
            r.committed_files(root, PUBLIC, git)
            self.refuses("source", lambda: r.committed_files(root, "e" * 40, git))
            for mode in (b"100755", b"120000", b"160000", b""):
                def bad_mode(args, code):
                    result = git(args, code)
                    return result.replace(b"100644", mode) if args[1] == "ls-tree" else result
                self.refuses("source", lambda: r.committed_files(root, PUBLIC, bad_mode))
            (root / "accepted-image.json").write_bytes(b"changed")
            self.refuses("source", lambda: r.committed_files(root, PUBLIC, git))
            (root / "accepted-image.json").unlink()
            (root / "accepted-image.json").symlink_to(root / "tinfoil-config.yml")
            self.refuses("source", lambda: r.committed_files(root, PUBLIC, git))

    def test_manifest_protocol_shape_is_not_crypto_verification(self):
        value = manifest(self.config)
        self.assertEqual(r.manifest_gate(json.dumps(value), self.config, receipt()), value)
        # No verifier or network is called by structural validation.
        with patch.object(r, "verify_file", side_effect=AssertionError("no crypto")):
            r.manifest_gate(json.dumps(value), self.config, receipt())

    def test_manifest_exact_config_bytes_and_cmdline(self):
        for key, bad in (("config", SECRET), ("config", base64.b64encode(self.config + b"\n").decode()),
                         ("config", True), ("cmdline", SECRET), ("cmdline", manifest(self.config)["cmdline"] + " tinfoil-config-hash=" + r.sha(self.config)),
                         ("snp_measurement", "f" * 95), ("snp_measurement", True), ("tdx_measurement", [])):
            value = manifest(self.config)
            value[key] = bad
            self.refuses("manifest", lambda: r.manifest_gate(json.dumps(value), self.config, receipt()))
        self.refuses("manifest", lambda: r.manifest_gate(json.dumps({**manifest(self.config), "credential": SECRET}), self.config, receipt()))
        for value in (True, [], None):
            self.refuses("manifest", lambda: r.manifest_gate(json.dumps(value), self.config, receipt()))

    def test_manifest_vm_shape_disks_are_base_not_persistent_volumes(self):
        for key, bad in (("cpus", True), ("cpus", 1), ("memory_mb", 4096), ("gpus", False), ("gpus", 1), ("disks", 0)):
            value = manifest(self.config)
            value["vm_shape"][key] = bad
            self.refuses("manifest", lambda: r.manifest_gate(json.dumps(value), self.config, receipt()))
        for shape in (None, SECRET, {**manifest(self.config)["vm_shape"], "volumes": 1}):
            value = manifest(self.config)
            value["vm_shape"] = shape
            self.refuses("manifest", lambda: r.manifest_gate(json.dumps(value), self.config, receipt()))

    def test_manifest_hashes_firmware_and_closed_tdx_keys(self):
        mutations = [("hashes", "version", "v0.14.10"), ("hashes", "root", SECRET), ("hashes", "extra", SECRET),
                     ("tdx_measurement", "hostile", SECRET), ("tdx_measurement", "rtmr2", "f" * 95),
                     ("tdx_measurement", "rtmr1", True)]
        for group, field, bad in mutations:
            value = manifest(self.config)
            value[group][field] = bad
            self.refuses("manifest", lambda: r.manifest_gate(json.dumps(value), self.config, receipt()))
        for group, field in (("hashes", "raw"), ("tdx_measurement", "rtmr1")):
            value = manifest(self.config)
            del value[group][field]
            self.refuses("manifest", lambda: r.manifest_gate(json.dumps(value), self.config, receipt()))
        value = manifest(self.config)
        value["firmware"]["sev_snp"]["sha256"] = "e" * 64
        self.refuses("manifest", lambda: r.manifest_gate(json.dumps(value), self.config, receipt()))

    def test_supported_signed_statement_shape_and_current_attempt(self):
        value = manifest(self.config)
        digest = r.sha(json.dumps(value).encode())
        checked = verified_statement(value, digest)
        r.statement_gate(checked, value, digest, environment())
        for field, bad in (("subjectAlternativeName", SECRET), ("buildSignerDigest", "e" * 40),
                           ("sourceRepositoryDigest", "e" * 40), ("sourceRepositoryRef", "refs/heads/main"),
                           ("runnerEnvironment", "self-hosted"),
                           ("runInvocationURI", f"https://github.com/{r.REPO}/actions/runs/123/attempts/2")):
            bad_checked = copy.deepcopy(checked)
            bad_checked[0]["verificationResult"]["signature"]["certificate"][field] = bad
            self.refuses("invocation" if field == "runInvocationURI" else "signature",
                         lambda: r.statement_gate(bad_checked, value, digest, environment()))
        for field, bad in (("predicateType", SECRET), ("predicate", {}), ("subject", [])):
            bad_checked = copy.deepcopy(checked)
            bad_checked[0]["verificationResult"]["statement"][field] = bad
            self.refuses("signature", lambda: r.statement_gate(bad_checked, value, digest, environment()))
        for bad in ([], [checked[0], checked[0]], True, [{"verificationResult": SECRET}], [{}]):
            self.refuses("signature", lambda: r.statement_gate(bad, value, digest, environment()))

    def test_verification_uses_supported_gh_exact_pins_no_fallback(self):
        calls = []
        def run(args, code, **kwargs):
            calls.append((args, code, kwargs))
            return b"[]"
        r.verify_file(Path("manifest.json"), PUBLIC, TAG, run)
        args, code, kwargs = calls[0]
        self.assertEqual(len(calls), 1)
        self.assertEqual(code, "signature")
        self.assertTrue(kwargs["token"])
        for flag, value in (("--repo", r.REPO), ("--source-ref", "refs/tags/" + TAG),
                            ("--source-digest", PUBLIC), ("--signer-digest", PUBLIC), ("--predicate-type", r.PREDICATE)):
            self.assertEqual(args[args.index(flag) + 1], value)
        self.assertIn("--deny-self-hosted-runners", args)
        self.assertNotIn(SECRET, " ".join(args))

    def test_closed_diagnostic_does_not_walk_exception_graphs(self):
        error = r.Stop(SECRET, outcome=SECRET, status=True)
        self.assertEqual(error.args, ())
        error.secondary = [error, RuntimeError(SECRET)]
        error.__cause__ = RuntimeError(SECRET)
        error.cleanup_failed = SECRET
        error.process_cleanup_failed = SECRET
        self.assertEqual(r.diagnostic(error)["code"], "SYNTHETIC_ARGUMENTS")
        self.assertEqual(r.diagnostic(error)["outcome"], "unknown")
        self.assertNotIn("additional_failures", r.diagnostic(error))
        error.code = SECRET
        error.status = SECRET
        error.outcome = SECRET
        self.assertNotIn(SECRET, json.dumps(r.diagnostic(error)))
        for status in (100, 404, 503, 599):
            self.assertEqual(r.diagnostic(r.Stop("transport", status=status))["status"], status)
        for status in (True, "403", 99, 600, SECRET):
            self.assertNotIn("status", r.diagnostic(r.Stop("transport", status=status)))

    def test_safe_unexpected_and_interrupt_keep_stage_no_hostile_text(self):
        for code in r.FAILURES:
            for error in (RuntimeError(SECRET), KeyboardInterrupt(SECRET)):
                def fault():
                    raise error
                self.refuses(code, lambda: r.safe(code, fault))
        known = r.Stop("assets", outcome="release_created", status=503)
        with self.assertRaises(r.Stop) as caught:
            r.safe("publication", lambda: (_ for _ in ()).throw(known))
        self.assertIs(caught.exception, known)

    def test_two_fixed_secondary_slots_keep_outcome(self):
        error = r.Stop("publication", outcome="release_created")
        error.cleanup_failed = error.reconciliation_failed = True
        error.cleanup_status, error.reconciliation_status = SECRET, 503
        detail = r.diagnostic(error)
        self.assertEqual([item["code"] for item in detail["additional_failures"]], ["SYNTHETIC_CLEANUP", "SYNTHETIC_TRANSPORT"])
        self.assertTrue(all(item["outcome"] == "release_created" for item in detail["additional_failures"]))
        self.assertNotIn(SECRET, json.dumps(detail))

    def test_public_get_http_status_and_hostile_body_boundaries(self):
        class Response:
            status = 200
            def __init__(self, raw):
                self.raw = raw
            def __enter__(self):
                return self
            def __exit__(self, *args):
                pass
            def read(self, limit):
                return self.raw[:limit]
        requests = []
        class Opener:
            def __init__(self, reply):
                self.reply = reply
            def open(self, request, timeout):
                requests.append(request)
                if isinstance(self.reply, BaseException):
                    raise self.reply
                return self.reply
        with patch.dict(os.environ, {"GH_TOKEN": SECRET}, clear=True):
            for status in (404, 401, 403, 302, 500):
                error = urllib.error.HTTPError("https://invalid.invalid/" + SECRET, status, SECRET, {}, io.BytesIO(SECRET.encode()))
                with patch.object(r.urllib.request, "build_opener", return_value=Opener(error)):
                    if status == 404:
                        self.assertEqual(r.public_get("/releases/tags/" + TAG), (404, None))
                    else:
                        caught = self.refuses("transport", lambda: r.public_get(""))
                        self.assertEqual(caught.status, status)
                self.assertTrue(error.fp is None or error.fp.closed)
            invalid_constants = [raw.encode() for constant in ("NaN", "Infinity", "-Infinity")
                                 for raw in (constant, '{"value":' + constant + '}',
                                             '{"nested":[{"value":' + constant + ',"hostile":"' + SECRET + '"}]}')]
            for raw in (SECRET.encode(), b"{", b"true", b"[]", b'{"a":1,"a":2}', b"x" * ((8 << 20) + 1), *invalid_constants):
                with patch.object(r.urllib.request, "build_opener", return_value=Opener(Response(raw))):
                    self.refuses("transport", lambda: r.public_get(""))
            for error in (OSError(SECRET), KeyboardInterrupt(SECRET)):
                with patch.object(r.urllib.request, "build_opener", return_value=Opener(error)):
                    self.refuses("transport", lambda: r.public_get(""))
            with patch.object(r.urllib.request, "build_opener", return_value=Opener(Response(b'{"private": false}'))):
                self.assertEqual(r.public_get(""), (200, {"private": False}))
        self.assertTrue(all(request.method == "GET" for request in requests))
        self.assertTrue(all(request.full_url.startswith("https://api.github.com/repos/" + r.REPO) for request in requests))
        self.assertIsNone(r.NoRedirect().redirect_request(None, None, None, None, None, None))
        with patch.dict(os.environ, {}, clear=True):
            self.refuses("transport", lambda: r.public_get(""))
        for path in ("../other", "/../other", "/x?credential=" + SECRET):
            self.refuses("transport", lambda: r.public_get(path))

    def test_bounded_file_duplicate_json_and_exclusive_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture"
            path.write_bytes(b"abcd")
            self.refuses("manifest", lambda: r.read_file(path, "manifest", 3))
            self.refuses("manifest", lambda: r.write_new(path, b"replace", "manifest"))
            self.assertEqual(path.read_bytes(), b"abcd")
            link = path.with_name("link")
            link.symlink_to(path)
            self.refuses("source", lambda: r.read_file(link, "source"))
            self.refuses("source", lambda: r.read_file(path.parent, "source"))

    def test_real_cli_status_and_render_offline_no_credentials_or_root_writes(self):
        admission_paths = [ROOT / name for name in ("accepted-image.json", "tinfoil-config.yml")]
        before = [path.read_bytes() if path.exists() else None for path in admission_paths]
        env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1", "GH_TOKEN": SECRET,
               "LEDGER_ADMIN_KEY": SECRET, "UNRELATED_SECRET": SECRET}
        with tempfile.TemporaryDirectory() as directory:
            receipt_path = Path(directory) / "receipt.json"
            receipt_path.write_text(json.dumps(receipt()))
            for args in (["status"], ["render", str(receipt_path), CVM], ["render", str(receipt_path), SECRET], [SECRET]):
                completed = subprocess.run([sys.executable, str(SCRIPT), *args], env=env, cwd=directory,
                                           capture_output=True, timeout=10)
                self.assertNotIn(SECRET.encode(), completed.stdout + completed.stderr)
                self.assertEqual(completed.stderr, b"")
                if args[0] == "status":
                    self.assertFalse(json.loads(completed.stdout)["runtime_verified"])
                elif args[-1] == CVM:
                    self.assertEqual(completed.stdout, self.config)
                    self.assertEqual(completed.returncode, 0)
                else:
                    self.assertEqual(completed.returncode, 1)
                self.assertEqual(sorted(path.name for path in Path(directory).iterdir()), ["receipt.json"])
        self.assertEqual([path.read_bytes() if path.exists() else None for path in admission_paths], before)

    def test_cli_unexpected_is_phase_specific(self):
        for arg, code in (("guard", "source"), ("measure", "measurement"), ("manifest", "manifest"),
                          ("publish", "publication"), ("verify-completed", "invocation"), ("render", "config")):
            stream = io.StringIO()
            with patch.object(r, "main", side_effect=RuntimeError(SECRET)), contextlib.redirect_stdout(stream):
                self.assertEqual(r.cli([arg]), 1)
            value = json.loads(stream.getvalue())
            self.assertEqual(value["code"], "SYNTHETIC_" + code.upper())
            self.assertEqual(value["outcome"], "unknown" if arg == "publish" else "no_effect")
            self.assertNotIn(SECRET, stream.getvalue())

    def test_cli_presentation_preserves_created_outcome(self):
        printed = []
        def failing_print(value):
            if not printed:
                printed.append(None)
                raise OSError(SECRET)
            printed.append(value)
        with patch.object(r, "main", return_value={"outcome": "release_created"}), patch("builtins.print", failing_print):
            self.assertEqual(r.cli(["publish"]), 1)
        value = json.loads(printed[1])
        self.assertEqual(value["code"], "SYNTHETIC_PRESENTATION")
        self.assertEqual(value["outcome"], "release_created")
        self.assertNotIn(SECRET, printed[1])

    def test_actual_child_process_environment_and_discarded_stderr(self):
        code = "import os,sys; assert os.environ['GH_TOKEN']; assert 'UNRELATED_SECRET' not in os.environ; sys.stdout.write('ok'); sys.stderr.write(os.environ['GH_TOKEN'])"
        argv = [sys.executable, "-c", code]
        self.assertNotIn(SECRET, " ".join(argv))
        with patch.dict(os.environ, {"GH_TOKEN": SECRET, "UNRELATED_SECRET": SECRET}, clear=False):
            self.assertEqual(r.command(argv, "measurement", token=True), (0, b"ok"))
            self.assertEqual(r.command([sys.executable, "-c", "import os; print('GH_TOKEN' in os.environ)"], "measurement"), (0, b"False\n"))
        with patch.dict(os.environ, {}, clear=True):
            self.refuses("measurement", lambda: r.command(argv, "measurement", token=True))

    def test_actual_process_nonzero_overflow_timeout_and_no_raw_error(self):
        argv = [sys.executable, "-c", "import os,sys; sys.stderr.write(os.environ['GH_TOKEN']); sys.exit(2)"]
        with patch.dict(os.environ, {"GH_TOKEN": SECRET}):
            self.refuses("signature", lambda: r.checked_command(argv, "signature", token=True))
        self.refuses("measurement", lambda: r.command([sys.executable, "-c", "import time; time.sleep(2)"], "measurement", timeout=0.01))
        self.refuses("measurement", lambda: r.command([sys.executable, "-c", "import sys; sys.stdout.buffer.write(b'x' * ((8 << 20) + 1))"], "measurement"))
        with patch.object(r.subprocess, "Popen", side_effect=OSError(SECRET)):
            self.refuses("measurement", lambda: r.command(["not-executed"], "measurement"))

    def test_docker_vendor_digest_and_env_name_only_no_registry_login(self):
        argv = r.docker_args(Path("config.yml"), Path("output"), "synthetic-measure-123-1")
        self.assertEqual(argv[-1], r.MEASURER)
        self.assertEqual(argv[argv.index("-e") + 1], "GH_TOKEN")
        self.assertNotIn(SECRET, " ".join(argv))
        self.assertNotIn("login", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--security-opt=no-new-privileges", argv)

    def test_measure_claims_name_before_attempt_and_cleans_joined_uncertain_create(self):
        for failure in (r.Stop("measurement"), RuntimeError(SECRET), KeyboardInterrupt(SECRET)):
            calls = []
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "output"
                def run(args, code, **kwargs):
                    calls.append(args)
                    if args[:2] == ["docker", "run"]:
                        self.assertTrue(output.exists())
                        raise failure  # Fake transport failed after possible container creation.
                    if args[:2] == ["docker", "ps"]:
                        return b"" if len(calls) == 1 else b"synthetic-measure-123-1\n"
                    return b""
                self.refuses("measurement", lambda: r.measure(Path("config"), output, "synthetic-measure-123-1", run))
            self.assertEqual([args[:2] for args in calls], [["docker", "ps"], ["docker", "run"], ["docker", "ps"], ["docker", "rm"]])
            self.assertEqual(sum(args[:2] == ["docker", "run"] for args in calls), 1)

    def test_measure_primary_and_cleanup_failure_both_survive(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def run(args, code, **kwargs):
                calls.append(args)
                if len(calls) == 1:
                    return b""
                if args[:2] == ["docker", "run"]:
                    raise r.Stop("measurement", outcome="unknown")
                raise RuntimeError(SECRET)
            error = self.refuses("measurement", lambda: r.measure(Path("config"), Path(directory) / "output", "synthetic-measure-123-1", run), "unknown")
            self.assertEqual(r.diagnostic(error)["additional_failures"][0]["code"], "SYNTHETIC_CLEANUP")
            self.assertEqual(len(calls), 3)

    def test_measure_cleanup_failure_after_success_is_not_silent(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def run(args, code, **kwargs):
                calls.append(args)
                if len(calls) <= 2:
                    return b""
                raise RuntimeError(SECRET)
            self.refuses("cleanup", lambda: r.measure(Path("config"), Path(directory) / "output", "synthetic-measure-123-1", run))
            self.assertEqual(len(calls), 3)

    def test_measure_never_removes_foreign_or_preexisting_name(self):
        for listing in (b"synthetic-measure-123-1\n", b"foreign\n"):
            calls = []
            def run(args, code, **kwargs):
                calls.append(args)
                return listing
            with tempfile.TemporaryDirectory() as directory:
                self.refuses("measurement", lambda: r.measure(Path("config"), Path(directory) / "output", "synthetic-measure-123-1", run))
            self.assertEqual(len(calls), 1)
            calls.clear()
            if listing == b"foreign\n":
                self.refuses("cleanup", lambda: r.cleanup_measurement("synthetic-measure-123-1", run))
                self.assertEqual(len(calls), 1)

    def test_measure_refuses_existing_output_and_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("bad-name", "synthetic-measure-0-1", "synthetic-measure-123-2"):
                self.refuses("measurement", lambda: r.measure(Path("config"), root / "missing", name, lambda *a, **k: self.fail("no command")))
            self.refuses("measurement", lambda: r.measure(Path("config"), root, "synthetic-measure-123-1", lambda *a, **k: self.fail("no command")))
            link = root / "link"
            link.symlink_to(root / "absent")
            self.refuses("measurement", lambda: r.measure(Path("config"), link, "synthetic-measure-123-1", lambda *a, **k: self.fail("no command")))

    def test_measure_output_permissions_after_cleanup_only(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            calls = []
            def run(args, code, **kwargs):
                calls.append(args)
                if args[:2] == ["docker", "run"]:
                    (output / "manifest").write_bytes(b"fixture")
                return b""
            r.measure(Path("config"), output, "synthetic-measure-123-1", run)
            self.assertEqual([args[0] for args in calls], ["docker", "docker", "docker", "sudo"])
            (output / "manifest").unlink()
            output.rmdir()
            def symlink_output(args, code, **kwargs):
                if args[:2] == ["docker", "run"]:
                    (output / "hostile").symlink_to(Path(directory) / "absent")
                if args[0] == "sudo":
                    self.fail("symlink must refuse chown")
                return b""
            self.refuses("permissions", lambda: r.measure(Path("config"), output, "synthetic-measure-123-1", symlink_output))

    def test_asset_metadata_strict_exact_bytes_and_scalar_types(self):
        files = {"tinfoil-deployment.json": b"manifest", "tinfoil.hash": b"hash\n"}
        value = {"tag_name": TAG, "target_commitish": PUBLIC, "draft": False, "prerelease": False,
                 "assets": [{"name": name, "state": "uploaded", "size": len(raw), "digest": "sha256:" + r.sha(raw)} for name, raw in files.items()]}
        r.release_metadata(value, TAG, PUBLIC, files)
        for key, bad in (("tag_name", "latest"), ("target_commitish", "main"), ("draft", 0), ("prerelease", True), ("assets", [])):
            changed = copy.deepcopy(value)
            changed[key] = bad
            self.refuses("assets", lambda: r.safe("assets", lambda: r.release_metadata(changed, TAG, PUBLIC, files)))
        for key, bad in (("name", SECRET), ("state", "new"), ("size", True), ("size", 99), ("digest", SECRET)):
            changed = copy.deepcopy(value)
            changed["assets"][0][key] = bad
            self.refuses("assets", lambda: r.safe("assets", lambda: r.release_metadata(changed, TAG, PUBLIC, files)))

    def test_live_create_one_verify_tag_nonlatest_no_tokens_in_argv(self):
        live = r.Live.__new__(r.Live)
        live.tag, live.commit, live.output = TAG, PUBLIC, Path("owned-output")
        calls = []
        with patch.object(r, "checked_command", side_effect=lambda *a, **k: calls.append((a, k))):
            live.create()
        self.assertEqual(len(calls), 1)
        args = calls[0][0][0]
        self.assertEqual(args[:3], ["gh", "release", "create"])
        self.assertIn("--verify-tag", args)
        self.assertIn("--latest=false", args)
        self.assertNotIn(SECRET, " ".join(args))
        self.assertTrue(calls[0][1]["token"])

    def test_passive_release_reconciliation_only_positive_is_evidence(self):
        live = r.Live.__new__(r.Live)
        live.tag = TAG
        for status, value, expected in ((404, None, False), (200, {"tag_name": TAG}, True)):
            with patch.object(r, "public_get", return_value=(status, value)):
                self.assertIs(live.release_exists(), expected)
        for status, value in ((200, True), (200, {"tag_name": "other"}), (500, None), ("200", {})):
            with patch.object(r, "public_get", return_value=(status, value)):
                self.refuses("transport", live.release_exists)

    def test_owned_child_join_fault_keeps_primary_and_fixed_cleanup_category(self):
        for kill_failure in (False, True):
            for join_failure in (False, True):
                if not (kill_failure or join_failure):
                    continue
                child = StuckChild(kill_failure=kill_failure, join_failure=join_failure)
                known = r.Stop("signature", status=503, outcome="release_created")
                with patch.object(r.subprocess, "Popen", return_value=child), \
                     patch.object(r.selectors, "DefaultSelector", side_effect=known):
                    error = self.refuses("signature", lambda: r.command(["not-executed"], "signature"), "release_created")
                self.assertIs(error, known)
                self.assertEqual(error.status, 503)
                self.assertEqual(child.waits, [r.PROCESS_JOIN_TIMEOUT])
                self.assertEqual(child.kills, 1)
                self.assertTrue(child.stdout.closed and child.stderr.closed)
                self.assertFalse(error.cleanup_failed)
                detail = r.diagnostic(error)
                self.assertEqual(detail["additional_failures"][0]["code"], "SYNTHETIC_PROCESS_CLEANUP")
                self.assertNotIn(SECRET, json.dumps(detail))
                self.assertNotIn(SECRET, repr(vars(error)))

    def test_unjoined_client_actual_cli_preserves_primary_and_unknown_outcome(self):
        child = StuckChild()
        stream = io.StringIO()
        with patch.object(r.subprocess, "Popen", return_value=child), \
             patch.object(r.selectors, "DefaultSelector", side_effect=KeyboardInterrupt(SECRET)), \
             patch.object(r, "main", side_effect=lambda args: r.command(["not-executed"], "measurement")), \
             contextlib.redirect_stdout(stream):
            self.assertEqual(r.cli(["measure"]), 1)
        detail = json.loads(stream.getvalue())
        self.assertEqual(detail["code"], "SYNTHETIC_MEASUREMENT")
        self.assertEqual(detail["outcome"], "unknown")
        self.assertEqual(detail["additional_failures"][0]["code"], "SYNTHETIC_PROCESS_CLEANUP")
        self.assertIn("Never retry", detail["additional_failures"][0]["next_step"])
        self.assertNotIn(SECRET, stream.getvalue())

    def test_cleanup_fault_after_observed_command_exit_never_returns_healthy(self):
        child = StuckChild()
        child.wait = unittest.mock.Mock(side_effect=[0, subprocess.TimeoutExpired(SECRET, 3)])
        selector = unittest.mock.MagicMock()
        selector.__enter__.return_value.get_map.return_value = {}
        with patch.object(r.subprocess, "Popen", return_value=child), \
             patch.object(r.selectors, "DefaultSelector", return_value=selector):
            error = self.refuses("process_cleanup", lambda: r.command(["not-executed"], "publication"), "release_created")
        self.assertFalse(error.cleanup_failed)
        self.assertEqual(child.wait.call_count, 2)
        self.assertEqual(child.wait.call_args.kwargs, {"timeout": r.PROCESS_JOIN_TIMEOUT})
        self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_actual_children_join_and_close_on_timeout_overflow_and_interruption(self):
        real_popen = subprocess.Popen
        for mode in ("timeout", "overflow", "interrupt"):
            children = []
            def spawn(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                children.append(child)
                return child
            script = "import time; time.sleep(30)"
            if mode == "overflow":
                script = "import sys,time; sys.stdout.buffer.write(b'x'*((8<<20)+1)); sys.stdout.flush(); time.sleep(30)"
            with patch.object(r.subprocess, "Popen", side_effect=spawn), contextlib.ExitStack() as stack:
                if mode == "interrupt":
                    stack.enter_context(patch.object(r.selectors, "DefaultSelector", side_effect=KeyboardInterrupt(SECRET)))
                error = self.refuses("measurement", lambda: r.command([sys.executable, "-c", script], "measurement",
                                                                      timeout=0.01 if mode == "timeout" else 10))
            self.assertFalse(error.process_cleanup_failed)
            self.assertIsNotNone(children[0].poll())
            self.assertTrue(children[0].stdout.closed and children[0].stderr.closed)

    def test_measure_skips_container_removal_when_client_join_unconfirmed(self):
        for code in ("measurement", "process_cleanup"):
            with tempfile.TemporaryDirectory() as directory:
                calls = []
                error = r.Stop(code, outcome="unknown")
                error.process_cleanup_failed = code == "measurement"
                def run(args, category, **kwargs):
                    calls.append(args)
                    if args[:2] == ["docker", "run"]:
                        raise error
                    return b""
                caught = self.refuses(code, lambda: r.measure(Path("config"), Path(directory) / "output",
                                                            "synthetic-measure-123-1", run), "unknown")
                self.assertEqual([args[:2] for args in calls], [["docker", "ps"], ["docker", "run"]])
                detail = r.diagnostic(caught)
                self.assertIn("SYNTHETIC_CLEANUP", [item["code"] for item in detail["additional_failures"]])
                self.assertTrue(caught.cleanup_failed)

    def test_measure_preserves_process_cleanup_failure_in_container_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def run(args, category, **kwargs):
                calls.append(args)
                if args[:2] == ["docker", "run"]:
                    raise r.Stop("measurement", outcome="unknown")
                if len(calls) > 2:
                    error = r.Stop("cleanup", outcome="unknown")
                    error.process_cleanup_failed = True
                    raise error
                return b""
            error = self.refuses("measurement", lambda: r.measure(Path("config"), Path(directory) / "output",
                                                                 "synthetic-measure-123-1", run), "unknown")
            self.assertEqual([item["code"] for item in r.diagnostic(error)["additional_failures"]],
                             ["SYNTHETIC_PROCESS_CLEANUP", "SYNTHETIC_CLEANUP"])

    def test_passive_status_initiates_zero_command_network_or_measurement(self):
        with patch.object(r, "command", side_effect=AssertionError("no command")), \
             patch.object(r, "public_get", side_effect=AssertionError("no network")), \
             patch.object(r, "measure", side_effect=AssertionError("no measurement")), \
             patch.object(r, "Live", side_effect=AssertionError("no live context")):
            self.assertTrue(r.main(["status"])["offline"])

    def test_http_cleanup_preserves_observed_status_not_absence(self):
        error = urllib.error.HTTPError("https://invalid.invalid", 404, SECRET, {}, io.BytesIO(b""))
        opener = unittest.mock.Mock()
        opener.open.side_effect = error
        with patch.dict(os.environ, {"GH_TOKEN": SECRET}, clear=True), \
             patch.object(r.urllib.request, "build_opener", return_value=opener), \
             patch.object(error, "close", side_effect=OSError(SECRET)):
            failure = self.refuses("transport", lambda: r.public_get(""))
        self.assertEqual(failure.status, 404)
        error.close()

    def test_full_cli_live_adapter_with_only_fake_git_docker_gh_and_http(self):
        # Real initialization, gates, output bytes, signed-shape parser and CLI.
        # Every tool/network result below is synthetic, not vendor qualification.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_files = {"accepted-image.json": json.dumps(receipt()).encode(),
                            "tinfoil-config.yml": self.config,
                            "templates/synthetic-config.yml.in": self.template,
                            "scripts/synthetic-release.py": SCRIPT.read_bytes(),
                            "scripts/test_synthetic_release.py": Path(__file__).read_bytes(),
                            r.WORKFLOW: (ROOT / r.WORKFLOW).read_bytes()}
            for name, raw in source_files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            payload = root / "event.json"
            payload.write_text(json.dumps(event()))
            env = {**environment(), "GITHUB_EVENT_PATH": str(payload), "GITHUB_OUTPUT": str(root / "github-output")}
            api, calls = PublicAPI(), []
            value = manifest(self.config)
            raw_manifest = json.dumps(value).encode()
            checked = verified_statement(value, r.sha(raw_manifest))
            def fake_command(args, code, **kwargs):
                calls.append(args)
                if args[0] == "git":
                    if args[1] == "rev-parse":
                        return 0, (PUBLIC + "\n").encode()
                    if args[1] == "ls-tree":
                        return 0, ("100644 blob " + "e" * 40 + "\t" + args[-1] + "\n").encode()
                    self.assertEqual(args[1], "show")
                    return 0, source_files[args[-1].removeprefix("HEAD:")]
                if args[:2] == ["docker", "ps"]:
                    return 0, b""
                if args[:2] == ["docker", "run"]:
                    (root / "output/tinfoil-deployment.json").write_bytes(raw_manifest)
                    return 0, b""
                if args[0] == "sudo":
                    return 0, b""
                if args[:3] == ["gh", "attestation", "verify"]:
                    return 0, json.dumps(checked).encode()
                if args[:3] == ["gh", "release", "create"]:
                    files = {name: (root / "output" / name).read_bytes() for name in ("tinfoil-deployment.json", "tinfoil.hash")}
                    api.values["/releases/tags/" + TAG] = 200, {
                        "tag_name": TAG, "target_commitish": PUBLIC, "draft": False, "prerelease": False,
                        "assets": [{"name": name, "state": "uploaded", "size": len(raw), "digest": "sha256:" + r.sha(raw)} for name, raw in files.items()]}
                    return 0, b"discarded tool output"
                self.fail("unexpected fake tool")
            real_live = r.Live
            with patch.dict(os.environ, env, clear=True), patch.object(r, "Live", side_effect=lambda: real_live(root)), \
                 patch.object(r, "command", side_effect=fake_command), patch.object(r, "public_get", side_effect=api):
                for args in (["guard"], ["measure"], ["manifest"], ["publish"]):
                    stream = io.StringIO()
                    with contextlib.redirect_stdout(stream):
                        self.assertEqual(r.cli(args), 0)
                    result = json.loads(stream.getvalue())
                    self.assertFalse(result["runtime_verified"])
                    self.assertNotIn(SECRET, stream.getvalue())
                self.assertEqual(result["signed_run_completion"], "pending_parent_check")
                self.assertEqual((root / "output/tinfoil.hash").read_bytes(), (r.sha(raw_manifest) + "\n").encode())
                self.assertEqual((root / "github-output").read_text(), "digest=sha256:" + r.sha(raw_manifest) + "\n")
                api.values["/actions/runs/123"][1].update(status="completed", conclusion="success")
                result = r.main(["verify-completed"])
                self.assertTrue(result["completed_signed_run_verified"])
                self.assertTrue(result["downloaded_asset_hashes_require_parent_check"])
                self.assertFalse(result["runtime_verified"])
            self.assertEqual(sum(args[:3] == ["gh", "release", "create"] for args in calls), 1)
            self.assertEqual(sum(args[:2] == ["docker", "run"] for args in calls), 1)
            self.assertFalse(any("login" in args or "retry" in args or "delete" in args for args in calls))
            self.assertNotIn(SECRET, json.dumps(calls))

    def test_workflow_stays_manual_explicit_default_false_and_pinned(self):
        text = (ROOT / r.WORKFLOW).read_text()
        self.assertIn("${{ inputs.publish == true", text)
        self.assertIn("default: false", text)
        self.assertIn("permissions: {}", text)
        self.assertIn("cancel-in-progress: false", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("ref: ${{ github.sha }}", text)
        self.assertIn("github.run_attempt == 1", text)
        self.assertIn("expected_private_source", text)
        self.assertIn("expected_image_digest", text)
        self.assertIn("actions/checkout@8e8c483db84b4bee98b60c0593521ed34d9990e8", text)
        self.assertIn("actions/attest@7667f588f2f73a90cea6c7ac70e78266c4f76616", text)
        self.assertIn("predicate-path: output/tinfoil-deployment.json", text)
        self.assertIn("subject-digest: ${{ steps.manifest.outputs.digest }}", text)
        self.assertIn(r.PREDICATE, text)
        for line in text.splitlines():
            if "uses:" in line:
                self.assertRegex(line, r"uses: actions/(checkout|attest)@[0-9a-f]{40}")
        for forbidden in ("workflow_run:", "push:", "pull_request:", "schedule:", "docker login", "secrets.", "gh workflow", "measure-image-action@v"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(text.count("python3 scripts/synthetic-release.py publish"), 1)


class StuckChild:
    """No real work; any unbounded wait/context exit fails immediately, not hangs."""
    def __init__(self, *, kill_failure=False, join_failure=True):
        self.stdout, self.stderr = io.BytesIO(), io.BytesIO()
        self.kill_failure, self.join_failure = kill_failure, join_failure
        self.waits, self.kills = [], 0

    def __enter__(self):
        raise AssertionError("Popen context manager must not be used")

    def __exit__(self, *args):
        raise AssertionError("Popen context exit must not be used")

    def poll(self):
        return None

    def kill(self):
        self.kills += 1
        if self.kill_failure:
            raise OSError(SECRET)

    def wait(self, timeout=None):
        if timeout is None:
            raise AssertionError("unbounded wait")
        self.waits.append(timeout)
        if self.join_failure:
            raise subprocess.TimeoutExpired(SECRET, timeout, output=SECRET, stderr=SECRET)
        return 0


class Port:
    def __init__(self):
        self.calls = []
        self.faults = {}
        self.exists = False

    def call(self, name):
        self.calls.append(name)
        error = self.faults.get(name)
        if error:
            raise error

    def gate(self):
        self.call("gate")

    def verify(self):
        self.call("verify")

    def create(self):
        self.call("create")

    def assets(self):
        self.call("assets")

    def release_exists(self):
        self.call("exists")
        return self.exists


class PublicationTests(unittest.TestCase):
    refuses = Checks.refuses

    def test_once_only_success_recheck_and_refused_second_attempt(self):
        port = Port()
        publication = r.Publication(port)
        result = publication.execute()
        self.assertEqual(port.calls, ["gate", "verify", "gate", "create", "assets"])
        self.assertEqual(result["outcome"], "release_created")
        self.assertEqual(result["signed_run_completion"], "pending_parent_check")
        self.assertFalse(result["runtime_verified"])
        self.refuses("publication", publication.execute, "release_created")
        self.assertEqual(port.calls.count("create"), 1)

    def test_precreation_faults_never_create(self):
        for stage, category in (("gate", "source"), ("verify", "signature")):
            for failure in (r.Stop(category), RuntimeError(SECRET), KeyboardInterrupt(SECRET)):
                port = Port()
                port.faults[stage] = failure
                self.refuses(category, r.Publication(port).execute)
                self.assertNotIn("create", port.calls)

    def test_recheck_fault_never_creates(self):
        port = Port()
        def gate():
            port.calls.append("gate")
            if port.calls.count("gate") == 2:
                raise RuntimeError(SECRET)
        port.gate = gate
        self.refuses("source", r.Publication(port).execute)
        self.assertNotIn("create", port.calls)

    def test_unknown_or_interrupted_create_zero_retries(self):
        for failure in (r.Stop("publication"), RuntimeError(SECRET), KeyboardInterrupt(SECRET)):
            port = Port()
            port.faults["create"] = failure
            publication = r.Publication(port)
            self.refuses("publication", publication.execute, "unknown")
            self.refuses("publication", publication.execute, "unknown")
            self.assertEqual(port.calls.count("create"), 1)
            self.assertEqual(port.calls[-1], "exists")
            self.assertNotIn("assets", port.calls)

    def test_unjoined_publication_client_only_positive_reconciliation_confirms_creation(self):
        for exists in (False, True):
            port = Port()
            port.exists = exists
            def create():
                port.calls.append("create")
                return r.checked_command(["not-executed"], "publication")
            port.create = create
            child = StuckChild()
            with patch.object(r.subprocess, "Popen", return_value=child), \
                 patch.object(r.selectors, "DefaultSelector", side_effect=RuntimeError(SECRET)):
                publication = r.Publication(port)
                error = self.refuses("publication", publication.execute, "release_created" if exists else "unknown")
                self.refuses("publication", publication.execute, publication.outcome)
            self.assertTrue(error.process_cleanup_failed)
            self.assertFalse(error.cleanup_failed)
            self.assertEqual(port.calls.count("create"), 1)
            self.assertEqual(port.calls[-1], "exists")
            self.assertNotIn("assets", port.calls)
            self.assertEqual(child.waits, [r.PROCESS_JOIN_TIMEOUT])

    def test_observed_cli_zero_survives_later_cleanup_without_reconciliation(self):
        port = Port()
        def create():
            port.calls.append("create")
            return r.checked_command(["not-executed"], "publication")
        port.create = create
        child = StuckChild()
        child.wait = unittest.mock.Mock(side_effect=[0, subprocess.TimeoutExpired(SECRET, 3)])
        selector = unittest.mock.MagicMock()
        selector.__enter__.return_value.get_map.return_value = {}
        stream = io.StringIO()
        with patch.object(r.subprocess, "Popen", return_value=child), \
             patch.object(r.selectors, "DefaultSelector", return_value=selector), \
             patch.object(r, "Live", return_value=port), contextlib.redirect_stdout(stream):
            self.assertEqual(r.cli(["publish"]), 1)
        detail = json.loads(stream.getvalue())
        self.assertEqual(detail["code"], "SYNTHETIC_PROCESS_CLEANUP")
        self.assertEqual(detail["outcome"], "release_created")
        self.assertNotIn("exists", port.calls)
        self.assertNotIn("assets", port.calls)
        self.assertEqual(port.calls.count("create"), 1)
        self.assertNotIn(SECRET, stream.getvalue())

    def test_partial_creation_positive_passive_reconciliation(self):
        port = Port()
        port.faults["create"] = RuntimeError(SECRET)
        port.exists = True
        self.refuses("publication", r.Publication(port).execute, "release_created")
        self.assertEqual(port.calls.count("create"), 1)
        self.assertNotIn("assets", port.calls)

    def test_reconciliation_fault_reported_alongside_primary(self):
        port = Port()
        port.faults = {"create": RuntimeError(SECRET), "exists": r.Stop("transport", status=503)}
        error = self.refuses("publication", r.Publication(port).execute, "unknown")
        detail = r.diagnostic(error)
        self.assertEqual(detail["additional_failures"][0]["code"], "SYNTHETIC_TRANSPORT")
        self.assertEqual(detail["additional_failures"][0]["status"], 503)
        self.assertEqual(port.calls.count("create"), 1)

    def test_created_outcome_survives_asset_failure_and_interrupt(self):
        for failure in (r.Stop("assets"), RuntimeError(SECRET), KeyboardInterrupt(SECRET)):
            port = Port()
            port.faults["assets"] = failure
            self.refuses("assets", r.Publication(port).execute, "release_created")
            self.assertNotIn("exists", port.calls)
            self.assertEqual(port.calls.count("create"), 1)

    def test_measurement_cleanup_fault_preserves_prior_creation_in_cli(self):
        # Synthetic post-create failure; NOT private COPY/publication evidence.
        port = Port()
        error = r.Stop("measurement")
        error.cleanup_failed = True
        port.faults["assets"] = error
        stream = io.StringIO()
        with patch.object(r, "Live", return_value=port), contextlib.redirect_stdout(stream):
            self.assertEqual(r.cli(["publish"]), 1)
        detail = json.loads(stream.getvalue())
        self.assertEqual(detail["outcome"], "release_created")
        self.assertEqual(detail["additional_failures"][0]["code"], "SYNTHETIC_CLEANUP")
        self.assertEqual(detail["additional_failures"][0]["outcome"], "release_created")
        self.assertNotIn(SECRET, stream.getvalue())


if __name__ == "__main__":
    unittest.main()
