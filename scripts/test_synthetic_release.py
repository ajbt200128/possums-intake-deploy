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
from unittest.mock import Mock, patch
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
CVM = "0.14.14"


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
            "RELEASE_IMAGE_DIGEST": receipt()["imageDigest"], "GITHUB_RUN_ID": "123",
            "RELEASE_STORAGE_PHASE": "disposable"}


def event():
    return {"ref": TAG, "repository": {"full_name": r.REPO}, "sender": {"login": r.OWNER},
            "inputs": {"publish": "true", "expected_public_commit": PUBLIC,
                       "expected_private_source": PRIVATE, "expected_image_digest": receipt()["imageDigest"],
                       "expected_storage_phase": "disposable"}}


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
    # Public release pins, independent of the implementation's expected values.
    hashes = {"version": "v0.14.14",
              "root": "41068e0738e14ee74d5b987586bdfc261d7bdd59e156dd6818154fd188b8ee7b",
              "kernel": "91b9c7979e00d4703cbabf9f6872639d23b1b60df88b971a7d49f11603ba4346",
              "initrd": "422948208e9d9aeddab46968ec7145eb9f0bf9dc82e9b6d0838cbf06995baada",
              "raw": "9634e66fe8761d227b2f39164dd13fbe54c3f1337b808287ce4a3477ee6d83a1"}
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
        self.assertTrue(self.config.startswith(b"cvm-version: 0.14.14\n"))
        for bad in ("0.14.14@sha256:" + "c" * 64, "0.14.14@sha256:" + "0" * 64,
                    "v0.14.14", "0.14.14 ", "0.14.14\n", "0.14.14-rc1", "0.15.0",
                    "0.15.0@sha256:" + "c" * 64, "0.14.7", "0.14.10",
                    "tinfoil-inference-v0.14.14.raw", SECRET, None):
            self.refuses("config", lambda: r.render(self.template, receipt(), bad))
            if isinstance(bad, str):
                changed = self.config.replace(b"cvm-version: 0.14.14\n", ("cvm-version: " + bad + "\n").encode())
                self.refuses("config", lambda: r.config_gate(changed, self.template, receipt()))
        for bad in (self.config + b"\n", self.config.replace(b"8192", b"4096"), self.config.replace(b"b" * 64, b"e" * 64)):
            self.refuses("config", lambda: r.config_gate(bad, self.template, receipt()))

    def test_exact_diagnostic_template_no_added_collection_or_privileges(self):
        expected = b"""cvm-version: @CVM_PIN@
cpus: 2
memory: 8192
gpus: 0
shim:
  upstream-port: 8090
  paths: ['/*']
containers:
  - name: intake-synthetic
    image: ghcr.io/ajbt200128/possums-intake-synthetic@@IMAGE_DIGEST@
    command: ['synthetic-serve', '--listen', '0.0.0.0:8090']
    user: '65532:65532'
    read_only: true
    tmpfs:
      /tmp: 'rw,nosuid,nodev,size=128m,mode=1777'
    healthcheck:
      test: ['CMD', '/proc/1/exe', 'synthetic-healthcheck']
      interval: '10s'
      timeout: '3s'
      retries: 1
      start_period: '5s'
    env:
      - OTEL_SDK_DISABLED: 'true'
      - LEDGER_SYNTHETIC_STARTUP_DIAGNOSTICS: 'true'
    secrets:
      - LEDGER_ADMIN_KEY
      - LEDGER_OPERATOR_EMAIL
      - LEDGER_OPERATOR_PASSWORD
"""
        self.assertEqual(self.template, expected)
        for old, new in ((b"synthetic-healthcheck", b"synthetic-serve"),
                         (b"'/proc/1/exe'", b"'/bin/sh'"),
                         (b"LEDGER_SYNTHETIC_STARTUP_DIAGNOSTICS: 'true'",
                          b"LEDGER_SYNTHETIC_STARTUP_DIAGNOSTICS: 'false'"),
                         (b"start_period: '5s'", b"start_period: '120s'"),
                         (b"OTEL_SDK_DISABLED: 'true'", b"OTEL_SDK_DISABLED: 'false'")):
            changed = self.template.replace(old, new)
            self.refuses("config", lambda: r.render(changed, receipt(), CVM))
            changed_config = self.config.replace(old, new)
            self.refuses("config", lambda: r.config_gate(changed_config, self.template, receipt()))

    def test_template_scope_exactly_three_names_no_volumes(self):
        text = self.config.decode()
        self.assertIn("cpus: 2\nmemory: 8192\ngpus: 0", text)
        self.assertIn("command: ['synthetic-serve', '--listen', '0.0.0.0:8090']", text)
        self.assertIn("read_only: true", text)
        self.assertIn("rw,nosuid,nodev,size=128m,mode=1777", text)
        self.assertIn("user: '65532:65532'", text)
        self.assertIn("OTEL_SDK_DISABLED: 'true'", text)
        self.assertIn("LEDGER_SYNTHETIC_STARTUP_DIAGNOSTICS: 'true'", text)
        self.assertEqual([line.strip() for line in text.split("    secrets:\n", 1)[1].splitlines()],
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
        names = ("accepted-image.json", "tinfoil-config.yml", "templates/synthetic-config.yml.in",
                 "templates/persistent-bootstrap-config.yml.in", "templates/persistent-serve-config.yml.in",
                 "templates/persistent-diagnostic-serve-config.yml.in",
                 "templates/persistent-ledger-init-config.yml.in",
                 "templates/persistent-ledger-replace-config.yml.in",
                 "templates/persistent-website-init-config.yml.in",
                 "templates/persistent-ledger-upgrade-config.yml.in",
                 "templates/persistent-observed-serve-config.yml.in",
                 "templates/persistent-live-payments-init-config.yml.in",
                 "templates/persistent-live-stripe-serve-config.yml.in",
                 "scripts/synthetic-release.py", "scripts/test_synthetic_release.py", r.WORKFLOW)
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
            for phase in ("persistent-live-payments-init", "persistent-live-stripe-serve"):
                name = "templates/" + r.PROFILES[phase][0]
                (root / name).write_bytes(b"changed")
                self.refuses("source", lambda: r.committed_files(root, PUBLIC, git))
                (root / name).write_bytes(contents[name])
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

    def test_manifest_rejects_every_wrong_verified_hash_and_version(self):
        for field in ("root", "kernel", "initrd", "raw"):
            for bad in ("e" * 64, "0" * 64, manifest(self.config)["hashes"][field].upper(),
                        True, None, SECRET):
                with self.subTest(field=field, bad_type=type(bad).__name__):
                    value = manifest(self.config)
                    value["hashes"][field] = bad
                    if field == "root" and isinstance(bad, str):
                        # Even a matching cmdline cannot authorize a different root.
                        value["cmdline"] = value["cmdline"].replace(manifest(self.config)["hashes"]["root"], bad)
                    self.refuses("manifest", lambda: r.manifest_gate(json.dumps(value), self.config, receipt()))
        for bad in ("v0.14.7", "v0.14.14-rc1", "v0.15.0", "0.14.14",
                    "v0.14.14@sha256:" + "c" * 64):
            value = manifest(self.config)
            value["hashes"]["version"] = bad
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
                            ("--cert-identity", f"https://github.com/{r.REPO}/.github/workflows/tinfoil-release.yml@refs/tags/{TAG}"),
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

    def test_measure_group_access_survives_umask_without_world_access(self):
        for mask in (0o022, 0o077, 0o777):
            with self.subTest(umask=mask), tempfile.TemporaryDirectory() as directory:
                # macOS inherits the temporary parent's group, unlike Linux's
                # ordinary non-setgid mkdir. Model the host-GID runner workspace.
                os.chown(directory, -1, os.getgid())
                output = Path(directory) / "output"
                calls = []
                def run(args, code, **kwargs):
                    calls.append((args, code, kwargs))
                    if args[:2] == ["docker", "run"]:
                        state = output.stat()
                        self.assertEqual(state.st_mode & 0o7777, 0o770)
                        self.assertEqual(state.st_uid, os.getuid())
                        self.assertEqual(state.st_gid, os.getgid())
                        self.assertEqual(args[args.index("--group-add") + 1], str(state.st_gid))
                        self.assertTrue(kwargs["token"])
                        self.assertEqual(kwargs["timeout"], 900)
                        (output / "manifest").write_bytes(b"fixture")
                        # Fake vendor has its own umask, not the host's mask.
                        (output / "manifest").chmod(0o644)
                    return b""
                previous = os.umask(mask)
                try:
                    r.measure(Path("config"), output, "synthetic-measure-123-1", run)
                finally:
                    os.umask(previous)
                self.assertEqual([item[0][0] for item in calls], ["docker", "docker", "docker", "sudo"])
                self.assertEqual((output / "manifest").read_bytes(), b"fixture")

    def test_measure_output_preparation_failure_never_invokes_vendor(self):
        for method, code in (("mkdir", "measurement"), ("chmod", "permissions")):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                calls = []
                def run(args, category, **kwargs):
                    calls.append(args)
                    return b""
                with patch.object(Path, method, side_effect=OSError(SECRET)):
                    error = self.refuses(code, lambda: r.measure(Path("config"), Path(directory) / "output",
                                                                 "synthetic-measure-123-1", run))
                self.assertEqual([args[:2] for args in calls], [["docker", "ps"]])
                self.assertFalse(error.cleanup_failed)
                self.assertNotIn(SECRET, repr(vars(error)))
                output = Path(directory) / "output"
                self.assertEqual(output.exists(), method == "chmod")
                if method == "chmod":
                    self.refuses("measurement", lambda: r.measure(Path("config"), output,
                                                                   "synthetic-measure-123-1", run))
                    self.assertEqual([args[:2] for args in calls], [["docker", "ps"]])

    def test_docker_numeric_group_preserves_exact_sandbox_and_default_user(self):
        with patch.object(r.os, "getgid", return_value=1001):
            argv = r.docker_args(Path("config.yml"), Path("output"), "synthetic-measure-123-1")
        self.assertEqual(argv, ["docker", "run", "--rm", "--name", "synthetic-measure-123-1",
            "--group-add", "1001", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
            "--tmpfs", "/tmp", "--tmpfs", "/cache", "--tmpfs", "/root/.cache",
            "-v", "config.yml:/config.yml:ro", "-v", "output:/output", "-e", "GH_TOKEN", r.MEASURER])

    def test_manual_linux_probe_is_explicit_local_cached_and_credential_free(self):
        calls = []
        def command(args, code, **kwargs):
            calls.append((args, kwargs))
            self.assertEqual(args[:3], ["docker", "--host", "unix:///var/run/docker.sock"])
            self.assertFalse(kwargs.get("token", False))
            if args[3] == "info":
                return 0, b'"linux"'
            if args[3:5] == ["image", "inspect"]:
                return 0, b'"root"'
            if args[3] == "ps":
                return 0, b""
            self.assertEqual(args[3], "run")
            self.assertIn("--pull=never", args)
            self.assertIn("--network=none", args)
            self.assertIn("--cap-drop=ALL", args)
            self.assertIn("--read-only", args)
            self.assertIn("--security-opt=no-new-privileges", args)
            self.assertEqual(args[args.index("--entrypoint") + 1], "/bin/sh")
            self.assertNotIn("-e", args)
            self.assertNotIn("--user", args)
            self.assertIn(r.MEASURER, args)
            output = Path(args[args.index("-v") + 1].removesuffix(":/output"))
            if "--group-add" not in args:
                self.assertEqual(output.stat().st_mode & 0o777, 0o700)
                return 23, b""
            self.assertEqual(output.stat().st_mode & 0o777, 0o770)
            self.assertEqual(args[args.index("--group-add") + 1], "1001")
            (output / "marker").write_bytes(b"synthetic")
            return 0, b""
        with patch.object(sys, "platform", "linux"), patch.object(os, "getuid", return_value=1001), \
             patch.object(os, "getgid", return_value=1001), patch.object(r, "command", side_effect=command):
            result = linux_output_probe()
        self.assertTrue(result["stage0_denied"] and result["stage1_group_write"])
        self.assertFalse(result["sdk_measurement"] or result["observed_failure_cause_verified"])
        self.assertEqual(sum(args[3] == "run" for args, _ in calls), 2)

    def test_manual_linux_probe_refuses_nonlinux_and_missing_cache(self):
        with patch.object(sys, "platform", "darwin"), patch.object(r, "command", side_effect=AssertionError("no command")):
            self.refuses("permissions", linux_output_probe)
        calls = []
        def command(args, code, **kwargs):
            calls.append(args)
            return (0, b'"linux"') if args[3] == "info" else (1, b"")
        with patch.object(sys, "platform", "linux"), patch.object(os, "getuid", return_value=1001), \
             patch.object(os, "getgid", return_value=1001), patch.object(r, "command", side_effect=command):
            self.refuses("permissions", linux_output_probe)
        self.assertEqual([args[3] for args in calls], ["info", "image"])

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
        r.release_metadata({**value, "target_commitish": "main"}, TAG, PUBLIC, files)
        for key, bad in (("tag_name", "latest"), ("target_commitish", "other-branch"), ("draft", 0), ("prerelease", True), ("assets", [])):
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
                            "templates/persistent-bootstrap-config.yml.in": (ROOT / "templates/persistent-bootstrap-config.yml.in").read_bytes(),
                            "templates/persistent-serve-config.yml.in": (ROOT / "templates/persistent-serve-config.yml.in").read_bytes(),
                            "templates/persistent-diagnostic-serve-config.yml.in": (ROOT / "templates/persistent-diagnostic-serve-config.yml.in").read_bytes(),
                            "templates/persistent-ledger-init-config.yml.in": (ROOT / "templates/persistent-ledger-init-config.yml.in").read_bytes(),
                            "templates/persistent-ledger-replace-config.yml.in": (ROOT / "templates/persistent-ledger-replace-config.yml.in").read_bytes(),
                            "templates/persistent-website-init-config.yml.in": (ROOT / "templates/persistent-website-init-config.yml.in").read_bytes(),
                            "templates/persistent-ledger-upgrade-config.yml.in": (ROOT / "templates/persistent-ledger-upgrade-config.yml.in").read_bytes(),
                            "templates/persistent-observed-serve-config.yml.in": (ROOT / "templates/persistent-observed-serve-config.yml.in").read_bytes(),
                            "templates/persistent-live-payments-init-config.yml.in": (ROOT / "templates/persistent-live-payments-init-config.yml.in").read_bytes(),
                            "templates/persistent-live-stripe-serve-config.yml.in": (ROOT / "templates/persistent-live-stripe-serve-config.yml.in").read_bytes(),
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

    def test_renamed_workflow_identity_rejects_old_path_without_fallback(self):
        self.assertEqual(r.WORKFLOW, ".github/workflows/tinfoil-release.yml")
        self.assertFalse((ROOT / ".github/workflows/tinfoil-release.yaml").exists())
        self.assertFalse((ROOT / ".github/workflows/tinfoil-release-publish.yml").exists())
        api = PublicAPI()
        api.values["/actions/runs/123"][1]["path"] = ".github/workflows/tinfoil-release-publish.yml"
        self.refuses("invocation", lambda: r.public_gate(environment(), event(), receipt(), api))
        value = manifest(self.config)
        digest = r.sha(json.dumps(value).encode())
        checked = verified_statement(value, digest)
        checked[0]["verificationResult"]["signature"]["certificate"]["subjectAlternativeName"] = (
            f"https://github.com/{r.REPO}/.github/workflows/tinfoil-release-publish.yml@refs/tags/{TAG}")
        self.refuses("signature", lambda: r.statement_gate(checked, value, digest, environment()))

    def test_workflow_stays_manual_explicit_default_false_and_pinned(self):
        text = (ROOT / r.WORKFLOW).read_text()
        self.assertIn("name: Tinfoil Release\n", text)
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
        official = "uses: tinfoilsh/measure-image-action@59f7ab5dbe472b3097c888ebe64e6a4131fc0975"
        self.assertEqual(text.count(official), 1)
        self.assertIn("config-file: ${{ github.workspace }}/tinfoil-config.yml", text)
        self.assertIn("github-token: ${{ secrets.GITHUB_TOKEN }}", text)
        self.assertIn("mark-as-latest: 'false'", text)
        self.assertLess(text.index("python3 scripts/synthetic-release.py guard"), text.index(official))
        self.assertNotIn("if:", text[text.index("      - name: Official Tinfoil"):])
        for line in text.splitlines():
            if "uses:" in line:
                self.assertRegex(line, r"uses: (actions/checkout|tinfoilsh/measure-image-action)@[0-9a-f]{40}")
        for forbidden in ("workflow_run:", "push:", "pull_request:", "schedule:", "docker login", "gh workflow", "measure-image-action@v",
                          "python3 scripts/synthetic-release.py measure", "python3 scripts/synthetic-release.py manifest",
                          "python3 scripts/synthetic-release.py publish", "uses: actions/attest@"):
            self.assertNotIn(forbidden, text)
        self.assertEqual(text.count("secrets."), 1)


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


def linux_output_probe():
    """Explicit manual Linux DAC fixture, never discovery/SDK measurement.

    Requires the already-running local daemon and already-cached pinned image.
    Reject translated bind ownership; no pull, credentials, network or SDK entrypoint.
    """
    r.require(sys.platform == "linux" and os.getuid() != 0 and os.getgid() != 0, "permissions")
    endpoint = ["docker", "--host", "unix:///var/run/docker.sock"]
    def run(args, code, **kwargs):
        return r.checked_command(endpoint + args[1:], code, **kwargs)
    r.require(run(["docker", "info", "--format", "{{json .OSType}}"], "permissions").strip() == b'"linux"', "permissions")
    user = r.decode(run(["docker", "image", "inspect", r.MEASURER, "--format", "{{json .Config.User}}"], "permissions"), "permissions")
    r.require(user in ("", "root", "0", "0:0"), "permissions")
    # Exit 23 means the fixed write was denied, not a classified SDK failure.
    shell = ('test "$(id -u)" = 0 && '
             'test "$(awk \'/^CapEff:/{print $2}\' /proc/self/status)" = 0000000000000000 && '
             'test "$(stat -c %u /output)" = "$1" && '
             'test "$(stat -c %g /output)" = "$2" || exit 24; '
             'if (printf synthetic > /output/marker) 2>/dev/null; then exit 0; else exit 23; fi')
    with tempfile.TemporaryDirectory() as directory:
        output = Path(directory) / "output"
        output.mkdir(mode=0o700)
        for group, mode, expected in ((False, 0o700, 23), (True, 0o770, 0)):
            output.chmod(mode)
            name = "synthetic-measure-" + str(os.getpid()) + "-1"
            r.require(run(["docker", "ps", "-a", "--filter", "name=^/" + name + "$",
                           "--format", "{{.Names}}"], "permissions") == b"", "permissions")
            args = ["run", "--rm", "--pull=never", "--name", name, "--network=none",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
                    "--tmpfs", "/tmp", "--tmpfs", "/cache", "--tmpfs", "/root/.cache",
                    "-v", str(output) + ":/output", "--entrypoint", "/bin/sh"]
            if group:
                args += ["--group-add", str(os.getgid())]
            args += [r.MEASURER, "-c", shell, "probe", str(os.getuid()), str(os.getgid())]
            try:
                result, _ = r.command(endpoint + args, "permissions", timeout=30)
            except r.Stop as error:
                if not error.process_cleanup_failed and error.code != "process_cleanup":
                    try:
                        r.cleanup_measurement(name, run)
                    except r.Stop as cleanup:
                        error.cleanup_failed = True
                        error.cleanup_status = cleanup.status
                        error.process_cleanup_failed |= cleanup.process_cleanup_failed or cleanup.code == "process_cleanup"
                        if error.process_cleanup_failed:
                            error.outcome = "unknown"
                else:
                    error.cleanup_failed = True
                raise
            r.cleanup_measurement(name, run)
            r.require(result == expected, "permissions")
            r.require((output / "marker").exists() is group, "permissions")
            if group:
                r.require((output / "marker").read_bytes() == b"synthetic", "permissions")
    return {"offline_fixture": True, "stage0_denied": True, "stage1_group_write": True,
            "sdk_measurement": False, "observed_failure_cause_verified": False}


class PersistentChecks(unittest.TestCase):
    setUp = Checks.setUp
    refuses = Checks.refuses

    def template_for(self, phase):
        return (ROOT / "templates" / r.PROFILES[phase][0]).read_bytes()

    def test_exact_profiles_and_one_shot_commands(self):
        self.assertEqual(set(r.PROFILES), {"disposable", "persistent-bootstrap", "persistent-serve", "persistent-diagnostic-serve", "persistent-ledger-init", "persistent-ledger-replace", "persistent-website-init", "persistent-ledger-upgrade", "persistent-observed-serve", "persistent-live-payments-init", "persistent-live-stripe-serve"})
        for phase in ("persistent-bootstrap", "persistent-serve", "persistent-diagnostic-serve", "persistent-ledger-init", "persistent-ledger-replace", "persistent-website-init", "persistent-ledger-upgrade"):
            template = self.template_for(phase)
            config = r.render(template, receipt(), CVM, phase)
            r.config_gate(config, template, receipt(), phase)
            self.assertIn(b"    owner: 65532\n", template)
            self.assertIn(b"    persistent_volumes: ['ledger:/state']\n", template)
            self.assertIn(b"    restart: 'no'\n", template)
            self.assertIn(b"    read_only: true\n", template)
            self.assertIn(b"      - LEDGER_VOLUME_KEY_B64\n", template)
            self.assertIn(b"      - OTEL_SDK_DISABLED: 'true'\n", template)
            for forbidden in (b"key-secret", b"keyserver", b"LEDGER_SYNTHETIC_STARTUP_DIAGNOSTICS", b"synthetic-serve"):
                self.assertNotIn(forbidden, template)
            if phase in ("persistent-website-init", "persistent-ledger-upgrade"):
                command = phase.removeprefix("persistent-")
                self.assertIn(f"  - name: intake-{phase}\n".encode(), template)
                self.assertIn(f"['{command}', '--state', '/state/ledger', '--tinfoil-volume', 'ledger']".encode(), template)
                for forbidden in (b"--initialize-volume", b"--operator", b"healthcheck:", b"--listen", b"LEDGER_ADMIN_KEY",
                                  b"LEDGER_OPERATOR_EMAIL", b"LEDGER_OPERATOR_PASSWORD",
                                  b"LEDGER_MANAGED_STARTUP_DIAGNOSTICS"):
                    self.assertNotIn(forbidden, template)
                self.assertEqual(template.split(b"    secrets:\n", 1)[1], b"      - LEDGER_VOLUME_KEY_B64\n")
            elif phase in ("persistent-ledger-init", "persistent-ledger-replace"):
                command = (b"['init', '--state', '/state/ledger', '--tinfoil-volume', 'ledger', '--operator']"
                           if phase == "persistent-ledger-init" else
                           b"['ledger-replace', '--state', '/state/ledger', '--tinfoil-volume', 'ledger', '--operator', '--discard-existing-ledger']")
                self.assertIn(command, template)
                for forbidden in (b"--initialize-volume", b"healthcheck:", b"--listen", b"LEDGER_ADMIN_KEY",
                                  b"LEDGER_MANAGED_STARTUP_DIAGNOSTICS"):
                    self.assertNotIn(forbidden, template)
                self.assertIn(b"      - LEDGER_OPERATOR_EMAIL\n      - LEDGER_OPERATOR_PASSWORD\n", template)
            elif phase == "persistent-bootstrap":
                self.assertIn(b"['init', '--state', '/state/ledger', '--tinfoil-volume', 'ledger', '--initialize-volume', '--operator']", template)
                for forbidden in (b"healthcheck:", b"--listen", b"LEDGER_ADMIN_KEY"):
                    self.assertNotIn(forbidden, template)
                self.assertIn(b"      - LEDGER_OPERATOR_EMAIL\n      - LEDGER_OPERATOR_PASSWORD\n", template)
            else:
                self.assertIn(b"['serve', '--state', '/state/ledger', '--tinfoil-volume', 'ledger', '--operator', '--listen', '0.0.0.0:8090']", template)
                self.assertIn(b"['CMD', '/bin/intake', 'synthetic-healthcheck']", template)
                self.assertIn(b"      - LEDGER_ADMIN_KEY\n", template)
                for forbidden in (b"--initialize-volume", b"LEDGER_OPERATOR_EMAIL", b"LEDGER_OPERATOR_PASSWORD"):
                    self.assertNotIn(forbidden, template)

    def test_template_or_rendered_config_mutation_refused(self):
        for phase in ("persistent-bootstrap", "persistent-serve", "persistent-diagnostic-serve", "persistent-ledger-init",
                      "persistent-ledger-replace", "persistent-website-init", "persistent-ledger-upgrade"):
            template = self.template_for(phase)
            config = r.render(template, receipt(), CVM, phase)
            for before, after in ((b"owner: 65532", b"owner: 0"),
                                  (b"restart: 'no'", b"restart: 'always'"),
                                  (b"ledger:/state", b"other:/state"),
                                  (b"/state/ledger", b"/state"),
                                  (b"LEDGER_VOLUME_KEY_B64", b"OTHER_FIXTURE_SECRET"),
                                  (b"OTEL_SDK_DISABLED: 'true'", b"OTEL_SDK_DISABLED: 'false'")):
                self.refuses("config", lambda: r.render(template.replace(before, after), receipt(), CVM, phase))
                self.refuses("config", lambda: r.config_gate(config.replace(before, after), template, receipt(), phase))
            if phase in ("persistent-serve", "persistent-diagnostic-serve"):
                self.refuses("config", lambda: r.render(template.replace(b"['serve',", b"['serve', '--initialize-volume',"), receipt(), CVM, phase))
                self.refuses("config", lambda: r.config_gate(config.replace(b"['serve',", b"['serve', '--initialize-volume',"), template, receipt(), phase))
            for addition in (b"\n", b"keyserver-url: hostile\n", b"networks: {}\n"):
                self.refuses("config", lambda: r.render(template + addition, receipt(), CVM, phase))
                self.refuses("config", lambda: r.config_gate(config + addition, template, receipt(), phase))

    def test_ledger_init_exact_template_render_and_manifest(self):
        phase = "persistent-ledger-init"
        template = self.template_for(phase)
        expected = b"""cvm-version: @CVM_PIN@
cpus: 2
memory: 8192
gpus: 0
volumes:
  - name: ledger
    owner: 65532
shim:
  upstream-port: 8090
  paths: ['/*']
containers:
  - name: intake-persistent-ledger-init
    image: ghcr.io/ajbt200128/possums-intake-synthetic@@IMAGE_DIGEST@
    command: ['init', '--state', '/state/ledger', '--tinfoil-volume', 'ledger', '--operator']
    user: '65532:65532'
    read_only: true
    restart: 'no'
    persistent_volumes: ['ledger:/state']
    tmpfs:
      /tmp: 'rw,nosuid,nodev,size=128m,mode=1777'
    env:
      - OTEL_SDK_DISABLED: 'true'
    secrets:
      - LEDGER_VOLUME_KEY_B64
      - LEDGER_OPERATOR_EMAIL
      - LEDGER_OPERATOR_PASSWORD
"""
        self.assertEqual(template, expected)
        self.assertEqual(r.PROFILES[phase], ("persistent-ledger-init-config.yml.in",
                         "8acff60da11650f0ccea6cf0eea1739cf58b14fcf3af68b80c89037e25784d45", 4))
        self.assertEqual(r.sha(template), r.PROFILES[phase][1])
        config = r.render(template, receipt(), CVM, phase)
        self.assertEqual(config, expected.replace(b"@CVM_PIN@", CVM.encode()).replace(
            b"@IMAGE_DIGEST@", receipt()["imageDigest"].encode()))
        r.config_gate(config, template, receipt(), phase)
        value = manifest(config)
        value["vm_shape"]["disks"] = 4
        self.assertEqual(r.manifest_gate(json.dumps(value), config, receipt(), phase), value)
        self.assertEqual(r.render(self.template, receipt(), CVM), self.config)
        r.config_gate(self.config, self.template, receipt())
        self.refuses("config", lambda: r.render(template, receipt(), CVM))
        self.refuses("config", lambda: r.config_gate(config, template, receipt()))

    def test_ledger_init_mutations_stop_before_guard_side_effects(self):
        phase = "persistent-ledger-init"
        template = self.template_for(phase)
        config = r.render(template, receipt(), CVM, phase)
        mutations = ((b"'--operator']", b"'--initialize-volume', '--operator']"),
                     (b"['init',", b"['serve',"),
                     (b"'--operator']", b"'--operator', '--listen', '0.0.0.0:8090']"),
                     (b"    env:\n", b"    healthcheck:\n      test: ['CMD', '/bin/intake', 'synthetic-healthcheck']\n    env:\n"),
                     (b"      - OTEL_SDK_DISABLED: 'true'\n",
                      b"      - OTEL_SDK_DISABLED: 'true'\n      - LEDGER_MANAGED_STARTUP_DIAGNOSTICS: 'true'\n"),
                     (b"    secrets:\n", b"    secrets:\n      - LEDGER_ADMIN_KEY\n"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "templates").mkdir()
            (root / "accepted-image.json").write_text(json.dumps(receipt()))
            env, payload = environment(), event()
            env["RELEASE_STORAGE_PHASE"] = payload["inputs"]["expected_storage_phase"] = phase
            env["GITHUB_EVENT_PATH"] = str(root / "event.json")
            (root / "event.json").write_text(json.dumps(payload))
            real_live = r.Live
            with patch.dict(os.environ, env, clear=True), patch.object(r, "committed_files") as committed, \
                 patch.object(r, "command") as command, patch.object(r, "public_get") as get, \
                 patch.object(r, "measure") as measure, patch.object(r, "Live", side_effect=lambda: real_live(root)):
                for before, after in mutations:
                    with self.subTest(mutation=before):
                        self.assertIn(before, template)
                        changed_template = template.replace(before, after)
                        changed_config = config.replace(before, after)
                        self.refuses("config", lambda: r.render(changed_template, receipt(), CVM, phase))
                        self.refuses("config", lambda: r.config_gate(changed_config, template, receipt(), phase))
                        for supplied_template in (template, changed_template):
                            (root / "templates" / r.PROFILES[phase][0]).write_bytes(supplied_template)
                            (root / "tinfoil-config.yml").write_bytes(changed_config)
                            stream = io.StringIO()
                            with contextlib.redirect_stdout(stream):
                                self.assertEqual(r.cli(["guard"]), 1)
                            self.assertEqual(json.loads(stream.getvalue())["code"], "SYNTHETIC_CONFIG")
                            self.assertFalse((root / "output").exists())
                committed.assert_not_called()
                command.assert_not_called()
                get.assert_not_called()
                measure.assert_not_called()

    def test_website_init_exact_template_render_and_manifest(self):
        phase = "persistent-website-init"
        template = self.template_for(phase)
        # Byte-derived from the guarded ledger-init template: only the container
        # name, the commands and the removed operator secret names differ.
        ledger = self.template_for("persistent-ledger-init")
        expected = (ledger
                    .replace(b"  - name: intake-persistent-ledger-init\n", b"  - name: intake-persistent-website-init\n")
                    .replace(b"['init', '--state', '/state/ledger', '--tinfoil-volume', 'ledger', '--operator']",
                             b"['website-init', '--state', '/state/ledger', '--tinfoil-volume', 'ledger']")
                    .replace(b"      - LEDGER_OPERATOR_EMAIL\n      - LEDGER_OPERATOR_PASSWORD\n", b""))
        self.assertEqual(template, expected)
        self.assertEqual(r.PROFILES[phase], ("persistent-website-init-config.yml.in",
                         "c1ec50de7f612e0691f5813dbeaacbf14ea04d43dc21fc229f0c7436e3b4d776", 4))
        self.assertEqual(r.sha(template), r.PROFILES[phase][1])
        # The existing five templates remain byte-identical to their pins.
        for other in ("disposable", "persistent-bootstrap", "persistent-ledger-init",
                      "persistent-serve", "persistent-diagnostic-serve"):
            self.assertEqual(r.sha(self.template_for(other)), r.PROFILES[other][1])
        config = r.render(template, receipt(), CVM, phase)
        self.assertEqual(config, expected.replace(b"@CVM_PIN@", CVM.encode()).replace(
            b"@IMAGE_DIGEST@", receipt()["imageDigest"].encode()))
        r.config_gate(config, template, receipt(), phase)
        value = manifest(config)
        value["vm_shape"]["disks"] = 4
        self.assertEqual(r.manifest_gate(json.dumps(value), config, receipt(), phase), value)
        self.refuses("config", lambda: r.render(template, receipt(), CVM))
        self.refuses("config", lambda: r.config_gate(config, template, receipt()))

    def test_website_init_mutations_stop_before_guard_side_effects(self):
        phase = "persistent-website-init"
        template = self.template_for(phase)
        config = r.render(template, receipt(), CVM, phase)
        mutations = ((b"'--tinfoil-volume', 'ledger']", b"'--tinfoil-volume', 'ledger', '--initialize-volume']"),
                     (b"['website-init',", b"['init',"),
                     (b"'--tinfoil-volume', 'ledger']", b"'--tinfoil-volume', 'ledger', '--operator']"),
                     (b"'--tinfoil-volume', 'ledger']", b"'--tinfoil-volume', 'ledger', '--listen', '0.0.0.0:8090']"),
                     (b"    env:\n", b"    healthcheck:\n      test: ['CMD', '/bin/intake', 'synthetic-healthcheck']\n    env:\n"),
                     (b"      - OTEL_SDK_DISABLED: 'true'\n",
                      b"      - OTEL_SDK_DISABLED: 'true'\n      - LEDGER_MANAGED_STARTUP_DIAGNOSTICS: 'true'\n"),
                     (b"    secrets:\n", b"    secrets:\n      - LEDGER_ADMIN_KEY\n"),
                     (b"    secrets:\n", b"    secrets:\n      - LEDGER_OPERATOR_EMAIL\n"),
                     (b"    secrets:\n", b"    secrets:\n      - LEDGER_OPERATOR_PASSWORD\n"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "templates").mkdir()
            (root / "accepted-image.json").write_text(json.dumps(receipt()))
            env, payload = environment(), event()
            env["RELEASE_STORAGE_PHASE"] = payload["inputs"]["expected_storage_phase"] = phase
            env["GITHUB_EVENT_PATH"] = str(root / "event.json")
            (root / "event.json").write_text(json.dumps(payload))
            real_live = r.Live
            with patch.dict(os.environ, env, clear=True), patch.object(r, "committed_files") as committed, \
                 patch.object(r, "command") as command, patch.object(r, "public_get") as get, \
                 patch.object(r, "measure") as measure, patch.object(r, "Live", side_effect=lambda: real_live(root)):
                for before, after in mutations:
                    with self.subTest(mutation=after):
                        self.assertIn(before, template)
                        changed_template = template.replace(before, after)
                        changed_config = config.replace(before, after)
                        self.refuses("config", lambda: r.render(changed_template, receipt(), CVM, phase))
                        self.refuses("config", lambda: r.config_gate(changed_config, template, receipt(), phase))
                        for supplied_template in (template, changed_template):
                            (root / "templates" / r.PROFILES[phase][0]).write_bytes(supplied_template)
                            (root / "tinfoil-config.yml").write_bytes(changed_config)
                            stream = io.StringIO()
                            with contextlib.redirect_stdout(stream):
                                self.assertEqual(r.cli(["guard"]), 1)
                            self.assertEqual(json.loads(stream.getvalue())["code"], "SYNTHETIC_CONFIG")
                            self.assertFalse((root / "output").exists())
                committed.assert_not_called()
                command.assert_not_called()
                get.assert_not_called()
                measure.assert_not_called()

    def test_ledger_upgrade_exact_template_render_and_four_disk_manifest(self):
        phase = "persistent-ledger-upgrade"
        template = self.template_for(phase)
        # Only the container name and command differ from website setup.
        website = self.template_for("persistent-website-init")
        expected = (website
                    .replace(b"  - name: intake-persistent-website-init\n", b"  - name: intake-persistent-ledger-upgrade\n")
                    .replace(b"['website-init', '--state', '/state/ledger', '--tinfoil-volume', 'ledger']",
                             b"['ledger-upgrade', '--state', '/state/ledger', '--tinfoil-volume', 'ledger']"))
        self.assertEqual(template, expected)
        self.assertEqual(r.PROFILES[phase], ("persistent-ledger-upgrade-config.yml.in",
                         "721c6b0549e5cd0e46bb682df233caa10a1ccc7f1cb05461d39c29d6278ff831", 4))
        self.assertEqual(r.sha(template), r.PROFILES[phase][1])
        for other in ("disposable", "persistent-bootstrap", "persistent-ledger-init",
                      "persistent-website-init", "persistent-serve", "persistent-diagnostic-serve"):
            self.assertEqual(r.sha(self.template_for(other)), r.PROFILES[other][1])
        config = r.render(template, receipt(), CVM, phase)
        self.assertEqual(config, expected.replace(b"@CVM_PIN@", CVM.encode()).replace(
            b"@IMAGE_DIGEST@", receipt()["imageDigest"].encode()))
        r.config_gate(config, template, receipt(), phase)
        value = manifest(config)
        value["vm_shape"]["disks"] = 4
        self.assertEqual(r.manifest_gate(json.dumps(value), config, receipt(), phase), value)
        for disks in (3, 5, True, "4"):
            changed = copy.deepcopy(value)
            changed["vm_shape"]["disks"] = disks
            self.refuses("manifest", lambda: r.manifest_gate(json.dumps(changed), config, receipt(), phase))
        self.refuses("config", lambda: r.render(template, receipt(), CVM))
        self.refuses("config", lambda: r.config_gate(config, template, receipt()))

    def test_ledger_upgrade_mutations_stop_before_guard_side_effects(self):
        phase = "persistent-ledger-upgrade"
        template = self.template_for(phase)
        config = r.render(template, receipt(), CVM, phase)
        mutations = ((b"['ledger-upgrade',", b"['init',"),
                     (b"['ledger-upgrade',", b"['website-init',"),
                     (b"['ledger-upgrade',", b"['serve',"),
                     (b"'--tinfoil-volume', 'ledger']", b"'--tinfoil-volume', 'ledger', '--initialize-volume']"),
                     (b"'--tinfoil-volume', 'ledger']", b"'--tinfoil-volume', 'ledger', '--operator']"),
                     (b"'--tinfoil-volume', 'ledger']", b"'--tinfoil-volume', 'ledger', '--listen', '0.0.0.0:8090']"),
                     (b"    env:\n", b"    healthcheck:\n      test: ['CMD', '/bin/intake', 'synthetic-healthcheck']\n    env:\n"),
                     (b"      - OTEL_SDK_DISABLED: 'true'\n",
                      b"      - OTEL_SDK_DISABLED: 'true'\n      - LEDGER_MANAGED_STARTUP_DIAGNOSTICS: 'true'\n"),
                     (b"      - OTEL_SDK_DISABLED: 'true'\n",
                      b"      - OTEL_SDK_DISABLED: 'true'\n      - LEDGER_SYNTHETIC_STARTUP_DIAGNOSTICS: 'true'\n"),
                     (b"    secrets:\n", b"    secrets:\n      - LEDGER_ADMIN_KEY\n"),
                     (b"    secrets:\n", b"    secrets:\n      - LEDGER_OPERATOR_EMAIL\n"),
                     (b"    secrets:\n", b"    secrets:\n      - LEDGER_OPERATOR_PASSWORD\n"),
                     (b"    secrets:\n", b"    secrets:\n      - EXTRA_FIXTURE_SECRET\n"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "templates").mkdir()
            (root / "accepted-image.json").write_text(json.dumps(receipt()))
            env, payload = environment(), event()
            env["RELEASE_STORAGE_PHASE"] = payload["inputs"]["expected_storage_phase"] = phase
            env["GITHUB_EVENT_PATH"] = str(root / "event.json")
            (root / "event.json").write_text(json.dumps(payload))
            real_live = r.Live
            with patch.dict(os.environ, env, clear=True), patch.object(r, "committed_files") as committed, \
                 patch.object(r, "command") as command, patch.object(r, "public_get") as get, \
                 patch.object(r, "measure") as measure, patch.object(r, "Live", side_effect=lambda: real_live(root)):
                for before, after in mutations:
                    with self.subTest(mutation=after):
                        self.assertIn(before, template)
                        changed_template = template.replace(before, after)
                        changed_config = config.replace(before, after)
                        self.refuses("config", lambda: r.render(changed_template, receipt(), CVM, phase))
                        self.refuses("config", lambda: r.config_gate(changed_config, template, receipt(), phase))
                        for supplied_template, supplied_config in ((template, changed_config),
                                                                   (changed_template, config),
                                                                   (changed_template, changed_config)):
                            (root / "templates" / r.PROFILES[phase][0]).write_bytes(supplied_template)
                            (root / "tinfoil-config.yml").write_bytes(supplied_config)
                            stream = io.StringIO()
                            with contextlib.redirect_stdout(stream):
                                self.assertEqual(r.cli(["guard"]), 1)
                            self.assertEqual(json.loads(stream.getvalue())["code"], "SYNTHETIC_CONFIG")
                            self.assertFalse((root / "output").exists())
                committed.assert_not_called()
                command.assert_not_called()
                get.assert_not_called()
                measure.assert_not_called()

    def test_ledger_replace_exact_template_confirmation_secrets_and_four_disks(self):
        phase = "persistent-ledger-replace"
        template = self.template_for(phase)
        expected = (self.template_for("persistent-ledger-init")
                    .replace(b"  - name: intake-persistent-ledger-init\n",
                             b"  - name: intake-persistent-ledger-replace\n")
                    .replace(b"['init', '--state', '/state/ledger', '--tinfoil-volume', 'ledger', '--operator']",
                             b"['ledger-replace', '--state', '/state/ledger', '--tinfoil-volume', 'ledger', '--operator', '--discard-existing-ledger']"))
        self.assertEqual(template, expected)
        self.assertEqual(r.PROFILES[phase], ("persistent-ledger-replace-config.yml.in",
                         "f01bb8a5740d244c7b4689e2f56f125bcb51f3368b3cde2152d4b0d348a10db5", 4))
        self.assertEqual(r.sha(template), r.PROFILES[phase][1])
        self.assertEqual(template.count(b"'--discard-existing-ledger'"), 1)
        self.assertEqual(template.split(b"    secrets:\n", 1)[1],
                         b"      - LEDGER_VOLUME_KEY_B64\n      - LEDGER_OPERATOR_EMAIL\n      - LEDGER_OPERATOR_PASSWORD\n")
        for other in r.PROFILES:
            self.assertEqual(r.sha(self.template_for(other)), r.PROFILES[other][1])
            if other != phase:
                self.assertNotIn(b"ledger-replace", self.template_for(other))
                self.assertNotIn(b"--discard-existing-ledger", self.template_for(other))
        config = r.render(template, receipt(), CVM, phase)
        self.assertEqual(config, expected.replace(b"@CVM_PIN@", CVM.encode()).replace(
            b"@IMAGE_DIGEST@", receipt()["imageDigest"].encode()))
        r.config_gate(config, template, receipt(), phase)
        value = manifest(config)
        value["vm_shape"]["disks"] = 4
        self.assertEqual(r.manifest_gate(json.dumps(value), config, receipt(), phase), value)
        with patch.object(r, "command") as command, patch.object(r, "public_get") as get, \
             patch.object(r, "measure") as measure:
            for disks in (0, 3, 5, True, "4"):
                changed = copy.deepcopy(value)
                changed["vm_shape"]["disks"] = disks
                self.refuses("manifest", lambda: r.manifest_gate(json.dumps(changed), config, receipt(), phase))
            command.assert_not_called()
            get.assert_not_called()
            measure.assert_not_called()

    def test_ledger_replace_mutations_stop_before_guard_tools(self):
        phase = "persistent-ledger-replace"
        template = self.template_for(phase)
        config = r.render(template, receipt(), CVM, phase)
        mutations = ((b", '--discard-existing-ledger'", b""),
                     (b"'--discard-existing-ledger'", b"'--initialize-volume'"),
                     (b"['ledger-replace',", b"['init',"),
                     (b"['ledger-replace',", b"['serve',"),
                     (b"'--discard-existing-ledger']", b"'--discard-existing-ledger', '--listen', '0.0.0.0:8090']"),
                     (b"    env:\n", b"    healthcheck:\n      test: ['CMD', '/bin/intake', 'synthetic-healthcheck']\n    env:\n"),
                     (b"      - OTEL_SDK_DISABLED: 'true'\n",
                      b"      - OTEL_SDK_DISABLED: 'true'\n      - LEDGER_MANAGED_STARTUP_DIAGNOSTICS: 'true'\n"),
                     (b"      - OTEL_SDK_DISABLED: 'true'\n",
                      b"      - OTEL_SDK_DISABLED: 'true'\n      - LEDGER_SYNTHETIC_STARTUP_DIAGNOSTICS: 'true'\n"),
                     (b"    secrets:\n", b"    secrets:\n      - LEDGER_ADMIN_KEY\n"),
                     (b"    secrets:\n", b"    secrets:\n      - EXTRA_FIXTURE_SECRET\n"),
                     (b"/state/ledger", b"/state"),
                     (b"owner: 65532", b"owner: 0"),
                     (b"user: '65532:65532'", b"user: '0:0'"),
                     (b"ledger:/state", b"other:/state"),
                     (b"  - name: ledger\n", b"  - name: ledger\n  - name: extra\n"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "templates").mkdir()
            (root / "accepted-image.json").write_text(json.dumps(receipt()))
            env, payload = environment(), event()
            env["RELEASE_STORAGE_PHASE"] = payload["inputs"]["expected_storage_phase"] = phase
            env["GITHUB_EVENT_PATH"] = str(root / "event.json")
            (root / "event.json").write_text(json.dumps(payload))
            real_live = r.Live
            with patch.dict(os.environ, env, clear=True), patch.object(r, "committed_files") as committed, \
                 patch.object(r, "command") as command, patch.object(r, "public_get") as get, \
                 patch.object(r, "measure") as measure, patch.object(r, "Live", side_effect=lambda: real_live(root)):
                for before, after in mutations:
                    with self.subTest(mutation=after):
                        self.assertIn(before, template)
                        changed_template = template.replace(before, after)
                        changed_config = config.replace(before, after)
                        self.refuses("config", lambda: r.render(changed_template, receipt(), CVM, phase))
                        self.refuses("config", lambda: r.config_gate(changed_config, template, receipt(), phase))
                        for supplied_template, supplied_config in ((template, changed_config),
                                                                   (changed_template, config),
                                                                   (changed_template, changed_config)):
                            (root / "templates" / r.PROFILES[phase][0]).write_bytes(supplied_template)
                            (root / "tinfoil-config.yml").write_bytes(supplied_config)
                            stream = io.StringIO()
                            with contextlib.redirect_stdout(stream):
                                self.assertEqual(r.cli(["guard"]), 1)
                            self.assertEqual(json.loads(stream.getvalue())["code"], "SYNTHETIC_CONFIG")
                            self.assertFalse((root / "output").exists())
                committed.assert_not_called()
                command.assert_not_called()
                get.assert_not_called()
                measure.assert_not_called()

    def test_managed_diagnostic_profile_is_exact_serve_plus_one_opt_in(self):
        line = b"      - LEDGER_MANAGED_STARTUP_DIAGNOSTICS: 'true'\n"
        serve = self.template_for("persistent-serve")
        diagnostic = self.template_for("persistent-diagnostic-serve")
        self.assertEqual(diagnostic, serve.replace(b"      - OTEL_SDK_DISABLED: 'true'\n",
                                                  b"      - OTEL_SDK_DISABLED: 'true'\n" + line))
        self.assertEqual(r.PROFILES["persistent-diagnostic-serve"],
                         ("persistent-diagnostic-serve-config.yml.in",
                          "c7ca16bf8d9d9fff81d6e70ef030c7a529b64c7d273956bab8feb4f7adb7be6a", 4))
        for phase in r.PROFILES:
            template = self.template_for(phase)
            self.assertEqual(template.count(line), int(phase == "persistent-diagnostic-serve"))
            self.assertEqual(template.count(b"LEDGER_MANAGED_STARTUP_DIAGNOSTICS"),
                             int(phase == "persistent-diagnostic-serve"))
        self.assertEqual(diagnostic.split(b"    secrets:\n", 1)[1],
                         b"      - LEDGER_VOLUME_KEY_B64\n      - LEDGER_ADMIN_KEY\n")
        workflow = (ROOT / r.WORKFLOW).read_text()
        self.assertIn("        default: disposable\n        options:\n"
                      "          - disposable\n          - persistent-bootstrap\n"
                      "          - persistent-ledger-init\n"
                      "          - persistent-ledger-replace\n"
                      "          - persistent-website-init\n"
                      "          - persistent-ledger-upgrade\n"
                      "          - persistent-serve\n          - persistent-diagnostic-serve\n"
                      "          - persistent-observed-serve\n"
                      "          - persistent-live-payments-init\n"
                      "          - persistent-live-stripe-serve\n", workflow)
        choices = workflow.split("        options:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(choices, "".join("          - " + phase + "\n" for phase in r.PROFILES))

    def test_managed_diagnostic_env_mutations_stop_before_live_work(self):
        phase = "persistent-diagnostic-serve"
        template = self.template_for(phase)
        config = r.render(template, receipt(), CVM, phase)
        line = b"      - LEDGER_MANAGED_STARTUP_DIAGNOSTICS: 'true'\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "templates").mkdir()
            (root / "accepted-image.json").write_text(json.dumps(receipt()))
            env, payload = environment(), event()
            env["RELEASE_STORAGE_PHASE"] = payload["inputs"]["expected_storage_phase"] = phase
            env["GITHUB_EVENT_PATH"] = str(root / "event.json")
            (root / "event.json").write_text(json.dumps(payload))
            with patch.dict(os.environ, env, clear=True), patch.object(r, "committed_files") as committed, \
                 patch.object(r, "checked_command") as command, patch.object(r, "public_get") as get, \
                 patch.object(r, "measure") as measure:
                for replacement in (b"", line.replace(b"'true'", b"'false'"),
                                    line + b"      - EXTRA_FIXTURE_ENV: 'true'\n",
                                    line.replace(b"'true'", b"true")):
                    changed_template = template.replace(line, replacement)
                    changed_config = config.replace(line, replacement)
                    self.refuses("config", lambda: r.render(changed_template, receipt(), CVM, phase))
                    self.refuses("config", lambda: r.config_gate(changed_config, template, receipt(), phase))
                    for supplied_template in (template, changed_template):
                        (root / "templates" / r.PROFILES[phase][0]).write_bytes(supplied_template)
                        (root / "tinfoil-config.yml").write_bytes(changed_config)
                        self.refuses("config", lambda: r.Live(root))
                committed.assert_not_called()
                command.assert_not_called()
                get.assert_not_called()
                measure.assert_not_called()

    def test_phase_templates_cannot_substitute_each_other(self):
        for actual in r.PROFILES:
            template = self.template_for(actual)
            config = r.render(template, receipt(), CVM, actual)
            for expected in r.PROFILES:
                if expected == actual:
                    continue
                self.refuses("config", lambda: r.render(template, receipt(), CVM, expected))
                self.refuses("config", lambda: r.config_gate(config, self.template_for(expected), receipt(), expected))

    def test_dispatch_phase_must_be_explicit_closed_and_exact(self):
        for phase in r.PROFILES:
            env, payload = environment(), event()
            env["RELEASE_STORAGE_PHASE"] = payload["inputs"]["expected_storage_phase"] = phase
            self.assertEqual(r.context_gate(env, payload), (TAG, PUBLIC))
            for bad in (None, "", "../" + SECRET, True, [], "persistent"):
                changed = {**env, "RELEASE_STORAGE_PHASE": bad}
                self.refuses("source", lambda: r.context_gate(changed, payload))
            for other in r.PROFILES:
                if other != phase:
                    changed = copy.deepcopy(payload)
                    changed["inputs"]["expected_storage_phase"] = other
                    self.refuses("source", lambda: r.context_gate(env, changed))
            changed = copy.deepcopy(payload)
            del changed["inputs"]["expected_storage_phase"]
            self.refuses("source", lambda: r.context_gate(env, changed))
            del env["RELEASE_STORAGE_PHASE"]
            self.refuses("source", lambda: r.context_gate(env, payload))

    def test_exact_phase_specific_vm_shapes_and_bindings(self):
        for phase in r.PROFILES:
            config = r.render(self.template_for(phase), receipt(), CVM, phase)
            value = manifest(config)
            value["vm_shape"]["disks"] = 3 if phase == "disposable" else 4
            self.assertEqual(r.manifest_gate(json.dumps(value), config, receipt(), phase), value)
            for disks in (0, 2, 3, 4, 5, True, "4"):
                if type(disks) is int and disks == value["vm_shape"]["disks"]:
                    continue
                changed = copy.deepcopy(value)
                changed["vm_shape"]["disks"] = disks
                self.refuses("manifest", lambda: r.manifest_gate(json.dumps(changed), config, receipt(), phase))
            changed = copy.deepcopy(value)
            changed["config"] = base64.b64encode(config + b"\n").decode()
            self.refuses("manifest", lambda: r.manifest_gate(json.dumps(changed), config, receipt(), phase))
            changed = copy.deepcopy(value)
            changed["cmdline"] += " extra=1"
            self.refuses("manifest", lambda: r.manifest_gate(json.dumps(changed), config, receipt(), phase))
        self.refuses("manifest", lambda: r.manifest_gate(json.dumps(value), config, receipt(), "../" + SECRET))

    def test_live_phase_swap_stops_before_source_or_vendor_work(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "templates").mkdir()
            for phase in r.PROFILES:
                (root / "templates" / r.PROFILES[phase][0]).write_bytes(self.template_for(phase))
            (root / "accepted-image.json").write_text(json.dumps(receipt()))
            for actual in r.PROFILES:
                config = r.render(self.template_for(actual), receipt(), CVM, actual)
                (root / "tinfoil-config.yml").write_bytes(config)
                for expected in r.PROFILES:
                    env, payload = environment(), event()
                    env["RELEASE_STORAGE_PHASE"] = payload["inputs"]["expected_storage_phase"] = expected
                    env["GITHUB_EVENT_PATH"] = str(root / "event.json")
                    (root / "event.json").write_text(json.dumps(payload))
                    with patch.dict(os.environ, env, clear=True), patch.object(r, "committed_files") as committed, \
                         patch.object(r, "command") as command, patch.object(r, "public_get") as get, \
                         patch.object(r, "measure") as measure:
                        if actual == expected:
                            live = r.Live(root)
                            self.assertEqual(live.phase, actual)
                            self.assertEqual(live.config, config)
                            committed.assert_called_once_with(root, PUBLIC)
                        else:
                            self.refuses("config", lambda: r.Live(root))
                            committed.assert_not_called()
                        command.assert_not_called()
                        get.assert_not_called()
                        measure.assert_not_called()

    def test_unknown_render_phase_is_content_free_and_initiates_no_work(self):
        output = io.StringIO()
        with patch.object(r, "read_file") as read, patch.object(r, "checked_command") as command, contextlib.redirect_stdout(output):
            self.assertEqual(r.cli(["render", "unused", CVM, "../" + SECRET]), 1)
        detail = json.loads(output.getvalue())
        self.assertEqual(detail["code"], "SYNTHETIC_CONFIG")
        self.assertNotIn(SECRET, output.getvalue())
        read.assert_not_called()
        command.assert_not_called()


class ObservedServeChecks(unittest.TestCase):
    setUp = Checks.setUp
    refuses = Checks.refuses
    template_for = PersistentChecks.template_for
    phase = "persistent-observed-serve"

    def test_historical_profiles_and_off_defaults_are_frozen(self):
        historical = {
            "disposable": ("synthetic-config.yml.in", "3ed591c27450d56887aabdb74ae466154c0da12d75b973ac20fd8dadb46b78e5", 3),
            "persistent-bootstrap": ("persistent-bootstrap-config.yml.in", "1f8204c8b0be394ee75e0feb00f69168cede18eb5e6084e3483da0e14035df93", 4),
            "persistent-ledger-init": ("persistent-ledger-init-config.yml.in", "8acff60da11650f0ccea6cf0eea1739cf58b14fcf3af68b80c89037e25784d45", 4),
            "persistent-ledger-replace": ("persistent-ledger-replace-config.yml.in", "f01bb8a5740d244c7b4689e2f56f125bcb51f3368b3cde2152d4b0d348a10db5", 4),
            "persistent-website-init": ("persistent-website-init-config.yml.in", "c1ec50de7f612e0691f5813dbeaacbf14ea04d43dc21fc229f0c7436e3b4d776", 4),
            "persistent-ledger-upgrade": ("persistent-ledger-upgrade-config.yml.in", "721c6b0549e5cd0e46bb682df233caa10a1ccc7f1cb05461d39c29d6278ff831", 4),
            "persistent-serve": ("persistent-serve-config.yml.in", "0b8e023d7daa78cc30e28dc2e050c5204495fe7d3c6c16e18db0039579c9b7e2", 4),
            "persistent-diagnostic-serve": ("persistent-diagnostic-serve-config.yml.in", "c7ca16bf8d9d9fff81d6e70ef030c7a529b64c7d273956bab8feb4f7adb7be6a", 4),
        }
        newer = {self.phase, "persistent-live-payments-init", "persistent-live-stripe-serve"}
        self.assertEqual({key: value for key, value in r.PROFILES.items() if key not in newer}, historical)
        for phase, (_, digest, _) in historical.items():
            template = self.template_for(phase)
            self.assertEqual(r.sha(template), digest)
            self.assertIn(b"      - OTEL_SDK_DISABLED: 'true'\n", template)
            self.assertNotIn(b"INTAKE_METRICS_", template)

    def test_native_validator_phase_literal_covers_all_profiles(self):
        # Source coverage only; actual pinned decoder acceptance is a separate gate.
        source = (ROOT / "tests/vendor-config/main.go").read_text()
        literal = source.split("for _, phase := range []string{", 1)[1].split("}", 1)[0]
        phases = json.loads("[" + literal + "]")
        self.assertEqual(phases, ["synthetic" if phase == "disposable" else phase
                                  for phase in r.PROFILES])

    def test_exact_clone_environment_secrets_render_and_four_disk_manifest(self):
        template = self.template_for(self.phase)
        expected_env = (b"      - OTEL_SDK_DISABLED: 'false'\n"
                        b"      - INTAKE_METRICS_ENDPOINT: 'https://api.honeycomb.io/v1/metrics'\n"
                        b"      - INTAKE_METRICS_ENVIRONMENT: 'production'\n"
                        b"      - INTAKE_METRICS_SLOT: 'intake-01'\n")
        expected = (self.template_for("persistent-serve")
                    .replace(b"      - OTEL_SDK_DISABLED: 'true'\n", expected_env)
                    + b"      - INTAKE_METRICS_HONEYCOMB_API_KEY\n")
        self.assertEqual(template, expected)
        self.assertEqual(template.split(b"    env:\n")[1].split(b"    secrets:\n")[0], expected_env)
        self.assertEqual(template.split(b"    secrets:\n")[1],
                         b"      - LEDGER_VOLUME_KEY_B64\n      - LEDGER_ADMIN_KEY\n      - INTAKE_METRICS_HONEYCOMB_API_KEY\n")
        self.assertEqual(r.PROFILES[self.phase], ("persistent-observed-serve-config.yml.in",
                         "621d71a185b11f293f1b1a425172102448f57314a337ee2cceb24391ce500ce7", 4))
        self.assertEqual(r.sha(template), r.PROFILES[self.phase][1])
        config = r.render(template, receipt(), CVM, self.phase)
        self.assertEqual(config, expected.replace(b"@CVM_PIN@", CVM.encode()).replace(
            b"@IMAGE_DIGEST@", receipt()["imageDigest"].encode()))
        r.config_gate(config, template, receipt(), self.phase)
        value = manifest(config)
        value["vm_shape"]["disks"] = 4
        self.assertEqual(r.manifest_gate(json.dumps(value), config, receipt(), self.phase), value)
        for forbidden in (b"--stripe-live", b"--initialize-volume", b"LEDGER_OPERATOR_", b"STARTUP_DIAGNOSTICS"):
            self.assertNotIn(forbidden, template)

    def test_observed_mutations_refused_before_any_live_boundary(self):
        template = self.template_for(self.phase)
        config = r.render(template, receipt(), CVM, self.phase)
        mutations = []
        # Each closed environment entry: removal, name/value edits, duplicates,
        # and YAML type changes are all rejected by exact-byte admission.
        env_lines = template.split(b"    env:\n")[1].split(b"    secrets:\n")[0].splitlines(keepends=True)
        for line in env_lines:
            name, value = line.split(b": ", 1)
            mutations.extend(((line, b""), (line, line + line),
                              (line, name + b"_EXTRA: " + value),
                              (line, name + b": 'invalid_fixture_value'\n"),
                              (line, name + b": " + value.replace(b"'", b""))))
        for line in (b"      - EXTRA_FIXTURE_ENV: 'true'\n",
                     b"      - OTEL_TRACES_EXPORTER: 'otlp'\n",
                     b"      - OTEL_EXPORTER_OTLP_ENDPOINT: 'https://invalid.invalid'\n",
                     b"      - OTEL_EXPORTER_OTLP_HEADERS: 'synthetic=sentinel'\n",
                     b"      - INTAKE_METRICS_HEADERS: 'synthetic=sentinel'\n",
                     b"      - INTAKE_METRICS_DATASET: 'synthetic'\n",
                     b"      - INTAKE_METRICS_HONEYCOMB_API_KEY: 'synthetic_key_in_yaml'\n",
                     b"      - LEDGER_MANAGED_STARTUP_DIAGNOSTICS: 'true'\n"):
            mutations.append((b"    env:\n", b"    env:\n" + line))
        mutations.extend((
            (b"OTEL_SDK_DISABLED: 'false'", b"OTEL_SDK_DISABLED: 'true'"),
            (b"api.honeycomb.io/v1/metrics", b"api.eu1.honeycomb.io/v1/metrics"),
            (b"'production'", b"'development'"), (b"'intake-01'", b"'intake-02'"),
            (b"      - INTAKE_METRICS_HONEYCOMB_API_KEY\n", b""),
            (b"      - INTAKE_METRICS_HONEYCOMB_API_KEY\n", b"      - GATEWAY_METRICS_KEY\n"),
            (b"      - INTAKE_METRICS_HONEYCOMB_API_KEY\n", b"      - INTAKE_METRICS_HONEYCOMB_API_KEY: synthetic_key_in_yaml\n"),
            (b"    secrets:\n", b"    secrets:\n      - EXTRA_FIXTURE_SECRET\n"),
            (b"LEDGER_ADMIN_KEY", b"OTHER_ADMIN_KEY"), (b"LEDGER_VOLUME_KEY_B64", b"OTHER_VOLUME_KEY"),
            (b"['serve',", b"['serve', '--stripe-live',"),
            (b"['serve',", b"['serve', '--stripe-synthetic',"),
            (b"['serve',", b"['serve', '--stripe-tax',"),
            (b"['serve',", b"['serve', '--initialize-volume',"),
            (b"['serve',", b"['serve', '--discard-existing-ledger',"),
            (b"['serve',", b"['init',"), (b"['serve',", b"['ledger-replace',"),
            (b"['serve',", b"['website-init',"), (b"['serve',", b"['ledger-upgrade',"),
            (b"cpus: 2", b"cpus: 4"), (b"memory: 8192", b"memory: 4096"), (b"gpus: 0", b"gpus: 1"),
            (b"  - name: ledger\n", b"  - name: ledger\n  - name: extra\n"),
            (b"owner: 65532", b"owner: 0"), (b"ledger:/state", b"other:/state"),
            (b"/state/ledger", b"/state"), (b"user: '65532:65532'", b"user: '0:0'"),
            (b"read_only: true", b"read_only: false"), (b"restart: 'no'", b"restart: 'always'"),
            (b"size=128m", b"size=256m"), (b"synthetic-healthcheck", b"serve"),
            (b"start_period: '35s'", b"start_period: '120s'"), (b"@CVM_PIN@", b"0.15.0"),
            (b"@IMAGE_DIGEST@", b"sha256:" + b"e" * 64),
        ))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "templates").mkdir()
            (root / "accepted-image.json").write_text(json.dumps(receipt()))
            env, payload = environment(), event()
            env["RELEASE_STORAGE_PHASE"] = payload["inputs"]["expected_storage_phase"] = self.phase
            env["GITHUB_EVENT_PATH"] = str(root / "event.json")
            (root / "event.json").write_text(json.dumps(payload))
            with patch.dict(os.environ, env, clear=True), patch.object(r, "committed_files") as committed, \
                 patch.object(r, "command") as command, patch.object(r, "public_get") as get, \
                 patch.object(r, "measure") as measure:
                for before, after in mutations:
                    with self.subTest(mutation=after):
                        self.assertIn(before, template)
                        changed_template = template.replace(before, after)
                        changed_config = changed_template.replace(b"@CVM_PIN@", CVM.encode()).replace(
                            b"@IMAGE_DIGEST@", receipt()["imageDigest"].encode())
                        self.refuses("config", lambda: r.render(changed_template, receipt(), CVM, self.phase))
                        self.refuses("config", lambda: r.config_gate(changed_config, template, receipt(), self.phase))
                        for supplied_template, supplied_config in ((template, changed_config),
                                                                   (changed_template, config),
                                                                   (changed_template, changed_config)):
                            (root / "templates" / r.PROFILES[self.phase][0]).write_bytes(supplied_template)
                            (root / "tinfoil-config.yml").write_bytes(supplied_config)
                            self.refuses("config", lambda: r.Live(root))
                committed.assert_not_called()
                command.assert_not_called()
                get.assert_not_called()
                measure.assert_not_called()

    def test_observed_profile_keeps_source_crypto_and_receipt_guards(self):
        env, payload = environment(), event()
        env["RELEASE_STORAGE_PHASE"] = payload["inputs"]["expected_storage_phase"] = self.phase
        self.assertEqual(r.public_gate(env, payload, receipt(), PublicAPI()), (TAG, PUBLIC))
        for field, bad in (("RELEASE_PUBLISH", "false"), ("SYNTHETIC_RELEASE_ENABLED", "false"),
                           ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_ACTOR", "other"),
                           ("GITHUB_REF_TYPE", "branch"), ("GITHUB_SHA", "e" * 40)):
            self.refuses("disabled" if field in ("RELEASE_PUBLISH", "SYNTHETIC_RELEASE_ENABLED") else "source",
                         lambda: r.public_gate({**env, field: bad}, payload, receipt(), PublicAPI()))
        for path in ("/git/ref/heads/main", "/git/ref/tags/" + TAG):
            api = PublicAPI()
            api.values[path][1]["object"]["sha"] = "e" * 40
            self.refuses("source", lambda: r.public_gate(env, payload, receipt(), api))
        self.refuses("receipt", lambda: r.public_gate(env, payload, {**receipt(), "publicSourceSHA": "e" * 40}, PublicAPI()))
        config = r.render(self.template_for(self.phase), receipt(), CVM, self.phase)
        value = manifest(config)
        value["vm_shape"]["disks"] = 4
        digest = r.sha(json.dumps(value).encode())
        checked = verified_statement(value, digest)
        r.statement_gate(checked, value, digest, env)
        checked[0]["verificationResult"]["signature"]["certificate"]["sourceRepositoryDigest"] = "e" * 40
        self.refuses("signature", lambda: r.statement_gate(checked, value, digest, env))
        for cvm in ("0.15.0", "0.14.14@sha256:" + "e" * 64):
            self.refuses("config", lambda: r.render(self.template_for(self.phase), receipt(), cvm, self.phase))

    def test_manifest_notes_are_phase_specific_and_historical_bytes_unchanged(self):
        for phase in r.PROFILES:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                live = Mock()
                live.phase, live.output = phase, Path(directory)
                live.env = {"GITHUB_OUTPUT": str(Path(directory) / "github-output")}
                raw = b"synthetic_manifest_fixture"
                live.manifest.return_value = (raw, {})
                with patch.object(r, "Live", return_value=live), \
                     patch.object(r, "command", side_effect=AssertionError("offline")), \
                     patch.object(r, "public_get", side_effect=AssertionError("offline")):
                    self.assertFalse(r.main(["manifest"])["runtime_verified"])
                notes = (Path(directory) / "release-notes.md").read_bytes()
                if phase == self.phase:
                    expected = ("Configuration phase: persistent-observed-serve. Operator-trusted private publication handoff; private source is not publicly inspectable. Explicit opt-in configuration for approved aggregate metrics only, conditional on valid dedicated private ingestion credentials. No telemetry delivery is established; production interface-error metrics remain disabled. No deployment, real data, payments, runtime identity or durability qualification. Parent must verify this exact completed signed run and downloaded asset hashes before one separately admitted instance.\n")
                    self.assertEqual(notes, expected.encode())
                elif phase == "persistent-live-payments-init":
                    expected = ("Configuration phase: persistent-live-payments-init. Operator-trusted private publication handoff; private source is not publicly inspectable. Existing-only volume unlock and absent-only live payment schema setup on the initialized ledger; no disk/ledger initialization, reset, credential change, listener or provider call. Preserve disk/key and existing state. No setup completion, deployment, provider acceptance, runtime identity or durability qualification is established. Require passive successful completion before a separately rendered, committed, signed and admitted live serving phase; never replay a failed or unknown setup. Parent must verify this exact completed signed run and downloaded asset hashes before one separately admitted instance.\n")
                    self.assertEqual(notes, expected.encode())
                elif phase == "persistent-live-stripe-serve":
                    expected = ("Configuration phase: persistent-live-stripe-serve. Operator-trusted private publication handoff; private source is not publicly inspectable. Explicit opt-in configuration for operator-authorized real Stripe checkout with exclusive tax added to credit principal, conditional on qualified live secrets, existing live payment state and launch gates. Approved aggregate metrics configuration is unchanged; no telemetry delivery is established and production interface-error metrics remain disabled. No activation, charge, provider acceptance, runtime identity or durability qualification is established. Preserve disk/key and existing state; no initialization, reset or automatic replay. Parent must verify this exact completed signed run and downloaded asset hashes before one separately admitted instance.\n")
                    self.assertEqual(notes, expected.encode())
                else:
                    expected = ("Synthetic-only configuration phase: " + phase + ". Operator-trusted private publication handoff; private source is not publicly inspectable. No deployment, real data, payments, live telemetry, runtime identity or durability qualification. Parent must verify this exact completed signed run and downloaded asset hashes before one separately admitted instance.\n")
                    self.assertEqual(notes, expected.encode())
                live.gate.assert_called_once_with()
                live.manifest.assert_called_once_with()


class LiveStripeChecks(unittest.TestCase):
    setUp = Checks.setUp
    refuses = Checks.refuses
    template_for = PersistentChecks.template_for

    def test_init_exact_existing_only_clone_and_closed_inputs(self):
        phase = "persistent-live-payments-init"
        template = self.template_for(phase)
        for original in ("persistent-website-init", "persistent-ledger-upgrade"):
            command = original.removeprefix("persistent-")
            expected = (self.template_for(original)
                        .replace(("intake-" + original).encode(), b"intake-persistent-live-payments-init")
                        .replace(("['" + command + "',").encode(), b"['live-payments-init',"))
            self.assertEqual(template, expected)
        self.assertEqual(r.PROFILES[phase], ("persistent-live-payments-init-config.yml.in",
                         "52009f1d7376260b500761fc7bc2c53142cb360b0ccad11c665ceee5b7816af1", 4))
        self.assertEqual(r.sha(template), r.PROFILES[phase][1])
        self.assertIn(b"command: ['live-payments-init', '--state', '/state/ledger', '--tinfoil-volume', 'ledger']\n", template)
        self.assertEqual(template.split(b"    env:\n")[1].split(b"    secrets:\n")[0],
                         b"      - OTEL_SDK_DISABLED: 'true'\n")
        self.assertEqual(template.split(b"    secrets:\n")[1], b"      - LEDGER_VOLUME_KEY_B64\n")
        for forbidden in (b"healthcheck:", b"--listen", b"--operator", b"--initialize-volume",
                          b"--discard-existing-ledger", b"LEDGER_ADMIN_KEY", b"LEDGER_OPERATOR_",
                          b"STRIPE_", b"INTAKE_METRICS_", b"STARTUP_DIAGNOSTICS"):
            self.assertNotIn(forbidden, template)

    def test_serve_exact_observed_clone_and_closed_live_inputs(self):
        phase = "persistent-live-stripe-serve"
        template = self.template_for(phase)
        expected = (self.template_for("persistent-observed-serve")
                    .replace(b"'--operator',", b"'--operator', '--stripe-live',")
                    .replace(b"    secrets:\n", b"      - STRIPE_LIVE_TAX_CODE: 'txcd_10103000'\n"
                             b"      - STRIPE_RETURN_ORIGIN: 'https://possums.dev'\n    secrets:\n")
                    + b"      - STRIPE_LIVE_API_KEY\n      - STRIPE_LIVE_WEBHOOK_SECRET\n")
        self.assertEqual(template, expected)
        self.assertEqual(r.PROFILES[phase], ("persistent-live-stripe-serve-config.yml.in",
                         "7e71fd63db75a232ec8e8eb5d10b45b437bd66cbeec7c99ff65d15d33e37848e", 4))
        self.assertEqual(r.sha(template), r.PROFILES[phase][1])
        self.assertIn(b"command: ['serve', '--state', '/state/ledger', '--tinfoil-volume', 'ledger', '--operator', '--stripe-live', '--listen', '0.0.0.0:8090']\n", template)
        self.assertEqual(template.split(b"    env:\n")[1].split(b"    secrets:\n")[0],
                         b"      - OTEL_SDK_DISABLED: 'false'\n"
                         b"      - INTAKE_METRICS_ENDPOINT: 'https://api.honeycomb.io/v1/metrics'\n"
                         b"      - INTAKE_METRICS_ENVIRONMENT: 'production'\n"
                         b"      - INTAKE_METRICS_SLOT: 'intake-01'\n"
                         b"      - STRIPE_LIVE_TAX_CODE: 'txcd_10103000'\n"
                         b"      - STRIPE_RETURN_ORIGIN: 'https://possums.dev'\n")
        self.assertEqual(template.split(b"    secrets:\n")[1],
                         b"      - LEDGER_VOLUME_KEY_B64\n      - LEDGER_ADMIN_KEY\n"
                         b"      - INTAKE_METRICS_HONEYCOMB_API_KEY\n"
                         b"      - STRIPE_LIVE_API_KEY\n      - STRIPE_LIVE_WEBHOOK_SECRET\n")
        for forbidden in (b"--initialize-volume", b"--discard-existing-ledger", b"LEDGER_OPERATOR_",
                          b"STARTUP_DIAGNOSTICS", b"OTEL_TRACES", b"OTEL_LOGS"):
            self.assertNotIn(forbidden, template)

    def test_live_mutations_refused_before_source_or_external_boundaries(self):
        for phase in ("persistent-live-payments-init", "persistent-live-stripe-serve"):
            template = self.template_for(phase)
            config = r.render(template, receipt(), CVM, phase)
            self.assertEqual(config, template.replace(b"@CVM_PIN@", CVM.encode()).replace(
                b"@IMAGE_DIGEST@", receipt()["imageDigest"].encode()))
            r.config_gate(config, template, receipt(), phase)
            mutations = [
                (b"cpus: 2", b"cpus: 4"), (b"memory: 8192", b"memory: 4096"), (b"gpus: 0", b"gpus: 1"),
                (b"owner: 65532", b"owner: 0"), (b"ledger:/state", b"other:/state"),
                (b"  - name: ledger\n", b"  - name: ledger\n  - name: extra\n"),
                (b"/state/ledger", b"/state"), (b"user: '65532:65532'", b"user: '0:0'"),
                (b"read_only: true", b"read_only: false"), (b"restart: 'no'", b"restart: 'always'"),
                (b"size=128m", b"size=256m"), (b"@CVM_PIN@", b"0.15.0"),
                (b"@IMAGE_DIGEST@", b"sha256:" + b"e" * 64),
                (b"    env:\n", b"    env:\n      - LEDGER_MANAGED_STARTUP_DIAGNOSTICS: 'true'\n"),
                (b"    env:\n", b"    env:\n      - OTEL_TRACES_EXPORTER: 'otlp'\n"),
                (b"    env:\n", b"    env:\n      - OTEL_LOGS_EXPORTER: 'otlp'\n"),
                (b"    secrets:\n", b"    secrets:\n      - EXTRA_FIXTURE_SECRET\n"),
            ]
            env_lines = template.split(b"    env:\n")[1].split(b"    secrets:\n")[0].splitlines(keepends=True)
            for line in env_lines:
                name, value = line.split(b": ", 1)
                mutations.extend(((line, b""), (line, line + line),
                                  (line, name + b"_EXTRA: " + value),
                                  (line, name + b": 'invalid_fixture_value'\n"),
                                  (line, name + b": " + value.replace(b"'", b""))))
            for line in template.split(b"    secrets:\n")[1].splitlines(keepends=True):
                mutations.extend(((line, b""), (line, line + line),
                                  (line, b"      - OTHER_FIXTURE_SECRET\n"),
                                  (line, line.rstrip() + b": synthetic_key_in_yaml\n")))
            if phase == "persistent-live-payments-init":
                for command in (b"init", b"ledger-replace", b"website-init", b"ledger-upgrade", b"serve"):
                    mutations.append((b"['live-payments-init',", b"['" + command + b"',"))
                for flag in (b"--initialize-volume", b"--discard-existing-ledger", b"--operator", b"--stripe-live"):
                    mutations.append((b"'ledger']", b"'ledger', '" + flag + b"']"))
                mutations.extend((
                    (b"'ledger']", b"'ledger', '--listen', '0.0.0.0:8090']"),
                    (b"    env:\n", b"    healthcheck:\n      test: ['CMD', '/bin/intake', 'synthetic-healthcheck']\n    env:\n"),
                    (b"    secrets:\n", b"    secrets:\n      - LEDGER_ADMIN_KEY\n"),
                    (b"    secrets:\n", b"    secrets:\n      - LEDGER_OPERATOR_EMAIL\n      - LEDGER_OPERATOR_PASSWORD\n"),
                    (b"    secrets:\n", b"    secrets:\n      - STRIPE_LIVE_API_KEY\n      - STRIPE_LIVE_WEBHOOK_SECRET\n"),
                ))
            else:
                mutations.extend((
                    (b", '--stripe-live'", b""), (b", '--operator'", b""),
                    (b"'--stripe-live'", b"'--stripe-synthetic'"),
                    (b"['serve',", b"['live-payments-init',"),
                    (b"['serve',", b"['serve', '--initialize-volume',"),
                    (b"['serve',", b"['serve', '--discard-existing-ledger',"),
                    (b"synthetic-healthcheck", b"serve"),
                    (b"start_period: '35s'", b"start_period: '120s'"),
                ))
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "templates").mkdir()
                (root / "accepted-image.json").write_text(json.dumps(receipt()))
                env, payload = environment(), event()
                env["RELEASE_STORAGE_PHASE"] = payload["inputs"]["expected_storage_phase"] = phase
                env["GITHUB_EVENT_PATH"] = str(root / "event.json")
                (root / "event.json").write_text(json.dumps(payload))
                with patch.dict(os.environ, env, clear=True), patch.object(r, "committed_files") as committed, \
                     patch.object(r, "command") as command, patch.object(r, "public_get") as get, \
                     patch.object(r, "measure") as measure:
                    for before, after in mutations:
                        with self.subTest(phase=phase, mutation=after):
                            self.assertIn(before, template)
                            changed_template = template.replace(before, after)
                            changed_config = changed_template.replace(b"@CVM_PIN@", CVM.encode()).replace(
                                b"@IMAGE_DIGEST@", receipt()["imageDigest"].encode())
                            self.refuses("config", lambda: r.render(changed_template, receipt(), CVM, phase))
                            self.refuses("config", lambda: r.config_gate(changed_config, template, receipt(), phase))
                            for supplied_template, supplied_config in ((template, changed_config),
                                                                       (changed_template, config),
                                                                       (changed_template, changed_config)):
                                (root / "templates" / r.PROFILES[phase][0]).write_bytes(supplied_template)
                                (root / "tinfoil-config.yml").write_bytes(supplied_config)
                                self.refuses("config", lambda: r.Live(root))
                    committed.assert_not_called()
                    command.assert_not_called()
                    get.assert_not_called()
                    measure.assert_not_called()


if __name__ == "__main__":
    if sys.argv[1:] == ["--linux-output-probe"]:
        try:
            print(json.dumps(r.safe("permissions", linux_output_probe)))
        except r.Stop as error:
            print(json.dumps(r.diagnostic(error)))
            sys.exit(1)
    else:
        unittest.main()
