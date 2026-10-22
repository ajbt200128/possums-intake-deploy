#!/usr/bin/env python3
"""Inactive release adapter; stdlib only. No private-app API or deployment adapter.

render/status are offline. Live commands require explicit activation and committed
operator handoff. Tests inject process/network boundaries; they perform no live work.
Measurement/provenance algorithms remain in pinned vendor tooling.
"""
import base64
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = "ajbt200128/possums-intake-deploy"
OWNER = "ajbt200128"
WORKFLOW = ".github/workflows/tinfoil-release.yml"
IMAGE = "ghcr.io/ajbt200128/possums-intake-synthetic"
# Deliberate adapter for upstream action.yaml, not an invocation of its composite.
UPSTREAM = "59f7ab5dbe472b3097c888ebe64e6a4131fc0975"
MEASURER = "ghcr.io/tinfoilsh/measure-image-action@sha256:9209c8449896c15615fced1c30e7283f9eb33c254a47b29ded0b86a0c8e9a6d1"
PREDICATE = "https://tinfoil.sh/predicate/snp-tdx-multiplatform/v1"
TEMPLATE_HASH = "3ed591c27450d56887aabdb74ae466154c0da12d75b973ac20fd8dadb46b78e5"
# Exact phase-specific bytes; never accept arbitrary YAML or disk counts.
PROFILES = {
    "disposable": ("synthetic-config.yml.in", TEMPLATE_HASH, 3),
    "persistent-bootstrap": ("persistent-bootstrap-config.yml.in", "1f8204c8b0be394ee75e0feb00f69168cede18eb5e6084e3483da0e14035df93", 4),
    "persistent-ledger-init": ("persistent-ledger-init-config.yml.in", "8acff60da11650f0ccea6cf0eea1739cf58b14fcf3af68b80c89037e25784d45", 4),
    "persistent-ledger-replace": ("persistent-ledger-replace-config.yml.in", "f01bb8a5740d244c7b4689e2f56f125bcb51f3368b3cde2152d4b0d348a10db5", 4),
    "persistent-website-init": ("persistent-website-init-config.yml.in", "c1ec50de7f612e0691f5813dbeaacbf14ea04d43dc21fc229f0c7436e3b4d776", 4),
    "persistent-ledger-upgrade": ("persistent-ledger-upgrade-config.yml.in", "721c6b0549e5cd0e46bb682df233caa10a1ccc7f1cb05461d39c29d6278ff831", 4),
    "persistent-serve": ("persistent-serve-config.yml.in", "0b8e023d7daa78cc30e28dc2e050c5204495fe7d3c6c16e18db0039579c9b7e2", 4),
    "persistent-diagnostic-serve": ("persistent-diagnostic-serve-config.yml.in", "c7ca16bf8d9d9fff81d6e70ef030c7a529b64c7d273956bab8feb4f7adb7be6a", 4),
}
FIRMWARE_HASH = "78c890175928167a1bc095d4bf3bb4ad81de80cd7e4e9e683477fc359119c1c4"
SHA = r"[0-9a-f]{40}"
HEX = r"[0-9a-f]{64}"
DIGEST = "sha256:" + HEX
TAG = r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
CVM = r"0\.14\.14"
# Exact parent-verified v0.14.14 release manifest; verification scope in README.
CVM_HASHES = {
    "version": "v0.14.14",
    "root": "41068e0738e14ee74d5b987586bdfc261d7bdd59e156dd6818154fd188b8ee7b",
    "kernel": "91b9c7979e00d4703cbabf9f6872639d23b1b60df88b971a7d49f11603ba4346",
    "initrd": "422948208e9d9aeddab46968ec7145eb9f0bf9dc82e9b6d0838cbf06995baada",
    "raw": "9634e66fe8761d227b2f39164dd13fbe54c3f1337b808287ce4a3477ee6d83a1",
}
ROOT = Path(__file__).resolve().parent.parent
PROCESS_JOIN_TIMEOUT = 3  # Necessary cleanup only; never a second execution attempt.
# Closed, packet-local diagnostics. No upstream exception text is classified.
FAILURES = {
    "arguments": ("input", "documented_closed_arguments", "Use documented public pins; no retry is authorized."),
    "disabled": ("activation", "explicit_separate_activation", "Source is inactive; obtain parent admission before activation."),
    "receipt": ("handoff", "exact_three_public_fields", "Supply the operator-accepted private publication receipt; do not extract credentials."),
    "config": ("configuration", "exact_template_and_verified_cvm_pin", "Review the fixed template and parent-verified CVM manifest pin; do not deploy placeholders."),
    "source": ("public_source", "owner_tag_current_main_and_attempt_one", "Resolve exact public main/tag/source and first manual attempt; never repoint a tag."),
    "transport": ("public_evidence_read", "bounded_typed_http_evidence", "Read cause is unknown; check public API availability privately. No mutation was retried."),
    "absence": ("release_precondition", "public_repo_200_release_404", "Existing or unavailable release evidence refuses publication; inspect authoritative state, never overwrite."),
    "measurement": ("vendor_measurement", "one_pinned_vendor_invocation", "Measurement cause is unknown; inspect privately. No second measurement was initiated."),
    "cleanup": ("measurement_cleanup", "joined_owned_container_removal", "Owned-container cleanup is unconfirmed; inspect it privately before any further work."),
    "process_cleanup": ("subprocess_cleanup", "bounded_owned_client_join", "Client completion is unconfirmed; inspect authoritative state privately. Never retry or replay the command."),
    "permissions": ("measurement_output", "owned_output_only", "Output access cause is unknown; review the owned output directory privately."),
    "manifest": ("manifest_validation", "sdk_config_hash_shape_and_structure", "Resolve actual SDK manifest binding; measurements are not fresh runtime verification."),
    "signature": ("signature_verification", "supported_tagged_certificate_and_predicate", "Require supported cryptographic verification of this exact tagged workflow and manifest."),
    "invocation": ("signed_invocation", "exact_current_run_attempt", "Require the actual signed invocation; parent must check successful completion after the run ends."),
    "publication": ("release_create", "one_nonreplayed_create", "Publication cause/outcome may be unknown; reconcile with passive authoritative reads. Never rerun, delete or overwrite."),
    "assets": ("release_evidence", "observed_release_and_exact_asset_metadata", "Retain observed creation evidence; parent must verify downloaded hashes and completed signed run before deployment."),
    "presentation": ("local_presentation", "closed_result_delivery", "Display cause is unknown; preserve any observed release creation and reconcile privately. Never replay publication."),
}


class Stop(Exception):
    def __init__(self, code, *, status=None, outcome="no_effect"):
        super().__init__()  # Do not retain arbitrary constructor arguments.
        self.code = code if type(code) is str and code in FAILURES else "arguments"
        self.status = status if type(status) is int and 100 <= status <= 599 else None
        self.outcome = outcome if type(outcome) is str and outcome in ("no_effect", "unknown", "release_created") else "unknown"
        # Fixed independent failure flags, never upstream exception graphs.
        self.process_cleanup_failed = False
        self.cleanup_failed = False
        self.cleanup_status = None
        self.reconciliation_failed = False
        self.reconciliation_status = None


def require(condition, code):
    if not condition:
        raise Stop(code)


def safe(code, operation, *, outcome="no_effect"):
    try:
        return operation()
    except Stop:
        raise
    except (Exception, KeyboardInterrupt):
        raise Stop(code, outcome=outcome) from None


def diagnostic(error):
    # Clamp again at presentation; no dynamic labels or recursive exceptions.
    closed = Stop(error.code, status=error.status, outcome=error.outcome)
    stage, constraint, next_step = FAILURES[closed.code]
    result = {"code": "SYNTHETIC_" + closed.code.upper(), "stage": stage,
              "constraint": constraint, "cause": "unknown_or_unconfirmed",
              "outcome": closed.outcome, "next_step": next_step}
    if closed.status is not None:
        result["status"] = closed.status
    additional = []
    for observed, code, status in ((error.process_cleanup_failed, "process_cleanup", None),
                                   (error.cleanup_failed, "cleanup", error.cleanup_status),
                                   (error.reconciliation_failed, "transport", error.reconciliation_status)):
        if observed is True:
            item = Stop(code, status=status, outcome=closed.outcome)
            stage, constraint, next_step = FAILURES[code]
            detail = {"code": "SYNTHETIC_" + code.upper(), "stage": stage,
                      "constraint": constraint, "cause": "unknown_or_unconfirmed",
                      "outcome": item.outcome, "next_step": next_step}
            if item.status is not None:
                detail["status"] = item.status
            additional.append(detail)
    if additional:
        result["additional_failures"] = additional
    return result


def pin(value, pattern):
    return isinstance(value, str) and re.fullmatch(pattern, value) is not None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError("duplicate")
        obj[key] = value
    return obj


def reject_constant(value):
    raise ValueError  # Never retain the parser's offending value.


def decode(raw, code):
    return safe(code, lambda: json.loads(raw, object_pairs_hook=unique_object,
                                        parse_constant=reject_constant))


def read_file(path, code, limit=8 << 20):
    def read():
        require(not path.is_symlink() and path.is_file(), code)
        with path.open("rb") as stream:
            data = stream.read(limit + 1)
        require(len(data) <= limit, code)
        return data
    return safe(code, read)


def receipt_gate(raw):
    value = decode(raw, "receipt")
    require(type(value) is dict and set(value) == {"publicSourceSHA", "imageDigest", "archiveSHA"}, "receipt")
    for field, pattern in (("publicSourceSHA", SHA), ("imageDigest", DIGEST), ("archiveSHA", HEX)):
        require(pin(value[field], pattern) and set(value[field].removeprefix("sha256:")) != {"0"}, "receipt")
    # Operator-trusted handoff, bound to committed bytes and expected inputs.
    # This public repository cannot inspect or automatically qualify private CI.
    return value


def render(template, receipt, cvm, phase="disposable"):
    # Hash-fixed bytes avoid a second YAML parser/schema or arbitrary env fields.
    require(type(phase) is str and phase in PROFILES, "config")
    require(sha(template) == PROFILES[phase][1] and pin(cvm, CVM), "config")
    receipt = receipt_gate(json.dumps(receipt).encode())
    require(template.count(b"@CVM_PIN@") == template.count(b"@IMAGE_DIGEST@") == 1, "config")
    return template.replace(b"@CVM_PIN@", cvm.encode()).replace(b"@IMAGE_DIGEST@", receipt["imageDigest"].encode())


def config_gate(root, template, receipt, phase="disposable"):
    match = re.match(rb"cvm-version: (0\.14\.14)\n", root)
    require(match is not None, "config")
    require(root == render(template, receipt, match[1].decode(), phase), "config")


def command(args, code, *, token=False, timeout=120, process_group=False):
    """Bounded transient pipes and cleanup, including overflow/interruption.

    Child env is allowlisted, never forwarded wholesale or printed. Token values
    occur only in process env. Caller decides whether nonzero means uncertainty.
    """
    def execute():
        require(type(process_group) is bool and (not process_group or os.name == "posix"), code)
        env = {key: os.environ[key] for key in ("PATH", "HOME", "SSL_CERT_FILE") if key in os.environ}
        if token:
            require(bool(os.environ.get("GH_TOKEN")), code)
            env["GH_TOKEN"] = os.environ["GH_TOKEN"]
        # Popen.__exit__ waits without a deadline, so own cleanup explicitly.
        process = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=env,
                                   **({"start_new_session": True} if process_group else {}))
        primary = None
        result = None
        cleanup_failed = False
        try:
            output = [bytearray(), bytearray()]
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                for index, stream in enumerate((process.stdout, process.stderr)):
                    selector.register(stream, selectors.EVENT_READ, index)
                while selector.get_map():
                    require(time.monotonic() < deadline, code)
                    for key, _ in selector.select(0.1):
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        output[key.data].extend(data)
                        require(len(output[key.data]) <= 8 << 20, code)
            result = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except (Exception, KeyboardInterrupt) as error:
            primary = error if isinstance(error, Stop) else Stop(code)
        finally:
            try:
                if process_group:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                        # A signal and leader join cannot prove descendant exit.
                        # Retain owned caches whenever a remaining group needed it.
                        cleanup_failed = True
                    except ProcessLookupError:
                        pass  # The owned group is already absent.
                    except (Exception, KeyboardInterrupt):
                        cleanup_failed = True
                if process.poll() is None:
                    try:
                        process.kill()
                    except (Exception, KeyboardInterrupt):
                        cleanup_failed = True
                    process.wait(timeout=PROCESS_JOIN_TIMEOUT)
            except (Exception, KeyboardInterrupt):
                cleanup_failed = True
            finally:
                for stream in (process.stdout, process.stderr):
                    try:
                        if stream is not None:
                            stream.close()
                    except (Exception, KeyboardInterrupt):
                        cleanup_failed = True
        if cleanup_failed:
            if primary is None:
                # CLI zero is creation evidence even if later local cleanup fails.
                outcome = "release_created" if code == "publication" and result == 0 else "unknown"
                primary = Stop("process_cleanup", outcome=outcome)
            else:
                primary.process_cleanup_failed = True
                if primary.outcome != "release_created":
                    primary.outcome = "unknown"
        if primary is not None:
            raise primary from None
        return result, bytes(output[0])  # stderr is discarded, even on success.
    return safe(code, execute)


def checked_command(args, code, **kwargs):
    result, raw = command(args, code, **kwargs)
    require(result == 0, code)
    return raw


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def public_get(path):
    """Only authenticated passive GitHub GETs for the fixed PUBLIC repository."""
    require(path == "" or (path.startswith("/") and ".." not in path and "?" not in path), "transport")
    def get():
        token = os.environ.get("GH_TOKEN")
        require(bool(token), "transport")
        request = urllib.request.Request("https://api.github.com/repos/" + REPO + path,
            headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "synthetic-release"}, method="GET")
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
                raw = response.read((8 << 20) + 1)
                require(len(raw) <= 8 << 20, "transport")
                if type(response.status) is not int or response.status != 200:
                    raise Stop("transport", status=response.status)
                value = decode(raw, "transport")
                require(type(value) is dict, "transport")
                return 200, value
        except urllib.error.HTTPError as error:
            # No raw body/headers/exception text. A real 404 is distinct from failure.
            status = error.code
            try:
                error.close()
            except (Exception, KeyboardInterrupt):
                raise Stop("transport", status=status) from None
            if type(status) is int and status == 404:
                return 404, None
            raise Stop("transport", status=status) from None
    return safe("transport", get)


def expect_get(get, path):
    status, value = get(path)
    if type(status) is not int or status != 200:
        raise Stop("transport", status=status)
    require(type(value) is dict, "transport")
    return value


def context_gate(env, event):
    require(env.get("SYNTHETIC_RELEASE_ENABLED") == "true" and env.get("RELEASE_PUBLISH") == "true", "disabled")
    require(env.get("GITHUB_REPOSITORY") == REPO and env.get("GITHUB_REPOSITORY_OWNER") == OWNER
            and env.get("GITHUB_ACTOR") == OWNER and env.get("GITHUB_TRIGGERING_ACTOR") == OWNER
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_REF_TYPE") == "tag" and env.get("GITHUB_RUN_ATTEMPT") == "1", "source")
    tag, commit = env.get("GITHUB_REF_NAME"), env.get("RELEASE_PUBLIC_SHA")
    require(pin(tag, TAG) and pin(commit, SHA) and env.get("GITHUB_REF") == "refs/tags/" + tag
            and env.get("GITHUB_SHA") == commit and pin(env.get("GITHUB_RUN_ID"), r"[1-9][0-9]*"), "source")
    # Do not require the dispatch payload to repeat GITHUB_REF's full spelling.
    # The full tag authority is GITHUB_REF plus the supported public ref API.
    require(type(event) is dict and type(event.get("repository")) is dict
            and type(event.get("sender")) is dict
            and event["repository"].get("full_name") == REPO
            and event["sender"].get("login") == OWNER
            and event.get("ref") in (tag, "refs/tags/" + tag), "source")
    phase = env.get("RELEASE_STORAGE_PHASE")
    require(type(phase) is str and phase in PROFILES, "source")
    inputs = event.get("inputs")
    require(type(inputs) is dict and inputs.get("expected_storage_phase") == phase
            and inputs.get("publish") == "true" and inputs.get("expected_public_commit") == commit
            and inputs.get("expected_private_source") == env.get("RELEASE_PRIVATE_SHA")
            and inputs.get("expected_image_digest") == env.get("RELEASE_IMAGE_DIGEST"), "source")
    return tag, commit


def absence_gate(get, tag):
    repo = expect_get(get, "")
    require(repo.get("full_name") == REPO and repo.get("private") is False
            and repo.get("default_branch") == "main", "absence")
    status, _ = get("/releases/tags/" + tag)
    # Opaque CLI/auth/network errors are NEVER absence.
    require(type(status) is int and status == 404, "absence")


def public_gate(env, event, receipt, get, *, completed=False):
    tag, commit = context_gate(env, event)
    require(receipt["publicSourceSHA"] == env.get("RELEASE_PRIVATE_SHA")
            and receipt["imageDigest"] == env.get("RELEASE_IMAGE_DIGEST"), "receipt")
    main_object = expect_get(get, "/git/ref/heads/main").get("object")
    require(type(main_object) is dict and main_object.get("type") == "commit" and main_object.get("sha") == commit, "source")
    # Require an existing lightweight tag; no tag creation/mutation by this helper.
    tag_object = expect_get(get, "/git/ref/tags/" + tag).get("object")
    require(type(tag_object) is dict and tag_object.get("type") == "commit" and tag_object.get("sha") == commit, "source")
    run = expect_get(get, "/actions/runs/" + env["GITHUB_RUN_ID"])
    require(all(type(run.get(field)) is dict for field in ("repository", "head_repository", "actor", "triggering_actor"))
            and run["repository"].get("full_name") == REPO
            and run["head_repository"].get("full_name") == REPO
            and run.get("path") == WORKFLOW and run.get("event") == "workflow_dispatch"
            and run.get("head_sha") == commit and run.get("head_branch") == tag
            and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
            and type(run.get("id")) is int and str(run["id"]) == env["GITHUB_RUN_ID"]
            and run.get("actor", {}).get("login") == OWNER
            and run.get("triggering_actor", {}).get("login") == OWNER, "invocation")
    if completed:
        require(run.get("status") == "completed" and run.get("conclusion") == "success", "invocation")
    else:
        require(run.get("status") == "in_progress" and run.get("conclusion") is None, "invocation")
        absence_gate(get, tag)
    return tag, commit


def committed_files(root, commit, run=checked_command):
    require(run(["git", "rev-parse", "HEAD"], "source").strip().decode() == commit, "source")
    names = ("accepted-image.json", "tinfoil-config.yml", "scripts/synthetic-release.py", "scripts/test_synthetic_release.py", WORKFLOW)
    for name in names + tuple("templates/" + profile[0] for profile in PROFILES.values()):
        mode = run(["git", "ls-tree", "HEAD", "--", name], "source")
        require(mode.startswith(b"100644 blob ") and mode.rstrip().endswith(b"\t" + name.encode()), "source")
        require(read_file(root / name, "source") == run(["git", "show", "HEAD:" + name], "source"), "source")


def manifest_gate(raw, config, receipt, phase="disposable"):
    require(type(phase) is str and phase in PROFILES, "manifest")
    value = decode(raw, "manifest")
    def validate():
        require(type(value) is dict and set(value) == {"snp_measurement", "tdx_measurement", "firmware", "vm_shape", "cmdline", "hashes", "config"}, "manifest")
        require(base64.b64decode(value["config"], validate=True) == config
                and value["config"] == base64.b64encode(config).decode()
                and (IMAGE + "@" + receipt["imageDigest"]).encode() in config, "manifest")
        shape = value["vm_shape"]
        require(shape == {"cpus": 2, "memory_mb": 8192, "gpus": 0, "disks": PROFILES[phase][2]}
                and all(type(item) is int for item in shape.values()), "manifest")
        hashes = value["hashes"]
        require(type(hashes) is dict and hashes == CVM_HASHES, "manifest")
        # Exact cmdline emitted by pinned vendor orchestrator; no duplicate hash token.
        expected = ("readonly=on pci=realloc,nocrs modprobe.blacklist=nouveau nouveau.modeset=0 "
                    "root=/dev/mapper/root roothash=" + hashes["root"] + " tinfoil-config-hash=" + sha(config))
        require(value["cmdline"] == expected and pin(value["snp_measurement"], r"[0-9a-f]{96}"), "manifest")
        tdx = value["tdx_measurement"]
        require(type(tdx) is dict and bool(tdx) and all(pin(key, r"(mrtd|rtmr[0-3])")
                and pin(item, r"[0-9a-fA-F]{96}") for key, item in tdx.items())
                and {"rtmr1", "rtmr2"} <= set(tdx), "manifest")
        require(value["firmware"] == {"sev_snp": {"type": "ovmf", "version": "v0.0.4", "sha256": FIRMWARE_HASH}}, "manifest")
        return value
    return safe("manifest", validate)


def verify_file(path, commit, tag, run=checked_command):
    identity = f"https://github.com/{REPO}/{WORKFLOW}@refs/tags/{tag}"
    raw = run(["gh", "attestation", "verify", str(path), "--repo", REPO,
        "--cert-identity", identity, "--source-ref", "refs/tags/" + tag,
        "--source-digest", commit, "--signer-digest", commit,
        "--deny-self-hosted-runners", "--predicate-type", PREDICATE, "--format", "json"], "signature", token=True)
    return decode(raw, "signature")


def statement_gate(checked, manifest, digest, env):
    # Input ONLY from supported gh cryptographic verification, not local statements.
    def validate():
        require(type(checked) is list and len(checked) == 1, "signature")
        verified = checked[0]["verificationResult"]
        statement, cert = verified["statement"], verified["signature"]["certificate"]
        tag, commit = env["GITHUB_REF_NAME"], env["RELEASE_PUBLIC_SHA"]
        require(statement["predicateType"] == PREDICATE and statement["predicate"] == manifest
                and statement["subject"] == [{"name": "tinfoil-deployment.json", "digest": {"sha256": digest}}], "signature")
        require(cert["subjectAlternativeName"] == f"https://github.com/{REPO}/{WORKFLOW}@refs/tags/{tag}"
                and cert["buildSignerDigest"] == cert["sourceRepositoryDigest"] == commit
                and cert["sourceRepositoryRef"] == "refs/tags/" + tag
                and cert["runnerEnvironment"] == "github-hosted", "signature")
        require(cert["runInvocationURI"] == f"https://github.com/{REPO}/actions/runs/{env['GITHUB_RUN_ID']}/attempts/1", "invocation")
    safe("signature", validate)


def docker_args(config, output, name):
    return ["docker", "run", "--rm", "--name", name, "--group-add", str(os.getgid()), "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--read-only", "--tmpfs", "/tmp",
            "--tmpfs", "/cache", "--tmpfs", "/root/.cache",
            "-v", str(config) + ":/config.yml:ro", "-v", str(output) + ":/output",
            "-e", "GH_TOKEN", MEASURER]


def cleanup_measurement(name, run=checked_command):
    listing = run(["docker", "ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.Names}}"], "cleanup")
    require(listing in (b"", (name + "\n").encode()), "cleanup")
    if listing:
        run(["docker", "rm", "-f", name], "cleanup")


def measure(config, output, name, run=checked_command):
    require(pin(name, r"synthetic-measure-[1-9][0-9]*-1"), "measurement")
    require(not output.exists() and not output.is_symlink(), "measurement")
    require(run(["docker", "ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.Names}}"], "measurement") == b"", "measurement")
    safe("measurement", lambda: output.mkdir(mode=0o770))
    # Root without DAC capabilities needs the host group; umask may strip it.
    # Retain the directory on failure as the per-checkout attempt marker; use
    # a fresh admitted job rather than clearing it to retry this invocation.
    safe("permissions", lambda: output.chmod(0o770))
    primary = None
    try:
        run(docker_args(config, output, name), "measurement", token=True, timeout=900)
    except (Exception, KeyboardInterrupt) as error:
        primary = error if isinstance(error, Stop) else Stop("measurement")
    # A late container create could race removal while the client is unjoined.
    if primary is not None and (primary.process_cleanup_failed is True or primary.code == "process_cleanup"):
        primary.cleanup_failed = True
        raise primary from None
    # Joined Docker client + known owned container cleanup on every attempted run.
    try:
        cleanup_measurement(name, run)
    except (Exception, KeyboardInterrupt) as error:
        cleanup = error if isinstance(error, Stop) else Stop("cleanup")
        if primary:
            primary.cleanup_failed = True
            primary.cleanup_status = cleanup.status
            if cleanup.process_cleanup_failed is True or cleanup.code == "process_cleanup":
                primary.process_cleanup_failed = True
                if primary.outcome != "release_created":
                    primary.outcome = "unknown"
        else:
            primary = cleanup
    if primary:
        raise primary from None
    def fix_permissions():
        require(not output.is_symlink() and all(not path.is_symlink() for path in output.rglob("*")), "permissions")
        run(["sudo", "chown", "-R", f"{os.getuid()}:{os.getgid()}", str(output)], "permissions")
    safe("permissions", fix_permissions)


def release_metadata(value, tag, commit, files):
    # Official action omits --target; GitHub records the default branch name.
    # Exact source authority remains the immutable tag, run and signed certificate.
    require(value.get("tag_name") == tag and value.get("target_commitish") in (commit, "main")
            and value.get("draft") is False and value.get("prerelease") is False, "assets")
    assets = value.get("assets", [])
    require(len(assets) == len(files) and {asset.get("name") for asset in assets} == set(files), "assets")
    for asset in assets:
        raw = files[asset["name"]]
        require(asset.get("state") == "uploaded" and type(asset.get("size")) is int
                and asset["size"] == len(raw)
                and asset.get("digest") == "sha256:" + sha(raw), "assets")


class Publication:
    """One session/one create; passive reconciliation never authorizes retry."""
    def __init__(self, port):
        self.port = port
        self.used = False
        self.outcome = "no_effect"

    def execute(self):
        if self.used:
            raise Stop("publication", outcome=self.outcome)
        safe("source", self.port.gate)
        safe("signature", self.port.verify)
        safe("source", self.port.gate)  # Recheck public main/tag/absence just before create.
        self.used = True
        self.outcome = "unknown"
        try:
            self.port.create()  # Exactly ONE side-effecting call; zero retries.
            self.outcome = "release_created"  # Observed CLI completion, not runtime success.
            safe("assets", self.port.assets)
            return {"outcome": self.outcome, "asset_metadata_verified": True,
                    "signed_run_completion": "pending_parent_check", "runtime_verified": False}
        except (Exception, KeyboardInterrupt) as error:
            failure = error if isinstance(error, Stop) else Stop("publication")
            if failure.outcome == "release_created":
                self.outcome = "release_created"
            if self.outcome == "unknown":
                try:
                    if safe("transport", self.port.release_exists) is True:
                        self.outcome = "release_created"  # Asset completion remains unconfirmed.
                except (Exception, KeyboardInterrupt) as reconciliation:
                    failure.reconciliation_failed = True
                    failure.reconciliation_status = reconciliation.status if isinstance(reconciliation, Stop) else None
            failure.outcome = self.outcome
            raise failure from None


class Live:
    def __init__(self, root=ROOT):
        self.root, self.env = root, dict(os.environ)
        self.event = decode(read_file(Path(self.env.get("GITHUB_EVENT_PATH", "")), "source"), "source")
        self.receipt = receipt_gate(read_file(root / "accepted-image.json", "receipt", 4096))
        self.config = read_file(root / "tinfoil-config.yml", "config", 4096)
        self.phase = self.env.get("RELEASE_STORAGE_PHASE")
        require(type(self.phase) is str and self.phase in PROFILES, "config")
        template = read_file(root / "templates" / PROFILES[self.phase][0], "config")
        config_gate(self.config, template, self.receipt, self.phase)
        self.tag, self.commit = context_gate(self.env, self.event)
        committed_files(root, self.commit)
        self.output = root / "output"

    def gate(self, *, completed=False):
        public_gate(self.env, self.event, self.receipt, public_get, completed=completed)

    def manifest(self):
        raw = read_file(self.output / "tinfoil-deployment.json", "manifest")
        return raw, manifest_gate(raw, self.config, self.receipt, self.phase)

    def verify(self):
        raw, manifest = self.manifest()
        require(read_file(self.output / "tinfoil.hash", "manifest", 128) == (sha(raw) + "\n").encode(), "manifest")
        statement_gate(verify_file(self.output / "tinfoil-deployment.json", self.commit, self.tag), manifest, sha(raw), self.env)

    def create(self):
        checked_command(["gh", "release", "create", self.tag, "--verify-tag", "--latest=false",
            "--repo", REPO, "--target", self.commit, "--title", self.tag,
            "--notes-file", str(self.output / "release-notes.md"),
            str(self.output / "tinfoil-deployment.json"), str(self.output / "tinfoil.hash")], "publication", token=True)

    def release_exists(self):
        status, value = public_get("/releases/tags/" + self.tag)
        if type(status) is int and status == 404:
            return False  # Absence does not establish that create had no effect.
        if type(status) is not int or status != 200:
            raise Stop("transport", status=status)
        require(type(value) is dict and value.get("tag_name") == self.tag, "transport")
        return True

    def assets(self):
        value = expect_get(public_get, "/releases/tags/" + self.tag)
        files = {name: read_file(self.output / name, "assets") for name in ("tinfoil-deployment.json", "tinfoil.hash")}
        safe("assets", lambda: release_metadata(value, self.tag, self.commit, files))


def write_new(path, data, code):
    def write():
        with path.open("xb") as stream:
            stream.write(data)
    safe(code, write)


def main(args):
    if args == ["status"]:
        return {"offline": True, "publication_requires_explicit_authorization": True, "private_ci_automatically_verified": False,
                "deployment_adapter": False, "runtime_verified": False}
    if len(args) in (3, 4) and args[0] == "render":
        phase = args[3] if len(args) == 4 else "disposable"
        require(phase in PROFILES, "config")
        receipt = receipt_gate(read_file(Path(args[1]), "receipt", 4096))
        raw = render(read_file(ROOT / "templates" / PROFILES[phase][0], "config"), receipt, args[2], phase)
        safe("config", lambda: sys.stdout.buffer.write(raw))  # Offline stdout only.
        return None
    require(args in (["guard"], ["measure"], ["manifest"], ["publish"], ["verify-completed"]), "arguments")
    live = safe("source", Live)
    if args == ["verify-completed"]:
        safe("source", lambda: live.gate(completed=True))
        safe("signature", live.verify)
        safe("assets", live.assets)
        return {"completed_signed_run_verified": True, "asset_metadata_verified": True,
                "downloaded_asset_hashes_require_parent_check": True, "runtime_verified": False}
    if args == ["publish"]:
        return Publication(live).execute()
    safe("source", live.gate)
    if args == ["measure"]:
        safe("measurement", lambda: measure(live.root / "tinfoil-config.yml", live.output, "synthetic-measure-" + live.env["GITHUB_RUN_ID"] + "-1"))
    if args == ["manifest"]:
        raw, _ = safe("manifest", live.manifest)
        write_new(live.output / "tinfoil.hash", (sha(raw) + "\n").encode(), "manifest")
        notes = ("Synthetic-only configuration phase: " + live.phase + ". Operator-trusted private publication handoff; private source is not publicly inspectable. No deployment, real data, payments, live telemetry, runtime identity or durability qualification. Parent must verify this exact completed signed run and downloaded asset hashes before one separately admitted instance.\n")
        write_new(live.output / "release-notes.md", notes.encode(), "manifest")
        def output_digest():
            with Path(live.env["GITHUB_OUTPUT"]).open("a") as stream:
                stream.write("digest=sha256:" + sha(raw) + "\n")
        safe("manifest", output_digest)
    return {"passed": True, "stage": args[0], "runtime_verified": False}


def interrupt(signum, frame):
    raise KeyboardInterrupt


def cli(args):
    fallback = {"render": "config", "guard": "source", "measure": "measurement",
                "manifest": "manifest", "publish": "publication", "verify-completed": "invocation"}.get(args[0] if args else "", "arguments")
    result = None
    try:
        result = safe(fallback, lambda: main(args), outcome="unknown" if args == ["publish"] else "no_effect")
        if result is not None:
            safe("presentation", lambda: print(json.dumps(result)))
        return 0
    except Stop as error:
        if type(result) is dict and result.get("outcome") == "release_created":
            error.outcome = "release_created"
        try:
            print(json.dumps(diagnostic(error)))
        except (Exception, KeyboardInterrupt):
            # An unusable stdout cannot carry a diagnostic; never emit raw stderr.
            pass
        return 1


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, interrupt)
    sys.exit(cli(sys.argv[1:]))
