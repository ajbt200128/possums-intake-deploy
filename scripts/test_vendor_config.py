"""Offline runner negatives; these mocks are not actual-decoder evidence."""
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("qualify_vendor_config", Path(__file__).with_name("qualify-vendor-config.py"))
q = importlib.util.module_from_spec(spec)
spec.loader.exec_module(q)
SECRET = "SYNTHETIC_HOSTILE_FIXTURE_SENTINEL"
PASS = {"stage": "vendor_config_decoder", "passed": True, "measurement": False, "runtime_verified": False}


def tool(args, code, **kwargs):
    if args[-1] == "version":
        return b"go version go1.27.2 synthetic\n"
    if "list" in args:
        version = "v0.1.14" if "-modfile=old.mod" in args else "v0.1.17" if "-modfile=runtime.mod" in args else "v0.1.16"
        return ("github.com/tinfoilsh/tinfoil-config " + version + "\n").encode()
    if "run" in args:
        return json.dumps(PASS).encode()
    if args[-2:] == ["clean", "-modcache"]:
        return b""
    raise AssertionError("unexpected fixture command")


class Checks(unittest.TestCase):
    def test_status_initiates_no_work(self):
        with patch.object(q, "qualify", side_effect=AssertionError("offline")), patch.object(q.r, "checked_command") as command:
            self.assertFalse(q.main(["status"])["qualification_started"])
            command.assert_not_called()

    def test_unknown_arguments_are_content_free_and_initiate_no_work(self):
        output = io.StringIO()
        with patch.object(q.r, "checked_command") as command, contextlib.redirect_stdout(output):
            self.assertEqual(q.cli([SECRET]), 1)
        self.assertEqual(json.loads(output.getvalue())["code"], "SYNTHETIC_ARGUMENTS")
        self.assertNotIn(SECRET, output.getvalue())
        command.assert_not_called()

    def test_mock_matrix_and_owned_cleanup(self):
        with patch.object(q.r, "checked_command", side_effect=tool) as command:
            result = q.qualify()
        self.assertTrue(result["owned_cache_removed"])
        self.assertEqual([case["persistent_behavior"] for case in result["cases"]], ["reject", "accept", "accept"])
        self.assertEqual(command.call_count, 8)
        for call in command.call_args_list:
            self.assertNotIn("GH_TOKEN", " ".join(call.args[0]))
            self.assertNotIn("LEDGER_", " ".join(call.args[0]))
            self.assertTrue(call.kwargs["process_group"])

    def test_wrong_compiler_does_not_start_modules(self):
        with patch.object(q.r, "checked_command", return_value=b"go version different\n") as command:
            with self.assertRaises(q.r.Stop) as caught:
                q.qualify()
        self.assertEqual(caught.exception.code, "vendor_toolchain")
        self.assertEqual(command.call_count, 1)

    def test_wrong_selected_module_stops_before_probe(self):
        def wrong(args, code, **kwargs):
            return b"unexpected fixture module\n" if "list" in args else tool(args, code, **kwargs)
        with patch.object(q.r, "checked_command", side_effect=wrong) as command:
            with self.assertRaises(q.r.Stop) as caught:
                q.qualify()
        self.assertEqual(caught.exception.code, "vendor_decoder")
        self.assertFalse(any("run" in call.args[0] for call in command.call_args_list))
        self.assertEqual(command.call_args_list[-1].args[0][-2:], ["clean", "-modcache"])

    def test_hostile_probe_and_cleanup_preserve_primary(self):
        with tempfile.TemporaryDirectory() as directory:
            owned = Path(directory) / "owned"
            owned.mkdir()
            def failing(args, code, **kwargs):
                if "run" in args or args[-2:] == ["clean", "-modcache"]:
                    raise RuntimeError(SECRET)
                return tool(args, code, **kwargs)
            output = io.StringIO()
            with patch.object(q.tempfile, "mkdtemp", return_value=str(owned)), patch.object(q.r, "checked_command", side_effect=failing), contextlib.redirect_stdout(output):
                self.assertEqual(q.cli(["qualify"]), 1)
            value = json.loads(output.getvalue())
            self.assertEqual(value["code"], "SYNTHETIC_VENDOR_DECODER")
            self.assertEqual(value["additional_failures"][0]["stage"], "vendor_fixture_cleanup")
            self.assertNotIn(SECRET, output.getvalue())

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_actual_descendant_is_signalled_and_uncertain_cache_is_retained(self):
        # No Go or vendor execution: a Python parent spawns a sleeping child.
        real_checked = q.r.checked_command
        real_popen = q.r.subprocess.Popen
        real_killpg = os.killpg
        leaders = []
        child_code = ("import os,pathlib,sys,time; "
                      "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
                      "print('ready',flush=True); time.sleep(30)")
        parent_code = ("import subprocess,sys,time; "
                       "p=subprocess.Popen([sys.executable,'-c'," + repr(child_code) + ",sys.argv[1]], "
                       "stdout=subprocess.PIPE); "
                       "assert p.stdout.readline()==b'ready\\n'; "
                       "print('ready',flush=True); time.sleep(30)")
        with tempfile.TemporaryDirectory() as directory:
            owned = Path(directory) / "owned"
            owned.mkdir()
            child_pid = Path(directory) / "child.pid"
            def tracked(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                leaders.append((process, kwargs))
                return process
            def invoke(args, code, **kwargs):
                if "run" in args:
                    return real_checked([sys.executable, "-c", parent_code, str(child_pid)], code,
                                        timeout=2, process_group=kwargs.get("process_group", False))
                return tool(args, code, **kwargs)
            try:
                with patch.object(q.tempfile, "mkdtemp", return_value=str(owned)), \
                     patch.object(q.r.subprocess, "Popen", side_effect=tracked), \
                     patch.object(q.r.os, "killpg", wraps=real_killpg) as group_signal, \
                     patch.object(q.r, "checked_command", side_effect=invoke) as command:
                    with self.assertRaises(q.r.Stop) as caught:
                        q.qualify()
                    self.assertTrue(child_pid.is_file(), "descendant fixture must actually start")
                    self.assertEqual(caught.exception.code, "vendor_decoder")
                    self.assertTrue(caught.exception.process_cleanup_failed)
                    self.assertTrue(caught.exception.cleanup_failed)
                    self.assertTrue(owned.is_dir())
                    leader, options = leaders[0]
                    self.assertTrue(options["start_new_session"])
                    self.assertIsNotNone(leader.poll())
                    group_signal.assert_any_call(leader.pid, signal.SIGKILL)
                    self.assertFalse(any(call.args[0][-2:] == ["clean", "-modcache"] for call in command.call_args_list))
            finally:
                # Rescue only this synthetic fixture, including when testing old code.
                if child_pid.is_file():
                    try:
                        os.kill(int(child_pid.read_text()), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                for leader, options in leaders:
                    if options.get("start_new_session"):
                        try:
                            real_killpg(leader.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    if leader.poll() is None:
                        leader.kill()
                        leader.wait(timeout=3)

    def test_unjoined_tool_refuses_cache_removal(self):
        with tempfile.TemporaryDirectory() as directory:
            owned = Path(directory) / "owned"
            owned.mkdir()
            def unjoined(args, code, **kwargs):
                if "run" in args:
                    raise q.r.Stop("process_cleanup", outcome="unknown")
                return tool(args, code, **kwargs)
            with patch.object(q.tempfile, "mkdtemp", return_value=str(owned)), patch.object(q.r, "checked_command", side_effect=unjoined) as command:
                with self.assertRaises(q.r.Stop) as caught:
                    q.qualify()
            self.assertEqual(caught.exception.code, "process_cleanup")
            self.assertTrue(caught.exception.cleanup_failed)
            self.assertTrue(owned.exists())
            self.assertFalse(any(call.args[0][-2:] == ["clean", "-modcache"] for call in command.call_args_list))

    def test_unexpected_probe_projection_is_refused(self):
        def wrong(args, code, **kwargs):
            return json.dumps({**PASS, "raw": SECRET}).encode() if "run" in args else tool(args, code, **kwargs)
        output = io.StringIO()
        with patch.object(q.r, "checked_command", side_effect=wrong), contextlib.redirect_stdout(output):
            self.assertEqual(q.cli(["qualify"]), 1)
        self.assertEqual(json.loads(output.getvalue())["code"], "SYNTHETIC_VENDOR_DECODER")
        self.assertNotIn(SECRET, output.getvalue())


if __name__ == "__main__":
    unittest.main()
