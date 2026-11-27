"""Durability and lost-acknowledgement checks for the installed local policy."""
import errno
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from workeros.policy_cli import _LocalDestination
from workeros.recording import EvidenceType, Persistence, RecordError, RecordKey, RecorderPolicy


class InstalledPolicyDurabilityTest(unittest.TestCase):
    def test_lazy_creation_syncs_held_parent_before_first_commit_and_on_verify(self):
        with TemporaryDirectory() as root:
            directory = Path(root) / "archive"
            store = _LocalDestination(directory)
            policy = RecorderPolicy.from_dict({
                "version": 1, "destinations": {"archive": {}},
                "routes": [{"name": "job", "media_type": "application/json", "required": ["archive"]}],
            }, stores={"archive": store})
            key, kind = RecordKey("job", "result"), EvidenceType("job", "application/json")
            parent = os.stat(root)
            real_fsync = os.fsync
            syncs = []

            def track(fd, fail=False):
                is_parent = os.path.samestat(os.fstat(fd), parent)
                syncs.append(is_parent)
                if is_parent and fail:
                    raise OSError(errno.EIO, "synthetic parent sync failure")
                real_fsync(fd)

            with patch("os.fsync", side_effect=lambda fd: track(fd, fail=True)):
                failed = policy.record(key, kind, b"{}").destinations[0]
            self.assertEqual(failed.state, Persistence.UNKNOWN)
            self.assertEqual(syncs, [True])
            self.assertEqual(list(directory.iterdir()), [])
            syncs.clear()
            with patch("os.fsync", side_effect=track):
                done = policy.record(key, kind, b"{}").destinations[0]
            self.assertEqual(done.state, Persistence.COMMITTED)
            self.assertEqual(syncs, [True, False, False])
            with patch("os.fsync", side_effect=lambda fd: track(fd, fail=True)):
                with self.assertRaises(RecordError) as error:
                    policy.verify_durable("archive", done.receipt)
            self.assertEqual(error.exception.status, Persistence.UNKNOWN)
            self.assertEqual(policy.readback("archive", done.receipt), b"{}")
            self.assertEqual(policy.verify_durable("archive", done.receipt), b"{}")

    def test_unknown_capture_recovers_by_announced_attempt_without_launch(self):
        with TemporaryDirectory() as root:
            root = Path(root)
            archive, marker, events = (root / name for name in ("archive", "started", "events"))
            worker = root / "worker"
            worker.write_text(
                f"#!{sys.executable}\n"
                "import json\nfrom pathlib import Path\n"
                f"assert json.loads(Path({str(events)!r}).read_text())['event'] == 'launch_attempt'\n"
                f"with Path({str(marker)!r}).open('a') as marker:\n    marker.write('once\\n')\n"
            )
            worker.chmod(0o700)
            operations = ["launch", "recover_receipt", "verify_durable"]
            document = {
                "version": 1, "roles": {"job": {"operations": operations}},
                "workflows": {"job": {"role": "job", "operations": operations, "recorder": "jobs",
                                       "bindings": {"executable": "tool"},
                                       "capture": {"launch": {"profile": "launch-terminal", "type": "job"}}}},
                "recorders": {"jobs": {"version": 1, "destinations": {"archive": {}}, "routes": [
                    {"name": "job", "media_type": "application/json", "required": ["archive"]}]}},
            }
            path = root / "policy"
            path.write_text(json.dumps(document))
            args = ["--run-policy", str(path), "--executable", "tool", str(worker),
                    "--store", "archive", str(archive)]
            inject = (
                "import errno, os\n"
                "from workeros.configuration_cli import main\n"
                "sync = os.fsync\n"
                "def fsync(fd):\n"
                f"    if os.path.isdir({str(archive)!r}) and "
                f"os.path.samestat(os.fstat(fd), os.stat({str(archive)!r})):\n"
                "        raise OSError(errno.EIO, 'synthetic leaf sync failure')\n"
                "    sync(fd)\n"
                "os.fsync = fsync\nraise SystemExit(main())\n"
            )

            def invoke(command, operation, options, **kwargs):
                request = {"version": 1, "workflow": "job", "role": "job",
                           "operation": operation, "options": options}
                return subprocess.run([sys.executable, *command, *args], input=json.dumps(request),
                                      text=True, stdout=subprocess.PIPE, timeout=12, **kwargs)

            with events.open("w") as log:
                child = invoke(["-c", inject], "launch", {"name": "label"}, stderr=log)
            reply = json.loads(child.stdout)
            if os.geteuid() == 0 or os.getuid() != os.geteuid() or os.getgid() != os.getegid():
                self.assertEqual((child.returncode, reply["code"]), (1, "privileged_policy_cli_unsupported"))
                self.assertFalse(marker.exists())
                return
            self.assertEqual(child.returncode, 3, reply)
            event = json.loads(events.read_text())
            self.assertEqual(event["attempt_id"], reply["result"]["attempt_id"])
            self.assertEqual(reply["result"]["terminal"]["returncode"], "0")
            item = reply["result"]["capture"]["record"]["destinations"][0]
            self.assertEqual((item["state"], item["receipt"]), ("unknown", None))
            cli = ["-m", "workeros.configuration_cli"]
            recovered = invoke(cli, "recover_receipt",
                               {"destination": "archive", "attempt_id": event["attempt_id"]})
            self.assertEqual(recovered.returncode, 0, recovered.stdout)
            result = json.loads(recovered.stdout)["result"]
            self.assertEqual((result["persistence"], result["durability"]), ("verified", "unconfirmed"))
            self.assertEqual(result["receipt"]["key"]["run_id"], event["attempt_id"])
            durable = invoke(cli, "verify_durable", {"destination": "archive", "receipt": result["receipt"]})
            self.assertEqual(durable.returncode, 0, durable.stdout)
            self.assertEqual(json.loads(durable.stdout)["result"]["durability"], "confirmed")
            self.assertEqual(marker.read_text(), "once\n")
