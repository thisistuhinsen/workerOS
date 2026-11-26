"""Run one explicitly selected, caller-owned host profile on Linux."""

import argparse
import base64
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic_ns
from uuid import uuid4

from worker_handoff import ReleasePlan, observe
from worker_handoff.configuration import ConfigurationError, decode_request
from worker_handoff.enrollment import DescriptorBinding, HostBindings, compile_policy
from worker_handoff.managed import ReleaseResult
from worker_handoff.recording import LocalStore, RecordError, StoragePolicy


PROFILE = "local-read"
ROLE = "local-operator"
WORKER = "read-original"
ARCHIVE = "archive"
TERMINAL = "terminal"
CLEANUP_MS = 2_000
CONTENT = b"workerOS local host profile\n"
OPERATIONS = ["release", "cleanup", "record", "readback"]


def policy():
    return {
        "version": 1,
        "roles": {ROLE: {"operations": OPERATIONS}},
        "workflows": {
            PROFILE: {
                "role": ROLE,
                "operations": OPERATIONS,
                "bindings": {"executable": "reader", "descriptors": "original",
                             "supervisor": "direct-child"},
                "require_supervision": True,
                "timeout_ms": 5_000,
                "cleanup_ms": CLEANUP_MS,
                "recorder": "local-recorder",
            },
        },
        "recorders": {
            "local-recorder": {
                "version": 1,
                "destinations": {ARCHIVE: {}},
                "routes": [{"name": TERMINAL, "media_type": "application/json",
                            "required": [ARCHIVE], "optional": []}],
            },
        },
    }


def request(operation, **options):
    return decode_request(json.dumps({"version": 1, "workflow": PROFILE, "role": ROLE,
                                      "operation": operation, "options": options}))


def reconcile_process(process, deadline_ns):
    """Reap the exact owned Popen returned if the supervisor could not pin it."""
    killed = False
    try:
        if process.poll() is None and monotonic_ns() < deadline_ns:
            process.kill()
            killed = True
        code = process.wait(timeout=max(0, deadline_ns - monotonic_ns()) / 1_000_000_000)
        return {"status": "reaped", "returncode": code, "kill_sent": killed}
    except subprocess.TimeoutExpired:
        return {"status": "pending", "kill_sent": killed}
    except OSError:
        return {"status": "unknown", "kill_sent": killed}


def cleanup_child(compiled, authorization, delivery):
    workflow = compiled[PROFILE]
    try:
        return compiled.execute(authorization)
    except KeyError:
        release = workflow.releases.get(WORKER)
        if type(release) is ReleaseResult and release.worker is not None and release.worker.process is not None:
            return reconcile_process(release.worker.process, workflow.cleanup_deadline_ns)
        return {"status": "not_requested" if delivery == "not-attempted" else "unknown"}
    except (ConfigurationError, OSError, RuntimeError):
        return {"status": "unknown"}


def record_terminal(compiled, approved, attempt_id, terminal, cleanup):
    # The host authorizes only this projection of its own observed child result.
    payload = json.dumps({"attempt_id": attempt_id, "lifecycle": terminal["lifecycle"],
                          "returncode": terminal["returncode"], "cleanup": cleanup["status"]},
                         sort_keys=True).encode("ascii")
    approved["record"] = request(
        "record", run_id=attempt_id, record_id=TERMINAL, type=TERMINAL,
        data=base64.b64encode(payload).decode("ascii"), effect="not-attempted",
    )
    committed = compiled.execute(approved["record"])
    (entry,) = committed["destinations"]
    answer = {"status": "unavailable", "commit": entry["state"]}
    if committed["required_complete"]:
        receipt = entry["receipt"]
        # Nanosecond timestamps use a canonical string in the JSON request.
        wire_receipt = receipt | {"committed_ns": str(receipt["committed_ns"])}
        approved["readback"] = request("readback", destination=ARCHIVE, receipt=wire_receipt)
        readback = compiled.execute(approved["readback"])
        answer["readback"] = readback["persistence"]
        if (readback["persistence"] == "verified" and readback["size"] == len(payload)
                and readback["sha256"] == sha256(payload).hexdigest()
                and readback["key"] == {"run_id": attempt_id, "record_id": TERMINAL}):
            answer.update(status="local_readback_verified", attempt_id=readback["key"]["run_id"])
    return answer


def run_profile(root, report):
    destination = root / ARCHIVE
    destination.mkdir(mode=0o700)
    archive = LocalStore(destination)
    try:
        if archive.check_writable(StoragePolicy()) is not True:
            raise ConfigurationError("archive_unavailable")
    except (ConfigurationError, OSError, RecordError):
        report["preflight"] = {"status": "refused", "code": "capability_unavailable", "binding": "stores.archive"}
        return 2

    original_path = root / "input"
    original_path.write_bytes(CONTENT)
    child = (
        "import os; fd = int(os.environ['WORKER_HANDOFF_FD_INPUT']); "
        f"raise SystemExit(0 if os.pread(fd, {len(CONTENT) + 1}, 0) == {CONTENT!r} else 1)"
    )
    argv = (str(Path(sys.executable).absolute()), "-I", "-c", child)
    approved = {
        "release": request("release", name=WORKER, supervise=True, cleanup_ms=CLEANUP_MS),
        "cleanup": request("cleanup", name=WORKER, cleanup_ms=CLEANUP_MS),
    }
    with original_path.open("rb") as original:
        binding = DescriptorBinding(observe(original.fileno()).identity, input_fd=original.fileno())
        expected_plan = None
        host = HostBindings(
            executables={"reader": argv}, descriptors={"original": binding}, stores={ARCHIVE: archive},
            supervisors=frozenset({"direct-child"}),
            authorize=lambda selected: selected == approved.get(selected.operation),
            authorize_release=lambda selected: selected == expected_plan,
        )
        try:
            compiled = compile_policy(policy(), host, workflow=PROFILE)
            workflow = compiled[PROFILE]
            expected_plan = ReleasePlan(WORKER, ROLE, argv, binding.identity, workflow.deadline_ns)
            workflow.supervisor.check_available(WORKER, ROLE)
        except ConfigurationError as exc:
            report["preflight"] = {"status": "refused", "code": str(exc)}
            return 2
        except (OSError, RuntimeError):
            report["preflight"] = {"status": "refused", "code": "capability_unavailable",
                                   "binding": "supervisors.direct-child"}
            return 2

        report["preflight"] = {"status": "prepared"}
        terminal = None
        try:
            result = compiled.execute(approved["release"])
            terminal = result["terminal"]
            report["operation"] = {
                "delivery": result["delivery"], "effect": result["effect"], "error": result["error"],
                "lifecycle": terminal["lifecycle"] if terminal else "unavailable",
                "returncode": terminal["returncode"] if terminal else None,
            }
        except ConfigurationError as exc:
            report["operation"]["code"] = str(exc)
        except (OSError, RuntimeError):
            report["operation"] = {"delivery": "unknown", "effect": "unknown"}
        finally:
            during_release = terminal["cleanup"] if terminal is not None else None
            if during_release and during_release["status"] == "reaped":
                report["cleanup"]["child"] = during_release
            else:
                if during_release and during_release["status"] != "not_requested":
                    report["cleanup"]["during_release"] = during_release
                report["cleanup"]["child"] = cleanup_child(compiled, approved["cleanup"], report["operation"]["delivery"])

        cleanup = report["cleanup"]["child"]
        if terminal is not None and cleanup["status"] == "reaped":
            try:
                report["evidence"] = record_terminal(compiled, approved, report["attempt_id"], terminal, cleanup)
            except (ConfigurationError, OSError, RuntimeError):
                report["evidence"] = {"status": "unavailable"}
        operation = report["operation"]
        completed = (operation["delivery"] == "dispatched" and operation.get("lifecycle") == "exited"
                     and operation.get("returncode") == 0 and not operation["error"]
                     and report["evidence"]["status"] == "local_readback_verified")
        return 0 if completed else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, help=f"select the enrolled {PROFILE} profile")
    parser.add_argument("--without-archive", action="store_true", help="demonstrate missing archive preflight")
    args = parser.parse_args(argv)

    report = {
        "profile": args.profile, "preflight": {"status": "refused"},
        "operation": {"delivery": "not-attempted", "effect": "not-attempted"},
        "evidence": {"status": "not_requested"},
        "cleanup": {"child": {"status": "not_requested"}, "local_resources": "not_created"},
    }
    code = 2
    if args.profile != PROFILE:
        report["preflight"]["code"] = "unknown_profile"
    elif args.without_archive:
        report["preflight"].update(code="missing_capability", binding="stores.archive")
    else:
        report["attempt_id"] = "attempt-" + uuid4().hex
        try:
            with TemporaryDirectory(prefix="workerOS-host-") as directory:
                report["cleanup"]["local_resources"] = "unknown"
                code = run_profile(Path(directory), report)
            report["cleanup"]["local_resources"] = "removed"
        except OSError:
            code = 1
            if report["preflight"]["status"] == "refused":
                report["preflight"]["code"] = "local_setup_unavailable"
                code = 2
    print(json.dumps(report, sort_keys=True))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
