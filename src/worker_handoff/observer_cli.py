"""One-shot JSON observation: python -m worker_handoff.observer_cli.

The launcher's first stdin line supplies the trusted binding. An observation is
not a signed receipt. No default file opens, PID discovery or policy changes.
"""
from dataclasses import asdict
import json
import os
import sys

from .evidence import EvidenceScope, RunBinding
from .lifecycle import RegularFileObserver
from .original import Identity
from .workers import Worker


def main():
    plan = json.loads(sys.stdin.readline())
    refs = [plan["original_fd"], plan["pidfd"]]
    if "directory_fd" in plan:
        refs.append(plan["directory_fd"])
    if any(type(fd) is not int or fd < 3 for fd in refs) or len(set(refs)) != len(refs):
        raise ValueError("expected distinct, explicitly inherited non-standard handles")
    for fd in refs:
        os.set_inheritable(fd, False)  # claim this observer's inherited copies only
    with RegularFileObserver(
        scope=plan["scope"], due_ns=plan["due_ns"],
        original_fd=plan["original_fd"], identity=Identity(plan["device"], plan["inode"]),
        pidfd=plan["pidfd"], worker=Worker("target", "observed", plan["pid"], plan["uid"]),
        slot=plan["slot"], directory_fd=plan.get("directory_fd"), leaf=plan.get("leaf"),
    ) as provider:
        if "scope_report" in plan:
            request = plan["scope_report"]
            scope_fields = dict(request["scope"])
            scope_fields["run"] = RunBinding(**scope_fields["run"])
            sample, report = provider.sample_for_scope(
                EvidenceScope(**scope_fields), provider_id=request["provider_id"],
                subject=request.get("subject", "slot"),
            )
            result = {"sample": asdict(sample), "scope_report": asdict(report)}
        else:
            result = asdict(provider.sample())
        print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
