"""Installed controller schema and runnable, locally owned evidence example."""

import argparse
from io import BytesIO
from importlib.resources import files
import json
from pathlib import Path
import sys
from time import monotonic_ns

from .configuration import ConfigurationError, Workflow, decode_request, serve
from .policy_cli import run_policy_cli
from .recording import LocalStore, RecorderPolicy


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--schema", action="store_true", help="print the installed JSON schema")
    mode.add_argument("--example-root", type=Path, help="caller-owned directory containing archive and review")
    mode.add_argument("--check-policy", type=Path, help="validate policy against enrolled local bindings")
    mode.add_argument("--run-policy", type=Path, help="serve one invocation under an approved local policy")
    parser.add_argument("--format", choices=("json", "yaml"),
                        help="policy file format for --check-policy or --run-policy (default: json; invocations use JSON)")
    parser.add_argument("--policy-sha256", help="optional expected SHA-256 of the policy bytes")
    parser.add_argument("--executable", nargs=2, action="append", default=[], metavar=("NAME", "ABSOLUTE_PATH"))
    parser.add_argument("--store", nargs=2, action="append", default=[], metavar=("NAME", "ABSOLUTE_DIR"))
    parser.add_argument("--group-store", nargs=3, action="append", default=[], metavar=("NAME", "ABSOLUTE_DIR", "GID"))
    parser.add_argument("--inherit-fd", nargs=2, action="append", default=[], metavar=("NAME", "FD"))
    parser.add_argument("--cwd", nargs=2, action="append", default=[], metavar=("NAME", "ABSOLUTE_DIR"))
    parser.add_argument("--env", nargs=2, action="append", default=[], metavar=("NAME", "VALUE"))
    parser.add_argument("--secret-env", nargs=2, action="append", default=[], metavar=("NAME", "VARIABLE"))
    parser.add_argument("--stream-fd", nargs=2, action="append", default=[], metavar=("NAME", "FD"))
    parser.add_argument("--workflow", help="bind only this operator-selected workflow")
    parser.add_argument("--explain", action="store_true", help="show safe effective values when checking policy")
    parser.add_argument("--settled-run", action="append", default=[], metavar="NAME")
    args = parser.parse_args(argv)
    if args.check_policy or args.run_policy:
        return run_policy_cli(args)
    if args.format is not None:
        parser.error("--format requires --check-policy or --run-policy")
    if any((args.policy_sha256, args.executable, args.store, args.group_store, args.inherit_fd,
            args.cwd, args.env, args.secret_env, args.stream_fd, args.explain, args.workflow, args.settled_run)):
        parser.error("host enrollment flags require a policy mode")
    if args.schema:
        sys.stdout.write(files("workeros").joinpath("configuration.schema.json").read_text())
        return 0
    try:
        data = sys.stdin.buffer.read(1_048_577)
        if len(data) > 1_048_576:
            raise ConfigurationError("request_too_large")
        request = decode_request(data)
        policy = request.recorder
        if not policy or request.workflow != "example" or request.role != "recorder":
            raise ConfigurationError("example_enrollment_required")
        root = args.example_root.absolute()
        stores = {
            name: LocalStore(root / name, group_id=policy["destinations"].get(name, {}).get("group_id"))
            for name in ("archive", "review")
        }
        recorder = RecorderPolicy.from_dict(policy, stores=stores)
    except (KeyError, TypeError, ValueError, OSError, AttributeError) as exc:
        code = str(exc) if type(exc) is ConfigurationError else "invalid_example_policy"
        print(json.dumps({"status": "refused", "code": code}))
        return 1
    workflow = Workflow("recorder", frozenset(("record", "readback")), monotonic_ns() + 60_000_000_000,
                        recorder=recorder, recorder_config=policy, authorize=lambda _: True)
    return serve({"example": workflow}, BytesIO(data), sys.stdout)


if __name__ == "__main__":
    raise SystemExit(main())
