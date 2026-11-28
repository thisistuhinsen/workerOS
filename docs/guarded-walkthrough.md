# Commission a guarded worker in a disposable systemd guest

This walkthrough uses a clean Ubuntu 24.04 x86-64 guest with systemd 255,
cgroup v2, POSIX ACLs, and the matching WorkerOS platform wheel. The
administrator selects one existing protected original for an appointed
worker to write. The caller has no access to that file or to the
administrator's setup documents. The writer, guard, caller and original
owner are four distinct OS users. The original owner also runs the
independent witness. For a real deployment, substitute already approved
identities and originals.

## Install and appoint the scope

Place the checker-approved wheel at
`/opt/workeros-qual/workeros-0.8.0-py3-none-linux_x86_64.whl`, owned and
writable only by the administrator, and make it readable by the guard and
witness. Have its published SHA-256 available. The example uses
`python3-venv`, a C compiler with static libc, and `setfacl`. Complete
the [verified platform install](install-0.8.0.md) first if the guest lacks them.

Enter the administrator shell through the OS once. Execute the remaining
setup blocks there in the same shell. These commands assume a guest
reserved for this test, with no existing WorkerOS configuration or these
four fixture accounts.

```sh
sudo -i
set -eu
home=/opt/workeros-qual
wheel=$home/workeros-0.8.0-py3-none-linux_x86_64.whl
umask 022
read -r -p 'Approved wheel SHA-256: ' wheel_sha
test "$(sha256sum "$wheel" | cut -d' ' -f1)" = "$wheel_sha"
python3 -m venv "$home/venv"
py=$home/venv/bin/python
wos=$home/venv/bin/workeros
"$py" -m pip install --no-index --no-deps "$wheel"
"$py" -I -m workeros.verify_install "$wheel" --sha256 "$wheel_sha"
umask 077
example=$home/venv/share/workeros/examples
test ! -e /etc/workeros
for user in wo-demo-guard wo-demo-worker wo-demo-caller wo-demo-owner; do
    ! getent passwd "$user"
    useradd --user-group --no-create-home --shell /usr/sbin/nologin "$user"
done
runuser -u wo-demo-caller -- "$wos" run -- /usr/bin/printf 'hello\n'
p=$(mktemp -d /run/workeros-demo.XXXXXXXX)
chmod 0755 "$p"
install -d -m 0700 /etc/workeros "$p/setup-journal"
install -d -m 0755 "$p/root" "$p/client"
install -d -m 0750 -g wo-demo-guard "$p/commission"
install -d -m 0700 -o wo-demo-guard -g wo-demo-guard "$p/guard" "$p/guard-journal"
install -d -m 0700 -o wo-demo-owner -g wo-demo-owner "$p/holder" "$p/witness" "$p/original"
for dir in holder witness; do
    setfacl --set 'u::rwx,u:wo-demo-guard:--x,g::---,m::--x,o::---' "$p/$dir"
done
install -m 0600 -o wo-demo-owner -g wo-demo-owner /dev/null "$p/original/output"
cc -static -O2 "$example/guarded_write.c" -o "$p/root/worker"
chmod 0755 "$p/root/worker"
```

The owner can open the file under its own OS permissions. Before granting
the role, verify that the caller cannot. This test opens the file without
writing.

```sh
runuser -u wo-demo-caller -- "$py" -I - "$p/original/output" <<'PY'
import errno, os, sys
try:
    fd = os.open(sys.argv[1], os.O_WRONLY)
except OSError as error:
    if error.errno not in (errno.EACCES, errno.EPERM):
        raise
    print("caller write denied")
else:
    os.close(fd)
    raise SystemExit("caller unexpectedly has write access")
PY
```

## Pin the guard, then preview and approve

Choose whether to meter this run before commissioning. `metered=1`
requires CPU and memory delegation in this disposable guest. `metered=0`
leaves accounting unavailable and supports the same scoped write. There
is no metered fallback after admission.

```sh
metered=1
unit=workeros-demo-guard.service
deadline=$("$py" -I -c 'import time; print(time.monotonic_ns()+900_000_000_000)')
expires=$(( $(date +%s) + 960 ))
systemd-run --quiet --collect --unit "$unit" \
  --uid wo-demo-guard --gid wo-demo-guard \
  --property Type=simple --property 'Delegate=cpu memory' --property DelegateSubgroup=anchor \
  --property 'AmbientCapabilities=CAP_SETUID CAP_SETGID' \
  --property 'CapabilityBoundingSet=CAP_SETUID CAP_SETGID' \
  --property RuntimeMaxSec=900s \
  "$wos" managed serve-guard --commissioned --commissioning-unit "$unit" \
    --commissioning-directory "$p/commission" --commissioning-deadline-ns "$deadline"

for tries in {1..100}; do
    journalctl --no-pager -b -u "$unit" -o cat > "$p/guard.log"
    grep -m1 '^{"phase": "guard_parent_pinned"' "$p/guard.log" > "$p/parent.json" && break
    sleep 0.05
done
test -s "$p/parent.json"
```

For the metered option, verify the guard is in the delegated anchor and
enable the requested controllers only inside that exact empty domain.
The operator configures the delegated service. WorkerOS checks the effective
controllers before opening its listener and measures only the worker leaf.

```sh
if [ "$metered" -eq 1 ]; then
    "$py" -I - "$p/parent.json" "$unit" <<'PY'
import json, os, subprocess, sys
from pathlib import Path

pin = json.loads(Path(sys.argv[1]).read_bytes())
parent = pin["parent"]
group = Path("/sys/fs/cgroup") / parent["control_group"].lstrip("/")
assert parent["unit"] == sys.argv[2] and group.name == parent["unit"]
assert os.readlink("/proc/self/ns/cgroup") == os.readlink("/proc/1/ns/cgroup")
st = group.stat()
assert (st.st_dev, st.st_ino, st.st_uid) == (parent["device"], parent["inode"], pin["guard_uid"])
assert (group / "cgroup.type").read_text().strip() == "domain"
assert not (group / "cgroup.procs").read_text().strip()
assert str(pin["main_pid"]) in (group / "anchor/cgroup.procs").read_text().split()
control = group / "cgroup.subtree_control"
assert control.stat().st_uid == pin["guard_uid"]
required = {"cpu", "memory"}
assert required <= set((group / "cgroup.controllers").read_text().split())
missing = required - set(control.read_text().split())
if missing:
    subprocess.run(["runuser", "-u", "wo-demo-guard", "--", "sh", "-c",
                    'printf "%s\n" "$2" > "$1"', "scope", str(control),
                    " ".join("+" + name for name in sorted(missing))], check=True)
assert required <= set(control.read_text().split())
PY
fi
```

Create a draft from those actual identities and the verified executable
and wheel. Review the draft and preview before running the apply command.

```sh
"$py" -I - "$p" "$wheel" "$wheel_sha" "$deadline" "$expires" "$metered" > "$p/spec.json" <<'PY'
from hashlib import sha256
import json, pwd, secrets, sys
from pathlib import Path

work, wheel, digest, until, unix_expiry, metered = sys.argv[1:]
p = Path(work)
owner, guard, caller, worker = (pwd.getpwnam("wo-demo-" + role)
                                for role in ("owner", "guard", "caller", "worker"))
root = p / "root"
out = p / "original/output"
st = out.stat()
parent = json.loads((p / "parent.json").read_bytes())["parent"]
spec = {
    "profile": "diagnostic-reports", "revision": "r1",
    "workflow": "write-health-record", "workflow_revision": "r1", "generation": "r1",
    "role": "health-record-writer", "principal": worker.pw_name,
    "launcher": "local-launcher", "manager": "local-manager", "authority": "local-guard",
    "authority_socket": str(p / "guard/guard.sock"), "authority_uid": guard.pw_uid,
    "client_socket": str(p / "client/launch.sock"),
    "wheel_path": wheel, "wheel_sha256": digest,
    "executable_sha256": sha256((root / "worker").read_bytes()).hexdigest(),
    "expires_ns": int(until), "expires_at": int(unix_expiry),
    "operation_key": secrets.token_hex(32),
    "run_uids": [caller.pw_uid], "result_uids": [caller.pw_uid],
    "journal_directory": str(p / "setup-journal"),
    "service": {
        "root_directory": str(root), "root_device": root.stat().st_dev, "root_inode": root.stat().st_ino,
        "executable": "/worker", "principal_gid": worker.pw_gid, "active_ms": 4000, "cleanup_ms": 5000,
        "metered": metered == "1", "parent": parent,
        "descriptors": [{"slot": "stdout", "scope": "health-report", "owner_uid": st.st_uid,
                         "mode": "write", "device": st.st_dev, "inode": st.st_ino, "fd": 3}],
        "elevated_capabilities": [{"name": "write_health_record", "scope": "health-report", "operation": "write"}],
    },
    "holder": {"uid": owner.pw_uid, "socket": str(p / "holder/holder.sock")},
    "result_observer": {"uid": owner.pw_uid, "socket": str(p / "witness/witness.sock"),
                        "source": "protected-output-owner", "handoff": True,
                        "expected_effect_sha256": sha256(b"worker ready\n").hexdigest()},
}
print(json.dumps(spec))
PY
"$py" -I "$example/draft_guarded_profile.py" draft "$p/spec.json" > "$p/approved.json"
"$wos" managed apply-profile --provision-managed --preview < "$p/approved.json"
```

```sh
profile=diagnostic-reports
revision=r1
workflow=write-health-record
"$wos" managed apply-profile --provision-managed < "$p/approved.json"
"$wos" managed profile-status --registered-managed "$profile" "$revision" > "$p/status.json"
pending=$(mktemp -d "$p/commission/pending.XXXXXXXX")
chgrp wo-demo-guard "$pending"
chmod 0750 "$pending"
"$py" -I "$example/draft_guarded_profile.py" guard "$p/approved.json" "$p/status.json" \
  "$workflow" --journal "$p/guard-journal" > "$pending/workeros-guard.json"
chgrp wo-demo-guard "$pending/workeros-guard.json"
chmod 0640 "$pending/workeros-guard.json"
install -m 0640 -g wo-demo-guard /etc/workeros/managed-setup.json "$pending/workeros-setup.json"
install -m 0640 -g wo-demo-guard /etc/workeros/launch-executor.json "$pending/workeros-executor.json"
```

## Activate and run under the appointed caller

The owners and services use finite listeners. Run this block together so each
listener is ready when its consumer connects. The holder opens precisely the
registered output with its existing authority. The witness separately opens
the same output read-only. The guard and launcher receive held descriptors
from the holder.

```sh
wait_socket() {
    for tries in {1..100}; do
        [ ! -S "$1" ] || return 0
        sleep 0.02
    done
    return 1
}
workeros_open_file() {
    printf 'OpenFile=%s/workeros-%s.json:workeros-%s:read-only' "$1" "$2" "$2"
}
systemd-run --quiet --collect --unit workeros-demo-holder.service \
  --uid wo-demo-owner --gid wo-demo-owner \
  --property "$(workeros_open_file "$pending" executor)" \
  "$wos" managed serve-holder --commissioned "$workflow" --original-stdout "$p/original/output"
wait_socket "$p/holder/holder.sock"
reg=$p/commission/registration
mv -T -- "$pending" "$reg"
wait_socket "$p/guard/guard.sock"
systemd-run --quiet --collect --unit workeros-demo-witness.service \
  --uid wo-demo-owner --gid wo-demo-owner \
  --property "$(workeros_open_file "$reg" setup)" --property "$(workeros_open_file "$reg" executor)" \
  "$wos" managed serve-witness --commissioned "$workflow" --observed-output "$p/original/output"
wait_socket "$p/witness/witness.sock"
id=$("$py" -I -c 'import secrets; print(secrets.token_hex(32))')
printf '%s\n' "$id" > "$p/request-id"
"$wos" managed serve-launch --commissioned "$workflow" > "$p/listener.json" &
listener=$!
wait_socket "$p/client/launch.sock"
if runuser -u wo-demo-caller -- "$wos" managed run-approved --workflow "$workflow" --request-id "$id"; then
    :
else
    printf 'Check status using request ID %s\n' "$id"
fi
wait "$listener"
```

If the result is unknown, retain the request ID and use `launch-status`.
Do not submit the same effect again. After the live guard's owned socket
retires, the appointed guard can serve authenticated terminal readback
from its existing journal with the same registration.

```sh
for tries in {1..250}; do
    [ -S "$p/guard/guard.sock" ] || break
    sleep 0.05
done
test ! -S "$p/guard/guard.sock"
systemd-run --quiet --collect --unit workeros-demo-readback.service \
  --uid wo-demo-guard --gid wo-demo-guard \
  --property "$(workeros_open_file "$reg" guard)" --property "$(workeros_open_file "$reg" setup)" \
  --property "$(workeros_open_file "$reg" executor)" \
  "$wos" managed serve-guard --commissioned --readback-only
wait_socket "$p/guard/guard.sock"
"$wos" managed serve-launch --commissioned "$workflow" > "$p/readback-listener.json" &
listener=$!
wait_socket "$p/client/launch.sock"
runuser -u wo-demo-caller -- "$wos" managed launch-status --workflow "$workflow" --request-id "$id"
# The status lookup leaves the run slot unused. The listener closes
# when its finite window expires after serving the authorized status.
wait "$listener"
"$wos" managed revoke-profile "$profile" "$revision"
for service in "$unit" workeros-demo-holder.service workeros-demo-witness.service workeros-demo-readback.service; do
    if systemctl is-active --quiet "$service"; then
        systemctl stop "$service"
    fi
done
```

Look for a verified independent result and cleanup on that exact ID.
When metering is selected, use the same result's initial and final CPU and
current/peak memory evidence. The output lives in the approved owner-held
file. A revoked profile may still be read by its enrolled historical reader
using `serve-launch --history` and `launch-status --revision "$revision"`
with the same ID. Keep the admin receipt and exact guest disposal record.
