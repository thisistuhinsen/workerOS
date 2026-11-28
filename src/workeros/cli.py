"""WorkerOS: run local jobs and connect approved managed profiles."""
import argparse
from io import BytesIO, TextIOWrapper
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from importlib.metadata import PackageNotFoundError, version as package_version
import json
import math
from pathlib import Path
import re
import shlex
import sys
import time

_LIMIT=65536
_INPUT_ROLES=frozenset(('preview','apply','grant-preview','grant-apply','grant-check','grant-revoke'))

_HELP={
 'start': '''WorkerOS
Run a job. Know how it ended.
Version: {version}

First run:
  $ workeros run -- /usr/bin/printf 'hello\\n'
  hello
  job: exited 0

Choose how to use WorkerOS:
  workeros help run       Run commands from your terminal
  workeros help config    Check and run a workflow from JSON or YAML
  workeros help file      Use the Python API or pass an open file

Host setup and recovery:
  workeros roles guide          Draft a role profile in your terminal
  workeros help formats         Use JSON or YAML role profiles
  workeros managed reconcile    Check an interrupted setup

Use wos as a short form. Run workeros help install for packages and platforms,
workeros help roles for the administrator handoff, or workeros help managed for
host setup. The controller requires Linux or Ubuntu WSL2 and Python 3.11+.
Install and upgrade: https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md
Upgrade and rollback: https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md#upgrade-and-roll-back
Recovery: https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/support.md#troubleshooting''',
 'install': '''Install a verified local wheel

  python3 -m venv .venv
  .venv/bin/python -m pip install --no-index --no-deps ./workeros-0.8.0-py3-none-any.whl
  .venv/bin/workeros run -- /usr/bin/printf 'hello\\n'

Run from the directory containing the independently verified wheel. Expected:
hello, then job: exited 0. Python 3.11+ on Linux or Ubuntu WSL2 is supported;
native Windows and macOS are not supported by the controller. For pip, uv,
npm, Go, Cargo, Conan and Maven, start with the project install guide and
choose the instructions for your version:
Stable v0.7.0 guide: https://github.com/thisistuhinsen/workerOS/blob/v0.7.0/docs/install.md
v0.8.0 instructions (use its release assets after publication): https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md
Upgrade and rollback: https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/install-0.8.0.md#upgrade-and-roll-back
For a failed or uncertain job, see https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/support.md#troubleshooting''',
 'run': '''Run a local command

  workeros run -- /usr/bin/printf 'hello\\n'
  workeros run --json -- /usr/bin/printf 'hello\\n'
  workeros run --json --cwd DIR --stdout FILE --stderr FILE --report FILE -- COMMAND

Expected: hello, then job: exited 0. Add --json before -- for one JSON result.
The child receives stdin, including piped input. JSON mode discards the child's
stdout and stderr by default. Capture either stream to a new file in a directory
you own that other users cannot write. Relative paths use your current
directory, including with --cwd. Capture never replaces a file. This starts one
trusted local command.
The versioned result includes an attempt ID and separates lifecycle and cleanup.
Use --report to save a caller-owned copy. Local runs have no status lookup.
If exporting fails, keep stdout and save that receipt without running again.
For the timeout and cleanup example, run workeros demo. A timeout or an unknown
effect is not proof that nothing happened; check effects before retrying.''',
 'file': '''Use WorkerOS from code

Give a worker an open file:
  {command}

Expected: Python: PASSED. The launcher opens a disposable file and runs one
worker; it checks the worker's exit and shared offset. Worker-side readers are
also supplied for Node.js, C, C++, Go, Rust and Java, where their toolchains
are available. They do not supply the Python controller's full API. Run
workeros help install for their packages, or workeros help config to call
the controller from another language.

Check the Python API import in this installation:
  {import_command}

Expected: WorkerRoster.

Python API examples:
https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/api.md#launch-and-supervise-workers''',
 'roles': '''Manage custom role declarations and named-UID ACL plans

  workeros roles guide
  workeros roles draft --help
  workeros roles preview < profile.json
  workeros roles preview --format yaml < profile.yaml
  workeros roles apply < profile.json
  workeros roles status PROFILE REVISION
  workeros roles revoke PROFILE REVISION
  workeros roles grant-preview < grant.json
  workeros roles grant-apply < grant.json
  workeros roles recover < grant.json
  workeros roles grant-check < grant.json       Same read-only recovery
  workeros roles grant-revoke < grant.json

The optional guide needs a terminal and writes no file or grant. Give its JSON
draft to an administrator to preview or apply from their trusted installation.
Preview starts nothing and writes nothing. Apply records a declaration.
OS access is granted separately. Revocation here affects the declaration.
Grant operations need an approved role, exact file identity and administrator
authority. The named-UID ACL backend grants one existing UID access to one exact
file for future opens only; see
https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/host-preflight.md#grant-read-access-to-one-linux-file.
If a result is unknown, use recover on the exact plan; do not repeat the grant.
Role labels and ACL readback do not qualify an independent observer.
See docs/host-preflight.md for the schema, limits and next steps.''',
 'managed': '''Managed setup and recovery

  workeros managed apply-profile --preview < profile.json
  workeros managed apply-profile < profile.json
  workeros managed profile-status PROFILE REVISION
  workeros managed revoke-profile PROFILE REVISION

Apply-profile validates, stores and reads back an approved local profile.
Include the host's pinned appointments in the profile to register them together.
Use --format yaml with optional PyYAML for YAML input. Preview writes no record.
The commission-apply and commission-status aliases remain available.

Include one approved `grant` for `named_uid_read_acl`, or a `grants` list
with --registered-file-acl for separately registered operations on distinct
Linux files. An exact repeat reads the stored grants. Use profile-status
after a lost reply and revoke-profile to remove the revision's exact ACLs.
Revocation affects future opens. Schedule it explicitly before expiry.
Provider attachment and independent evidence require separate checks.
See https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/host-preflight.md#apply-a-profile-and-verify-a-file-grant.

  workeros managed commission PROFILE REVISION --declaration-sha256 SHA --intent-sha256 SHA

Commission records administrator intent for an active local role declaration.
Status checks that receipt and the declaration. Configured reports the local
record, with readiness not checked and independence unverified.

  workeros managed appointment-register < appointments.json
  workeros managed appointment-status PROFILE REVISION

Appointment-register records approved role bindings for managed setup.
Appointment-status reads the registration. The host verifies live bindings
and independent evidence separately.

  workeros managed preview
  workeros managed check-bindings
  workeros managed setup
  workeros managed readback
  workeros managed reconcile
  workeros managed serve-setup --listen-fd FD
  workeros managed serve-setup --recover-interrupted
  workeros managed serve-provider --config-fd FD --listen-fd FD
  workeros managed run-approved --request-id ID
  workeros managed launch-status --request-id ID
  workeros managed run-approved --workflow NAME --request-id ID
  workeros managed launch-status --workflow NAME --request-id ID
  workeros managed launch-status --workflow NAME --request-id ID --report FILE
  workeros managed serve-launch --listen-fd FD
  workeros managed serve-launch --commissioned WORKFLOW
  workeros managed serve-guard --commissioned
  workeros managed serve-holder --commissioned WORKFLOW
  workeros managed serve-witness --commissioned WORKFLOW

Preview reads configuration without connecting. Check-bindings asks the
commissioned host to verify exact bindings before any setup record or start.
Commissioned activation serves an existing approved workflow. The host
manager must supply the registered roles and retain their original resources.
Use --report FILE to save a caller-owned copy without overwriting an existing
file. If export fails, use launch-status and the same request ID.
For multi-check setup, add --max-requests 16 to the provider command. The
provider serves fresh checks for an approved point observer or cgroup meter.
Setup requires an authenticated host and approved bindings. If its reply is lost,
use readback or reconcile for the same operation. If providers have retired,
an administrator can use --recover-interrupted to read durable scope commits
with the original trusted setup configuration. This does not replay setup or
check readiness. See docs/host-preflight.md.''',
 'formats': '''Profile input formats

Role profiles use JSON by default. Add --format yaml to roles preview, roles
apply, the grant commands, or managed apply-profile to use YAML. For a
workflow policy, add --format yaml to workeros config with --check-policy
or --run-policy. Install PyYAML in the same environment or submit JSON if
yaml_dependency_missing.
Both formats use the same validation. YAML duplicate keys, aliases, anchors and
multiple documents are refused. Quote ambiguous YAML identifiers. Command
results and workflow invocations use JSON.''',
 'config': '''Workflow configuration

Check the installed example policy from your project directory:
  workeros config --check-policy {policy} \\
    --executable sample /usr/bin/printf --store archive "$PWD/archive"

Expected: JSON with status "checked" and workflow "fileless". This checks
the policy and supplied bindings without creating the archive or starting work.

  workeros config --schema
  workeros config --help

The schema command prints JSON without starting a job. To run a workflow,
use --run-policy and supply the invocation as JSON on stdin. Policy files
default to JSON. Use --format yaml with optional PyYAML for a YAML policy.
The policy SHA-256 covers the original file bytes in either format.
Other languages can call this command and exchange the same JSON.

First runnable policies:
JSON: https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/start/config.md#run-from-json-v080
YAML: https://github.com/thisistuhinsen/workerOS/blob/v0.8.0/docs/start/config.md#run-from-yaml

Host bindings and authority come from the operator. Check the result for
delivery, cleanup and evidence. Reconcile an unknown effect before retrying.''',
}
_ROLE_HELP={
 'guide': 'Create a role draft interactively: workeros roles guide\nRequires a terminal. Use back or cancel; JSON is printed without writing a file or granting access.',
 'draft': 'Create a no-write draft: workeros roles draft --help\nChoose an existing principal, scope and expiry. The output is JSON; no authority is granted.',
 'preview': (
     "Preview a role declaration from the administrator's trusted installation.\n"
     '  workeros roles preview < profile.json\n'
     '  workeros roles preview --format yaml < profile.yaml\n'
     'Requires an administrator. Preview starts nothing and writes nothing. YAML needs PyYAML.'
 ),
 'apply': 'Record a declaration: workeros roles apply [--format json|yaml] < profile.json\nRequires an administrator. It creates no principal, OS grant or observer authority.',
 'status': 'Read a declaration: workeros roles status PROFILE REVISION\nShows configured, expired or revoked declaration state; it does not verify a grant.',
 'show': 'Read a declaration: workeros roles status PROFILE REVISION\nShows configured, expired or revoked declaration state; it does not verify a grant.',
 'revoke': 'Revoke a declaration: workeros roles revoke PROFILE REVISION\nRequires an administrator. Actual host grants need separate revocation.',
 'grant-preview': 'Preview the approved ACL plan: workeros roles grant-preview [--format json|yaml] < grant.json\nNo grant is applied. See docs/host-preflight.md for prerequisites.',
 'grant-apply': 'Apply an approved ACL plan: workeros roles grant-apply [--format json|yaml] < grant.json\nAn administrator grants one existing UID access to one exact file for future opens. Never retry an unknown effect. See docs/host-preflight.md#grant-read-access-to-one-linux-file.',
 'grant-check': 'Reconcile the same ACL plan: workeros roles grant-check [--format json|yaml] < grant.json\nReads recorded state and ACL; it does not repeat the grant.',
 'recover': 'Reconcile the same ACL plan: workeros roles recover [--format json|yaml] < grant.json\nReads recorded state and ACL; it does not repeat the grant.',
 'grant-revoke': 'Remove the recorded ACL entry: workeros roles grant-revoke [--format json|yaml] < grant.json\nRequires the exact approved plan. Existing open descriptors are unaffected.',
}


class InputError(ValueError):
    pass


def _yaml_to_json(data):
    try:
        import yaml
    except ImportError:
        raise InputError('yaml_dependency_missing') from None
    try:
        text=data.decode('utf-8')
        depth=0
        count=0
        json_number=re.compile(r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z')
        for event in yaml.parse(text,Loader=yaml.SafeLoader):
            if getattr(event,'tag',None) is not None:
                raise ValueError('explicit YAML tags unsupported')
            if isinstance(event,yaml.events.AliasEvent) or getattr(event,'anchor',None) is not None:
                raise ValueError('anchors and aliases unsupported')
            if isinstance(event,yaml.events.ScalarEvent) and event.style is None:
                # PyYAML follows YAML 1.1 implicit typing (for example, `on`,
                # `01`, and dates). Refuse those ambiguous spellings instead
                # of silently changing a JSON value's type.
                resolved=yaml.SafeLoader('').resolve(yaml.nodes.ScalarNode,event.value,event.implicit)
                if resolved in ('tag:yaml.org,2002:bool','tag:yaml.org,2002:null'):
                    allowed=('true','false') if resolved.endswith(':bool') else ('null',)
                    if event.value not in allowed: raise ValueError('ambiguous YAML scalar')
                elif resolved=='tag:yaml.org,2002:int' and not re.fullmatch(r'-?(?:0|[1-9][0-9]*)',event.value):
                    raise ValueError('non-JSON integer spelling')
                elif resolved=='tag:yaml.org,2002:timestamp':
                    raise ValueError('implicit timestamps unsupported')
                elif resolved=='tag:yaml.org,2002:float' and not json_number.fullmatch(event.value):
                    raise ValueError('non-JSON number spelling')
            if isinstance(event,(yaml.events.MappingStartEvent,yaml.events.SequenceStartEvent)):
                depth+=1
                if depth>64: raise ValueError('document too deep')
            if isinstance(event,(yaml.events.MappingEndEvent,yaml.events.SequenceEndEvent)): depth-=1
            if isinstance(event,(yaml.events.MappingStartEvent,yaml.events.SequenceStartEvent,yaml.events.ScalarEvent)):
                count+=1
                if count>4096: raise ValueError('document too complex')
        class StrictLoader(yaml.SafeLoader):
            # Restrict implicit scalar typing to the JSON data model while
            # retaining the JSON primitive spellings and plain string keys.
            yaml_implicit_resolvers={key:list(value) for key,value in yaml.SafeLoader.yaml_implicit_resolvers.items()}
            for _key,_resolvers in tuple(yaml_implicit_resolvers.items()):
                yaml_implicit_resolvers[_key]=[(tag,regexp) for tag,regexp in _resolvers
                    if tag not in ('tag:yaml.org,2002:bool','tag:yaml.org,2002:int',
                                   'tag:yaml.org,2002:float','tag:yaml.org,2002:null',
                                   'tag:yaml.org,2002:timestamp')]
            yaml_implicit_resolvers[None]=[
                ('tag:yaml.org,2002:bool',re.compile(r'^(?:true|false)$')),
                ('tag:yaml.org,2002:null',re.compile(r'^null$')),
                ('tag:yaml.org,2002:float',re.compile(r'^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+|[eE][+-]?[0-9]+)(?:[eE][+-]?[0-9]+)?$')),
                ('tag:yaml.org,2002:int',re.compile(r'^-?(?:0|[1-9][0-9]*)$')),
            ]
            def construct_mapping(self,node,deep=False):
                if not isinstance(node,yaml.nodes.MappingNode): raise ValueError('expected mapping')
                result={}
                for key_node,value_node in node.value:
                    key=self.construct_object(key_node,deep=deep)
                    if type(key) is not str or key=='<<' or key in result:
                        raise ValueError('invalid or duplicate mapping key')
                    result[key]=self.construct_object(value_node,deep=deep)
                return result
        document=yaml.load(text,Loader=StrictLoader)
        def validate(value,depth=0):
            if depth>64: raise ValueError('document too deep')
            if value is None or type(value) in (str,bool,int): return
            if type(value) is float:
                if not math.isfinite(value): raise ValueError('non-finite number')
                return
            if type(value) is list:
                for item in value: validate(item,depth+1)
                return
            if type(value) is dict:
                for key,item in value.items():
                    if type(key) is not str: raise ValueError('invalid key')
                    validate(item,depth+1)
                return
            raise ValueError('non-JSON YAML value')
        validate(document)
        encoded=json.dumps(document,ensure_ascii=True,separators=(',',':'),allow_nan=False).encode()
        if len(encoded)>_LIMIT: raise ValueError('document too large')
        return encoded
    except (yaml.YAMLError,ValueError,TypeError,UnicodeError,RecursionError,OverflowError):
        raise InputError('invalid_yaml') from None


def _refuse(code, *, versioned=False):
    advice=('Install the optional PyYAML package in this environment, or use JSON.' if code=='yaml_dependency_missing'
            else 'Run workeros roles guide in a terminal, or use the noninteractive draft command.' if code=='tty_required'
            else 'Use workeros run -- COMMAND ARG ... for text output; no command was started.' if code=='run_json_unsupported'
            else 'Run workeros --help to find a command or help topic.' if code in ('unknown_command','unknown_help_topic')
            else 'Correct the command or input; no operation was attempted.')
    result = {'status':'refused','effect':'not_attempted','code':code,'next_action':advice}
    if versioned:
        from .result_export import RESULT_VERSION
        result['version'] = RESULT_VERSION
    print(json.dumps(result,separators=(',',':')))
    return 1


def _draft(args):
    from . import roles_cli
    class DraftParser(argparse.ArgumentParser):
        def error(self,message): raise InputError('invalid_draft')
    parser=DraftParser(prog='workeros roles draft',description='Make a JSON role draft; no grant or write.')
    for field in ('profile','revision','role','principal','scope','expires-at'):
        parser.add_argument('--'+field,required=True)
    parser.add_argument('--operation',action='append',help='existing WorkerOS operation; default read')
    parser.add_argument('--independent-of',help='existing different principal; not proof of independence')
    try:
        args=parser.parse_args(args)
        role={'name':args.role,'principal':args.principal,'operations':args.operation or ['read'],
              'scopes':[args.scope],'expires_at':int(args.expires_at)}
        if args.independent_of is not None: role['independent_of']=args.independent_of
        document={'version':1,'profile':args.profile,'revision':args.revision,'roles':[role]}
        encoded=json.dumps(document,separators=(',',':')).encode()
        roles_cli._validate(encoded)
    except (ValueError,TypeError,OverflowError):
        return _refuse('invalid_draft')
    print(encoded.decode()); return 0


def _guide(args):
    """Collect one draft on a TTY; JSON stdout and instructions on stderr."""
    from . import roles_cli
    if args: return _refuse('invalid_guide')
    if not sys.stdin.isatty() or not sys.stdout.isatty(): return _refuse('tty_required')
    def expiry_seconds(raw):
        value=raw.strip()
        if re.fullmatch(r'[0-9]+',value):
            result=int(value)
        else:
            relative=re.fullmatch(r'\+?([1-9][0-9]*)([hdw])',value,re.IGNORECASE)
            if relative:
                amount=int(relative.group(1)); scale={'h':3600,'d':86400,'w':604800}[relative.group(2).lower()]
                result=int(time.time())+amount*scale
            elif re.fullmatch(r'\d{4}-\d{2}-\d{2}',value):
                # A date means the end of that UTC day, not local machine time.
                next_day=date.fromisoformat(value)+timedelta(days=1)
                result=int(datetime.combine(next_day,datetime_time.min,timezone.utc).timestamp())
            else:
                try: parsed=datetime.fromisoformat(value[:-1]+'+00:00' if value.endswith(('Z','z')) else value)
                except ValueError: raise ValueError('Enter a Unix timestamp, +30d, YYYY-MM-DD, or a timezone-qualified ISO date and time.') from None
                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    raise ValueError('Add Z or a UTC offset, such as 2027-04-30T17:00:00Z.')
                result=int(parsed.timestamp())
        if result <= int(time.time()) or result >= 2**53:
            raise ValueError('Expiry must be in the future and below 2^53 Unix seconds.')
        return result

    base_fields=(('profile','Profile name'),('revision','Revision'))
    role_fields=(('name','Role name'),('principal','Existing OS principal'),
                 ('scopes','Scopes, comma-separated'),
                 ('expires_at','Expiry (Unix seconds, +30d, YYYY-MM-DD, or ISO time with Z/offset)'),
                 ('operations','Operations, comma-separated [read]'),
                 ('independent_of','Different existing principal to declare independence from [none]'))
    values={}; index=0; role_count=1
    fields=list(base_fields)+[(f'role0_{key}',label) for key,label in role_fields]
    sys.stderr.write('Role draft only. You can define several roles. Type back to change the previous field or cancel to stop.\n')
    try:
        while index < len(fields):
            key,label=fields[index]
            role_field=key.startswith('role')
            leaf=key.split('_',1)[1] if role_field else key
            if leaf=='expires_at':
                label='Expiry (Unix timestamp, +30d, YYYY-MM-DD through end of UTC day, or ISO time with Z/offset)'
            sys.stderr.write(label+': '); sys.stderr.flush()
            raw=sys.stdin.readline(4097)
            if not raw or raw.strip().lower()=='cancel':
                print(json.dumps({'status':'cancelled','effect':'not_attempted'},separators=(',',':')))
                return 1
            if len(raw)>4096: return _refuse('input_too_large')
            value=raw.strip()
            if value.lower()=='back':
                if index: index-=1
                else: sys.stderr.write('Already at the first field; enter a value or cancel.\n')
                continue
            if not value and leaf not in ('operations','independent_of'):
                sys.stderr.write('This field is required. Enter a value, back, or cancel.\n'); continue
            try:
                if leaf in ('profile','revision','name','scope'):
                    roles_cli._name(value)
                elif leaf=='principal':
                    roles_cli._principal(value)
                elif leaf=='scopes':
                    items=[item.strip() for item in value.split(',')]
                    if not items or any(not item for item in items): raise roles_cli.Refusal('invalid_scopes')
                    for item in items: roles_cli._name(item)
                    if len(set(items))!=len(items): raise roles_cli.Refusal('duplicate_scopes')
                    value=items
                elif leaf=='operations':
                    items=[item.strip() for item in value.split(',')] if value else ['read']
                    if not items or any(not item for item in items): raise roles_cli.Refusal('invalid_operations')
                    for item in items: roles_cli._name(item)
                    if len(set(items))!=len(items): raise roles_cli.Refusal('duplicate_operations')
                    if not set(items)<=roles_cli._OPTIONS.keys(): raise roles_cli.Refusal('unsupported_operation')
                    value=items
                elif leaf=='expires_at':
                    value=expiry_seconds(value)
                elif leaf=='independent_of' and value:
                    roles_cli._principal(value)
                if leaf=='independent_of' and value and values.get(key[:key.index('_')+1]+'principal')==value:
                    raise roles_cli.Refusal('independence_mismatch')
            except (ValueError,TypeError,OverflowError) as exc:
                reason=str(exc) if not isinstance(exc,roles_cli.Refusal) else str(exc)
                if reason=='expected a bounded evidence identifier': reason='invalid_name'
                messages={
                    'invalid_name':'Start with a letter or digit; then use letters, digits, dot, underscore or hyphen (up to 128 characters).',
                    'principal_missing':'That account does not exist. Choose an existing OS principal.',
                    'invalid_principal':'Enter an existing account name without spaces, slash or colon.',
                    'unsupported_operation':'One operation is not supported by this WorkerOS role schema. Use workeros roles draft --help to see current options.',
                    'independence_mismatch':'Choose a different existing account; this declaration does not prove independent authority.',
                    'duplicate_scopes':'Each scope must be listed once.',
                    'duplicate_operations':'Each operation must be listed once.',
                    'invalid_scopes':'Enter one or more comma-separated scope names.',
                    'invalid_operations':'Enter one or more comma-separated operation names.',
                }
                sys.stderr.write(messages.get(reason,reason)+' Nothing was written or granted. Correct this field, type back, or cancel.\n')
                continue
            values[key]=value
            index+=1
            if index < len(fields): continue

            roles=[]
            for number in range(role_count):
                prefix=f'role{number}_'
                role={'name':values[prefix+'name'],'principal':values[prefix+'principal'],
                      'operations':values[prefix+'operations'],'scopes':values[prefix+'scopes'],
                      'expires_at':values[prefix+'expires_at']}
                if values[prefix+'independent_of']: role['independent_of']=values[prefix+'independent_of']
                roles.append(role)
            document={'version':1,'profile':values['profile'],'revision':values['revision'],'roles':roles}
            try:
                encoded=json.dumps(document,separators=(',',':')).encode()
                roles_cli._validate(encoded)
            except (ValueError,TypeError,OverflowError) as exc:
                code=str(exc)
                if code=='duplicate_role' and role_count>1:
                    target=next((number for number,role in enumerate(roles)
                                 if sum(other['name']==role['name'] for other in roles)>1),role_count-1)
                    index=next(i for i,(field,_) in enumerate(fields) if field==f'role{target}_name')
                    sys.stderr.write('Role names in one profile must be unique. Choose a different name; nothing was written.\n')
                    continue
                if code=='independence_mismatch':
                    target=next((number for number,role in enumerate(roles)
                                 if role.get('independent_of') and
                                 roles_cli._principal(role['principal']).pw_uid ==
                                 roles_cli._principal(role['independent_of']).pw_uid),role_count-1)
                    index=next(i for i,(field,_) in enumerate(fields) if field==f'role{target}_independent_of')
                    sys.stderr.write('The independent principal must be a different account. This field is a declaration only; it does not prove independent authority. Nothing was written.\n')
                    continue
                sys.stderr.write('The full draft is invalid ('+code+'). Correct the last field or type back to review it; nothing was written.\n')
                index=max(0,index-1)
                continue

            sys.stderr.write('Profile draft preview — no record, grant, or worker is created.\n')
            for role in roles:
                try: expiry=datetime.fromtimestamp(role['expires_at'],timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
                except (OverflowError,OSError,ValueError): expiry=f"Unix {role['expires_at']} seconds (outside calendar display range)"
                sys.stderr.write(f"  {role['name']} (account {role['principal']}): "
                                 f"{', '.join(role['operations'])} on {', '.join(role['scopes'])}; expires {expiry}\n")
                if role.get('independent_of'):
                    sys.stderr.write(f"    Declares independence from {role['independent_of']}; not verified by this draft.\n")
            while True:
                sys.stderr.write('Add another role? [y/N]: '); sys.stderr.flush()
                answer=sys.stdin.readline(4097)
                if len(answer)>4096: return _refuse('input_too_large')
                if not answer or answer.strip().lower()=='cancel':
                    print(json.dumps({'status':'cancelled','effect':'not_attempted'},separators=(',',':')))
                    return 1
                choice=answer.strip().lower()
                if choice=='back':
                    index=max(0,index-1)
                    break
                if choice in ('y','yes'):
                    if role_count>=64:
                        sys.stderr.write('A profile can contain at most 64 roles. The draft is not emitted.\n')
                        return _refuse('invalid_roles')
                    prefix=f'role{role_count}_'
                    fields.extend((prefix+key,label) for key,label in role_fields)
                    role_count+=1
                    break
                if choice in ('','n','no'):
                    text=encoded.decode(); print(text)
                    sys.stderr.write('No files or access changed. Give this draft to the administrator.\n'
                        'In their own shell, the administrator must set ADMIN_WORKEROS to the absolute path\n'
                        'of their independently installed, trusted WorkerOS executable, then preview:\n  '
                        "printf '%s\\n' "+shlex.quote(text)+' | "$ADMIN_WORKEROS" roles preview\n')
                    return 0
                sys.stderr.write('Answer y or n, back, or cancel. Nothing has been written or granted.\n')
            continue
    except KeyboardInterrupt:
        print(json.dumps({'status':'cancelled','effect':'not_attempted'},separators=(',',':')))
        return 130


def _roles(args):
    from . import roles_cli
    if not args: return roles_cli.main(['--help'])
    action=args[0]
    if action=='guide': return _guide(args[1:])
    if action=='draft': return _draft(args[1:])
    if action=='status': action='show'
    elif action=='recover': action='grant-check'
    rest=args[1:]
    mode='json'
    if '--format' in rest:
        if rest.count('--format')!=1: return _refuse('invalid_format')
        index=rest.index('--format')
        if index+1>=len(rest) or rest[index+1] not in ('json','yaml'): return _refuse('invalid_format')
        mode=rest[index+1]; rest=rest[:index]+rest[index+2:]
        if action not in _INPUT_ROLES: return _refuse('format_not_supported')
    if mode=='json': return roles_cli.main([action,*rest])
    data=sys.stdin.buffer.read(_LIMIT+1)
    if len(data)>_LIMIT: return _refuse('document_too_large')
    try: encoded=_yaml_to_json(data)
    except InputError as exc: return _refuse(str(exc))
    original=sys.stdin
    replacement=TextIOWrapper(BytesIO(encoded),encoding='utf-8')
    try:
        sys.stdin=replacement
        return roles_cli.main([action,*rest])
    finally:
        sys.stdin=original
        replacement.close()


def _installed_version():
    try:
        return package_version('workeros')
    except PackageNotFoundError:
        return 'development'


def _render_help(topic):
    help_text = _HELP[topic]
    if topic == 'start':
        return help_text.replace('{version}', _installed_version())
    if topic == 'file':
        example = Path(sys.prefix) / 'share/workeros/examples/run_inherited_fd.py'
        command = shlex.join([sys.executable, '-I', str(example), '--language', 'python'])
        import_command = shlex.join([sys.executable, '-I', '-c',
                                     'from workeros import WorkerRoster; print(WorkerRoster.__name__)'])
        return help_text.format(command=command, import_command=import_command)
    if topic == 'config':
        policy = Path(sys.prefix) / 'share/workeros/examples/workflow_policy.json'
        return help_text.format(policy=shlex.quote(str(policy)))
    return help_text


def main(argv=None):
    argv=list(sys.argv[1:] if argv is None else argv)
    if argv==['--version'] or argv==['-V']:
        print(f'WorkerOS {_installed_version()}')
        return 0
    if not argv or argv[0] in ('-h','--help'):
        print(_render_help('start'))
        return 0
    if argv[0]=='help':
        topic=argv[1] if len(argv)==2 else 'start' if len(argv)==1 else None
        if topic not in _HELP: return _refuse('unknown_help_topic')
        print(_render_help(topic))
        return 0
    command,remaining=argv[0],argv[1:]
    if command=='roles' and remaining and remaining[0]=='draft' and ('--help' in remaining or '-h' in remaining):
        return _draft(['--help'])
    if command=='managed' and remaining and remaining[0] in ('commission', 'commission-status', 'commission-apply',
                                                            'apply-profile', 'profile-status', 'revoke-profile', 'serve-setup',
                                                            'serve-provider', 'appointment-register', 'appointment-status',
                                                            'run-approved', 'launch-status', 'serve-launch', 'serve-guard',
                                                            'serve-holder', 'serve-witness'):
        from . import managed_cli
        return managed_cli.main(remaining)
    if command in ('roles','managed') and (not remaining or '--help' in remaining or '-h' in remaining):
        if command=='roles' and remaining and remaining[0] in _ROLE_HELP:
            print(_ROLE_HELP[remaining[0]])
        else: print(_render_help(command))
        return 0
    if command=='run' and remaining in (['--help'],['-h']):
        print(_render_help('run')); return 0
    if command in ('demo','run'):
        from . import quickstart
        if command=='demo': return quickstart.main(remaining)
        if remaining and remaining[0]=='--json':
            return quickstart.run_json_main(remaining[1:])
        if remaining and remaining[0] in ('--format=json','--format','--output=json'):
            return _refuse('run_json_unsupported')
        if remaining and remaining[0]=='--': remaining=remaining[1:]
        if not remaining: return _refuse('command_required')
        return quickstart.main(['--',*remaining])
    if command=='roles': return _roles(remaining)
    if command=='managed':
        from . import managed_cli
        return managed_cli.main(remaining)
    if command=='config':
        from . import configuration_cli
        return configuration_cli.main(remaining)
    if command=='owner-access':
        from . import owner_access
        return owner_access.main(remaining)
    return _refuse('unknown_command')


if __name__=='__main__': sys.exit(main())
