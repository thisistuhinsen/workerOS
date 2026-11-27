"""WorkerOS: run local jobs and connect approved managed profiles."""
import argparse
from io import BytesIO, TextIOWrapper
from importlib.metadata import PackageNotFoundError, version as package_version
import json
import math
from pathlib import Path
import re
import shlex
import sys

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

Expected: hello, then job: exited 0. Add --json before -- for one JSON result.
The child receives stdin, including piped input. Its stdout and stderr go to
stderr. The JSON result separates lifecycle and cleanup and leaves effects
unknown. This starts one trusted local command.
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

Apply-profile validates, stores and reads back an approved local profile.
Include the host's pinned appointments in the profile to register them together.
Use --format yaml with optional PyYAML for YAML input. Preview writes no record.
The commission-apply and commission-status aliases remain available.

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

Preview reads configuration without connecting. Check-bindings asks the
commissioned host to verify exact bindings before any setup record or start.
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


def _refuse(code):
    advice=('Install the optional PyYAML package in this environment, or use JSON.' if code=='yaml_dependency_missing'
            else 'Run workeros roles guide in a terminal, or use the noninteractive draft command.' if code=='tty_required'
            else 'Use workeros run -- COMMAND ARG ... for text output; no command was started.' if code=='run_json_unsupported'
            else 'Run workeros --help to find a command or help topic.' if code in ('unknown_command','unknown_help_topic')
            else 'Correct the command or input; no operation was attempted.')
    print(json.dumps({'status':'refused','effect':'not_attempted','code':code,'next_action':advice},separators=(',',':')))
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
    fields=(('profile','Profile name'),('revision','Revision'),('role','Role name'),
            ('principal','Existing OS principal'),('scope','Scope name'),('expires_at','Expiry (Unix seconds)'),
            ('operations','Operations, comma-separated [read]'),
            ('independent_of','Different existing principal to declare independence from [none]'))
    values={}; index=0
    sys.stderr.write('Role draft only. Type back to change a field or cancel to stop.\n')
    try:
        while True:
            key,label=fields[index]
            sys.stderr.write(label+': '); sys.stderr.flush()
            raw=sys.stdin.readline(4097)
            if not raw or raw.strip().lower()=='cancel':
                print(json.dumps({'status':'cancelled','effect':'not_attempted'},separators=(',',':')))
                return 1
            if len(raw)>4096: return _refuse('input_too_large')
            value=raw.strip()
            if value.lower()=='back':
                if index: index-=1
                else: sys.stderr.write('Already at the first field.\n')
                continue
            if not value and key not in ('operations','independent_of'):
                sys.stderr.write('Enter a value, back, or cancel.\n'); continue
            values[key]=value
            if index<len(fields)-1:
                index+=1; continue
            try:
                operations=[item.strip() for item in values['operations'].split(',')] if values['operations'] else ['read']
                role={'name':values['role'],'principal':values['principal'],'operations':operations,
                      'scopes':[values['scope']],'expires_at':int(values['expires_at'])}
                if values['independent_of']: role['independent_of']=values['independent_of']
                document={'version':1,'profile':values['profile'],'revision':values['revision'],'roles':[role]}
                encoded=json.dumps(document,separators=(',',':')).encode()
                roles_cli._validate(encoded)
            except (ValueError,TypeError,OverflowError):
                sys.stderr.write('Draft is invalid. Correct a field with back, or cancel.\n')
                continue
            text=encoded.decode(); print(text)
            sys.stderr.write('No files or access changed. Give this draft to the administrator.\n'
                'In their own shell, the administrator must set ADMIN_WORKEROS to the absolute path\n'
                'of their independently installed, trusted WorkerOS executable, then preview:\n  '
                "printf '%s\\n' "+shlex.quote(text)+' | "$ADMIN_WORKEROS" roles preview\n')
            return 0
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
                                                            'apply-profile', 'profile-status', 'serve-setup',
                                                            'serve-provider', 'appointment-register', 'appointment-status'):
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
            if len(remaining)<3 or remaining[1]!='--': return _refuse('json_command_required')
            return quickstart.run_json(remaining[2:])
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
