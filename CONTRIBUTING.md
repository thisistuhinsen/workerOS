# Contributing to workerOS

Start with a small example that shows what breaks or becomes easier. Tell us who owns the file descriptor, who can act on the worker, and which process observes the result. A report with one file and two processes is usually enough.

- Open an issue for a public bug, compatibility gap, or feature idea. Include the workerOS version or commit, OS and kernel, architecture, language/runtime version, exact command, and observed output. Use disposable files and processes you control. Follow [SECURITY.md](SECURITY.md) for vulnerability reports.
- Open a focused pull request with the user-facing change and its test evidence. Keep unrelated formatting and dependency changes out of the diff. Describe compatibility effects on the Python API, inherited FD ABI, connected Unix stream framing, or release assets.
- Document who owns a descriptor at each step. Describe effect, delivery, worker exit, cleanup, and custody separately where they matter. Use “verified” for evidence the test actually collected.
- Contributions are submitted under the [MIT license](LICENSE). Only submit material you can contribute under that license.

## Local checks

```sh
bash scripts/check-linux.sh
```

That command builds a wheel and installs it offline into a fresh environment for the Python suite and examples. Its default example discovery reports unavailable toolchains. To check all seven examples without silently accepting an unavailable language, use the release verifier. Choose tests that exercise the normal package entry point and the failure you are fixing. A descriptor change needs at least one real inherited or connected-socket test alongside narrow parser tests. Add a privacy-safe log excerpt or a public CI link to the pull request.

The [support matrix](docs/support.md) lists the hosted jobs and their scopes. Run the appropriate package-manager consumer checks in the [individual adapter directories](README.md#packages) when changing an adapter. Keep a narrow public API across languages. New dependencies need a concrete benefit for workers or maintainers.

## Review and releases

A maintainer checks behavior, supported install paths, files in each asset, and attached test evidence before a release. Get a second review for a change that affects descriptor ownership, authorization, cleanup, custody, wire compatibility, release credentials, or artifact contents. Reviews should leave a record of what was run, what passed, and any platform left unverified.

The GitHub release workflow can validate a candidate in read-only mode. A release is a separate maintainer decision tied to an exact default-branch commit. See [Release process](docs/releasing.md) for the version marker, required checks, and recovery from an interrupted draft. Publish a fresh version for changed release bytes. Maintainers may close requests without a reproducible case or outside the supported scope and reopen them when new evidence is available.
