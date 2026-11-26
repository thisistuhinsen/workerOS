# Releasing workerOS

The release workflow builds packages with a read-only token. A separate job gets permission to create a tag and a GitHub Release after the packaged-consumer checks and the Linux, hosted WSL2, and strict-custody workflows have passed for the exact release commit.

## Validate a candidate

1. Update the package versions together in the implementation PR against protected `main`. Keep the release marker for the later authorization PR. Record the candidate's full commit SHA for independent source and package review.
2. From that exact checkout, run `bash scripts/build-release.sh` into an empty directory, then `bash scripts/check-git-consumers.sh` with the resulting wheel. The first script compares two builds and checks the packaged consumers, including a fresh uv project lock and sync. The second resolves the Go and Cargo packages from a disposable local tag at the checked-out SHA. Exact byte comparison assumes the same toolchains and `SOURCE_DATE_EPOCH`. The Linux compatibility workflow exercises release authorization, external readback and interruption cases with local fixtures. These checks create no public tag or release.
3. After the approved implementation PR lands, the optional hosted staging run uses [GitHub release](https://github.com/thisistuhinsen/workerOS/actions/workflows/release.yml) on the canonical default `main` with its exact current SHA, committed version without `v`, and `publish` unchecked. The workflow stores the candidate assets and checksums in GitHub Actions. Review the artifacts and public instructions against the version being released. Treat green checks as technical evidence for the maintainer review.

Each release includes the Python wheel and sdist, npm tarball, Maven JAR and POM, Conan recipe archive, and `SHA256SUMS`. Go and Cargo consume the same reviewed source tag. The [Git consumer check](https://github.com/thisistuhinsen/workerOS/blob/v0.5.0/scripts/check-git-consumers.sh) verifies a disposable tag at the exact candidate commit and launches both external consumers with the built wheel. The GitHub release job publishes the exact tested artifact from its build job.

## Authorize a public release

Wait for explicit release authorization before merging a marker PR or starting a publishing run. Implementation approval and staging results are inputs to that separate decision. Prepare a marker-only PR against the approved `main` that changes only `.github/release-version` to the chosen version with one trailing newline. A reviewed squash merge produces the single-parent marker commit and automatically triggers the publish workflow. The prior `main` tip must be that commit's parent. The marker commit is the release SHA. Keep it at the default-branch tip through publication. A manual publishing run requires the same exact marked tip, version, and release authorization.

GitHub must report the canonical default `main` as protected for a publishing run. The marker and all required jobs must agree on the version and current SHA. The tag and release must be unused. A publication request that misses a prerequisite fails before reserving a tag.

The publish job checks the artifact, reserves the tag at the exact commit, and uploads assets to a draft. It downloads every asset and compares it byte for byte before publishing that draft. The job stops when its read-only preflight finds an existing tag or release. A separate job with an empty repository permission set checks the public result only after the writer reports success.

## Inspect an interrupted publication

Preserve the attempted run and attempt number, exact marker SHA, version, and the `workerOS-release-<marker SHA>` artifact from the build job of that publishing run. Use an account already authorized to see drafts. From the checkout, set `version` and `revision` to the attempted values and inspect the result with GET requests.

```bash
set -euo pipefail
repo=thisistuhinsen/workerOS
tag="v$version"
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
gh api "repos/$repo/git/matching-refs/tags/$tag" > "$work/refs.json"
gh api --paginate "repos/$repo/releases?per_page=100" |
  jq -esc --arg tag "$tag" '
    if length > 0 and all(.[]; type == "array" and all(.[]; type == "object" and (.tag_name | type == "string")))
    then [.[][] | select(.tag_name == $tag)] else error("Invalid release listing") end' > "$work/releases.json"
python -I scripts/classify-release-effect.py \
  "$version" "$revision" "$work/refs.json" "$work/releases.json"
```

| Evidence | Disposition |
| --- | --- |
| Exact tag and release absent in a complete snapshot | Record the result. A snapshot after an uncertain write provides no replay authorization. |
| Exact tag only | Retain the tag and compare its commit with the marker. Record the run evidence for an approval-scoped recovery. |
| Draft with an exact tag and a matching workflow marker | Compare the run and attempt, release ID, asset list and actual bytes against the original verified artifact before any recovery review. The workflow marker is a clue about ownership. |
| Unrecognized draft, divergent tag, conflicting records, or incomplete read | Stop for maintainer inspection. Preserve the existing tag and assets. |
| Public release exists | Verify the exact public tag and original asset bytes with the read-only consumer path below. |

A failed publish step or a failed consumer check reports its outcome. Live recovery requires separate maintainer authorization. Automatic recovery leaves tags, drafts, assets and access settings untouched.

## Verify the public release

The post-publication job uses the original build artifact as the expected bytes, compares the anonymous public tag and release with the authorized marker SHA, and checks both asset metadata and downloaded content. It then exercises the package-manager paths from clean consumers without repository credentials:

- Install the wheel with pip and uv. Use a fresh uv project with `uv add <wheel-url>`, then `uv lock --check` and `uv sync --locked`.
- Install the tarball with npm. Install the JAR and POM into a clean local Maven repository and build the Java reader. Import the Conan archive and build and run both native readers.
- Resolve the Go module and Cargo Git dependency from the public tag. Verify the Go module with its normal checksum settings and check the exact commit in Cargo's lockfile. A successful local-mirror check covers the committed code and tag layout. Public proxy and checksum availability are measured here.

Launch the installed readers through the inherited descriptor contract and check an actual positional read. GitHub is the distribution host for these paths. Central package registry publication is a separate operation.

To repeat only the read-only verification, use the exact released checkout and the `workerOS-release-<marker SHA>` build artifact from the original publishing run. An optional staging run has its own artifact. The public output directory must be empty. Use a clean environment without a netrc file or repository credentials, and supply the same release toolchains used for staging.

```bash
revision=$(git rev-parse HEAD)
version=$(python -I scripts/verify-release.py version)
python -I scripts/check-public-release.py "$version" "$revision" /path/to/staged /path/to/public-readback
bash scripts/build-release.sh --verify-public /path/to/public-readback
bash scripts/check-git-consumers.sh --public "/path/to/public-readback/worker_handoff-$version-py3-none-any.whl"
```

If public proxy or checksum data is unavailable, record the failure from the normal Go path and which later checks the run did not reach. An exact local-mirror result gives no public availability verdict. Repeat the public checks as read-only work once the dependency is reachable.
