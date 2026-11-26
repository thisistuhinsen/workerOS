# Releasing workerOS

The release workflow builds packages with a read-only token. A separate job gets permission to create a tag and a GitHub Release after the packaged-consumer checks and the Linux, hosted WSL2, and strict-custody workflows have passed for the exact release commit.

## Validate a candidate

1. Update the package versions together in the implementation PR. Keep the release marker for the later authorization PR. Record the candidate's full commit SHA for independent source and package review.
2. From that exact checkout, run `bash scripts/build-release.sh` into an empty directory, then `bash scripts/check-git-consumers.sh` with the resulting wheel. The first script compares two builds and checks packaged consumers. The second resolves the Go and Cargo packages from a disposable local tag at the checked-out SHA. Exact byte comparison assumes the same toolchains and `SOURCE_DATE_EPOCH`.
3. After the implementation PR lands, the optional hosted staging run uses [GitHub release](https://github.com/thisistuhinsen/workerOS/blob/main/.github/workflows/release.yml) on the canonical default `main` with its exact current SHA, committed version without `v`, and `publish` unchecked. The workflow stores the candidate assets and checksums in GitHub Actions. Review the artifacts and public instructions against the version being released.

Each release includes the Python wheel and sdist, npm tarball, Maven JAR and POM, Conan recipe archive, and `SHA256SUMS`. Go and Cargo consume the same reviewed source tag. The [Git consumer check](https://github.com/thisistuhinsen/workerOS/blob/main/scripts/check-git-consumers.sh) verifies a disposable tag at the exact candidate commit and launches both external consumers with the built wheel. The GitHub release job publishes the exact tested artifact from its build job.

## Authorize a public release

After candidate review, open a separate marker-only PR against the approved `main`. Change only `.github/release-version` to the chosen version with one trailing newline. A reviewed squash merge yields the single-parent marker commit that the push trigger expects. The prior `main` tip must be that commit's parent. The marker commit is the release SHA. Keep it at the default-branch tip through publication. A manual publishing run requires the same exact marked tip and version.

GitHub must report the canonical default `main` as protected for a publishing run. The marker and all required jobs must agree on the version and current SHA. The tag and release must be unused. A publication request that misses a prerequisite fails before reserving a tag.

The publish job checks the artifact, reserves the tag at the exact commit, and uploads assets to a draft. It downloads every asset and compares it byte for byte before publishing that draft. Interruption may leave the reserved tag or an unpublished draft. Inspect the tag, draft and workflow run before choosing a recovery. The workflow refuses existing tags or releases and avoids rerunning uncertain mutations. A reviewed new version can take a new release through the same checks.

## Verify the public release

From clean consumers without repository credentials, fetch the tagged release assets and check every entry in the published `SHA256SUMS`. Verify that the tag points to the marker commit. Exercise the same consumer paths against the public URLs and tag:

- Install the wheel with pip and uv. Use a fresh uv project with `uv add <wheel-url>`, then `uv lock --check` and `uv sync --locked`.
- Install the tarball with npm. Install the JAR and POM into a clean local Maven repository and build the Java reader. Import the Conan archive and build and run both native readers.
- Resolve the Go module and Cargo Git dependency from the public tag. Verify the Go module with its normal checksum settings and check the exact commit in Cargo's lockfile. A successful local-mirror check covers the committed code and tag layout. Public proxy and checksum availability are measured here.

Launch the installed readers through the inherited descriptor contract and check an actual positional read. GitHub is the distribution host for these paths. Central package registry publication is a separate operation.
