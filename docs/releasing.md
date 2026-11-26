# Releasing workerOS

The release workflow builds packages with a read-only token. A separate job gets permission to create a tag and a GitHub Release after the packaged-consumer checks and the Linux, hosted WSL2, and strict-custody workflows have passed for the exact release commit.

## Validate a candidate

1. Update the package versions together and review the public source. Copy the candidate's full commit SHA.
2. On the canonical repository's default `main`, run [GitHub release](https://github.com/thisistuhinsen/workerOS/blob/main/.github/workflows/release.yml) with that SHA, the committed version without `v`, and `publish` unchecked. The workflow records the asset checksums and stores the candidate as a GitHub Actions artifact.
3. Review the exact artifact, install its packages in fresh consumers, and review the workflow and public documentation again. For a local pass with the same build tools, run `bash scripts/build-release.sh` into an empty directory. The script compares two clean builds and checks packaged entry points. An exact byte comparison assumes the same toolchain versions and `SOURCE_DATE_EPOCH`.

Each release includes the Python wheel and sdist, npm tarball, Maven JAR and POM, Conan recipe archive, and `SHA256SUMS`. Go and Cargo consume the same reviewed source tag. The [Git consumer check](https://github.com/thisistuhinsen/workerOS/blob/main/scripts/check-git-consumers.sh) verifies a disposable tag at the exact candidate commit and launches both external consumers with the built wheel. The GitHub release job publishes the exact tested artifact from its build job.

## Authorize a public release

After candidate review, the maintainer commits only `.github/release-version` with the chosen version and one trailing newline. Push that marker commit on its own. The exact marker commit is the release SHA. The workflow also accepts a manual run with `publish` checked when the exact marked tip and version are supplied.

GitHub must report the canonical default `main` as protected for a publishing run. The marker and all required jobs must agree on the version and current SHA. The tag and release must be unused. A publication request that misses a prerequisite fails before reserving a tag.

The publish job checks the artifact, reserves the tag at the exact commit, and uploads assets to a draft. It downloads every asset and compares it byte for byte before publishing that draft. Interruption may leave the reserved tag or an unpublished draft. Inspect the tag, draft and workflow run before choosing a recovery. The workflow refuses existing tags or releases and avoids rerunning uncertain mutations. A reviewed new version can take a new release through the same checks.
