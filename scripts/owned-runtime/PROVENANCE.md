# WorkerOS Linux x86-64 bundled runtime

The [Bubblewrap 0.12.0 release source archive](https://github.com/containers/bubblewrap/releases/download/v0.12.0/bubblewrap-0.12.0.tar.xz) has SHA-256 `9760d007363e3abba7c747489910f9f82d9fca53ba3bd3282e396fa3c97a3314`. The bundle includes the original LGPL 2.1 text and the copyright and license notices from the exact Ubuntu libcap package used for static linking.

The [Ubuntu archive snapshot](https://snapshot.ubuntu.com/) and every package file needed by the producer are pinned in `inputs.lock.tsv`. This includes the exact libcap-dev archive (source package [Ubuntu libcap2](https://launchpad.net/ubuntu/+source/libcap2/1:2.66-5ubuntu2.4)) and the toolchain. Ubuntu supplies the corresponding libcap source package.

On a Linux x86-64 host with Bash, Python 3, curl and Docker, run `bash produce-owned-bwrap.sh NEW_OUTPUT_DIRECTORY` from this directory. The producer checks each download by SHA-256 and builds in a pinned Ubuntu 24.04 container with its network disabled. It corrects the extracted libcap pkg-config file to address the static archive's actual package path. The original build path is retained inside the container because the approved debug information records it. No Bubblewrap source changes are applied.

The output ELF has SHA-256 `6865e23c7ac667d87b8805850ec1759aca3fec338eb30fec6a099f31bd8aebbf` and GNU Build ID `ab143a5cf2d18cc62c85aa9bed0bb881ff17abda`. The installed runtime requires glibc 2.38 or newer. Both outputs are checked by hash before packaging.

The matching source artifacts are available from the [same Ubuntu snapshot](https://snapshot.ubuntu.com/ubuntu/20261128T160000Z/pool/main/libc/libcap2/).

| File | SHA-256 |
| --- | --- |
| `libcap2_2.66-5ubuntu2.4.dsc` | `8178019803f285b92e52e82cf84b0a6fc18840041270b2c588db826b8277e3e0` |
| `libcap2_2.66.orig.tar.xz` | `15c40ededb3003d70a283fe587a36b7d19c8b3b554e33f86129c059a4bb466b2` |
| `libcap2_2.66-5ubuntu2.4.debian.tar.xz` | `7eb46752c6b59984494d2f641a049b9d4b394b7d1fe067729ccbc413c5943136` |
