# Support and verification

workerOS is a Linux file-descriptor handoff library. Use the [release’s checks](../README.md#verify-and-contribute) for the exact source version you are deploying. The table describes what each verification path covers.

| Path | Required environment and evidence |
| --- | --- |
| Python controller and readers | Linux, Python 3.11 or newer. The hosted matrix covers Ubuntu x64 and ARM64, plus Debian, Fedora, and Alpine userspace on an Ubuntu host kernel. The suite includes a real connected Unix stream descriptor transfer and the inherited-FD ABI. |
| Direct-child supervision | Usable Linux pidfds and `waitid(P_PIDFD)`. Only a launched or explicitly adopted, waitable direct child is within the supervisor’s stop and reap authority. A legacy roster join can time out with the child still running. |
| Independent strict custody | An independently controlled, qualified Linux observer with its own credentials and exact release-scope evidence. Hosted CI demonstrates a read-only grant of one sealed original, a separate writer UID, terminal reaping, and refusal cases. A deployment that uses strict custody needs its own qualified observer. |
| Installed worker examples | Inherited descriptor ABI v1 under the Linux controller. The hosted Linux jobs exercise C, C++, Go, Java, Node.js, Python, and Rust. Java FFM requires 64-bit Linux and a JDK 22 or newer. |
| Hosted WSL2 | A real Ubuntu 24.04 guest with the Microsoft WSL2 kernel on a hosted Windows runner. The guest builds the wheel, installs it offline, and exercises the Python suite plus the C and Python examples. Individual PCs need their own verification. |
| Native Windows | Wheel build and offline installation, followed by the expected Linux-only `fcntl` import boundary. |

The connected Unix stream framing and Python controller APIs remain at their existing compatibility boundaries. The native language adapters consume inherited descriptor bindings. Their package metadata and documentation state Linux runtime and minimum toolchain requirements. Runtime support still depends on which kernel facilities the host permits.

An inherited FD and its environment fields describe an application grant. The application must establish authorization and descriptor lifetime. A readable file descriptor permits reading the file, including when the roster labels a worker `observe`. Holding an inode across a rename preserves what the descriptor refers to. It does not freeze bytes another writer can change.

The project supports the latest published release. Report failures against that release and include the exact platform and package-manager path. [Contribution policy](../CONTRIBUTING.md)
