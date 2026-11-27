//! Read an ABI-v1 regular file inherited from a trusted workerOS launcher.

#[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
compile_error!("workeros requires Linux x86-64 or AArch64");

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod linux;
#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub use linux::{open_read, Identity, InheritedReader};
