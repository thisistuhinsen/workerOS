use std::env;
use std::ffi::c_int;
use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileExt, MetadataExt};

// Linux UAPI fcntl commands and file status flags.
const F_GETFL: c_int = 3;
const F_DUPFD_CLOEXEC: c_int = 1030;
const O_ACCMODE: c_int = 0o3;
const O_PATH: c_int = 0o10000000;

extern "C" {
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
}

/// Device and inode sampled from the duplicate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub device: u64,
    pub inode: u64,
}

/// Owns one close-on-exec duplicate. Drop closes that duplicate.
#[derive(Debug)]
pub struct InheritedReader {
    file: File,
    identity: Identity,
}

impl InheritedReader {
    pub fn identity(&self) -> Identity {
        self.identity
    }

    /// Reads at an explicit position without changing the shared file offset.
    /// A short read or zero bytes at EOF is possible.
    pub fn read_at(&self, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
        self.file.read_at(buffer, offset)
    }
}

impl AsFd for InheritedReader {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.file.as_fd()
    }
}

fn invalid(reason: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason.into())
}

fn value(key: &str) -> io::Result<String> {
    env::var(key).map_err(|_| invalid(format!("missing or non-UTF-8 {key}")))
}

fn decimal(key: &str) -> io::Result<u64> {
    let text = value(key)?;
    text.parse::<u64>()
        .ok()
        .filter(|number| number.to_string() == text)
        .ok_or_else(|| {
            invalid(format!(
                "{key} must be a canonical decimal unsigned integer"
            ))
        })
}

fn duplicate(fd: RawFd) -> io::Result<File> {
    // This syscall needs a raw slot number and an integer minimum.
    let owned = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, 3 as c_int) };
    if owned < 0 {
        return Err(io::Error::last_os_error());
    }
    // A successful F_DUPFD_CLOEXEC returns a new descriptor owned by this call.
    Ok(unsafe { File::from_raw_fd(owned) })
}

/// Duplicates the named read-only FD after checking its ABI metadata and kernel
/// identity. The launcher controls authorization and must keep the named slot
/// stable until the duplicate is open. This function leaves that slot open.
pub fn open_read(binding: &str) -> io::Result<InheritedReader> {
    let mut bytes = binding.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        || !bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(invalid(
            "binding must start with A-Z and contain only A-Z, 0-9, and _",
        ));
    }
    if value("WORKER_HANDOFF_ABI")? != "1" {
        return Err(invalid("expected WORKER_HANDOFF_ABI=1"));
    }
    if value(&format!("WORKER_HANDOFF_ACCESS_{binding}"))? != "read" {
        return Err(invalid("expected an inherited binding with read access"));
    }
    let fd = RawFd::try_from(decimal(&format!("WORKER_HANDOFF_FD_{binding}"))?)
        .ok()
        .filter(|fd| *fd >= 3)
        .ok_or_else(|| invalid("expected an inherited FD numbered 3 or higher"))?;
    let expected = Identity {
        device: decimal(&format!("WORKER_HANDOFF_DEV_{binding}"))?,
        inode: decimal(&format!("WORKER_HANDOFF_INO_{binding}"))?,
    };
    if expected.inode == 0 {
        return Err(invalid("the advertised inode must be positive"));
    }

    let file = duplicate(fd)?;
    // The duplicate remains live and owned while the kernel samples its flags.
    let flags = unsafe { fcntl(file.as_raw_fd(), F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let actual = file.metadata()?;
    let identity = Identity {
        device: actual.dev(),
        inode: actual.ino(),
    };
    if flags & (O_ACCMODE | O_PATH) != 0 || !actual.is_file() || identity != expected {
        return Err(invalid(
            "inherited FD must match the advertised read-only regular file",
        ));
    }
    Ok(InheritedReader { file, identity })
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
