use super::*;
use std::fs::{remove_file, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

const CASE: &str = "WORKEROS_RUST_TEST_CASE";
const BINDING: &str = "INPUT_1";
const FD: &str = "WORKER_HANDOFF_FD_INPUT_1";
const DEVICE: &str = "WORKER_HANDOFF_DEV_INPUT_1";
const INODE: &str = "WORKER_HANDOFF_INO_INPUT_1";
const ACCESS: &str = "WORKER_HANDOFF_ACCESS_INPUT_1";
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;

fn test_child(case: &str) {
    if case != "read" {
        assert_eq!(
            open_read(BINDING).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        return;
    }
    let input = open_read(BINDING).unwrap();
    let original: RawFd = env::var(FD).unwrap().parse().unwrap();
    let duplicate = input.as_fd().as_raw_fd();
    assert_ne!(original, duplicate);
    assert_eq!(unsafe { fcntl(duplicate, F_GETFD) }, FD_CLOEXEC);
    assert_eq!(
        input.identity().inode,
        env::var(INODE).unwrap().parse::<u64>().unwrap()
    );
    let mut byte = [0];
    assert_eq!(input.read_at(&mut byte, 0).unwrap(), 1);
    assert_eq!(byte, [b'W']);
    assert_eq!(input.read_at(&mut byte, 10).unwrap(), 0);
    drop(input);
    assert_eq!(unsafe { fcntl(duplicate, F_GETFD) }, -1);
    assert_eq!(unsafe { fcntl(original, F_GETFD) }, 0);
}

fn spawn_case(case: &str, file: &File) {
    let metadata = file.metadata().unwrap();
    let slot = file.as_raw_fd();
    let mut child = Command::new(env::current_exe().unwrap());
    child
        .args([
            "--exact",
            "linux::tests::real_inherited_descriptor",
            "--nocapture",
        ])
        .env_clear()
        .env(CASE, case)
        .env("WORKER_HANDOFF_ABI", "1")
        .env(FD, slot.to_string())
        .env(DEVICE, metadata.dev().to_string())
        .env(INODE, metadata.ino().to_string())
        .env(ACCESS, "read");
    match case {
        "wrong-abi" => {
            child.env("WORKER_HANDOFF_ABI", "01");
        }
        "noncanonical-fd" => {
            child.env(FD, format!("0{slot}"));
        }
        "fd-overflow" => {
            child.env(FD, "2147483648");
        }
        "noncanonical-device" => {
            child.env(DEVICE, format!("+{}", metadata.dev()));
        }
        "wrong-device" => {
            child.env(DEVICE, (metadata.dev() ^ 1).to_string());
        }
        "wrong-inode" => {
            child.env(INODE, (metadata.ino() ^ 1).to_string());
        }
        "wrong-access" => {
            child.env(ACCESS, "read-write");
        }
        _ => {}
    }
    // Clearing FD_CLOEXEC after fork changes only the child's descriptor table.
    unsafe {
        child.pre_exec(move || {
            if fcntl(slot, F_SETFD, 0 as c_int) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let result = child.output().unwrap();
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        result.status.success() && stdout.contains("running 1 test"),
        "{case}: {stdout}\n{}",
        String::from_utf8_lossy(&result.stderr),
    );
}

#[test]
fn real_inherited_descriptor() {
    if let Ok(case) = env::var(CASE) {
        test_child(&case);
        return;
    }
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = env::temp_dir().join(format!("workeros-{}-{unique}", process::id()));
    let mut writable = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap();
    writable.write_all(b"Worker").unwrap();
    let mut readable = File::open(&path).unwrap();
    let path_only = OpenOptions::new()
        .read(true)
        .custom_flags(O_PATH)
        .open(&path)
        .unwrap();
    remove_file(path).unwrap();

    readable.seek(SeekFrom::Start(2)).unwrap();
    for case in [
        "read",
        "wrong-abi",
        "noncanonical-fd",
        "fd-overflow",
        "noncanonical-device",
        "wrong-device",
        "wrong-inode",
        "wrong-access",
    ] {
        spawn_case(case, &readable);
    }
    assert_eq!(readable.stream_position().unwrap(), 2);
    spawn_case("writable", &writable);
    spawn_case("path-only", &path_only);
    spawn_case("directory", &File::open(env::temp_dir()).unwrap());
}

#[test]
fn malformed_bindings_are_refused() {
    for binding in ["", "1INPUT", "input", "IN-PUT", "INÉ"] {
        assert_eq!(
            open_read(binding).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
