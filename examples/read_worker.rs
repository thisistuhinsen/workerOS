use std::{
    env,
    fs::File,
    os::fd::FromRawFd,
    os::unix::fs::FileExt,
    process::ExitCode,
};

fn main() -> ExitCode {
    if env::var("WORKER_HANDOFF_ABI").as_deref() != Ok("1") {
        return 2.into();
    }
    let Ok(value) = env::var("WORKER_HANDOFF_FD_INPUT") else {
        return 2.into();
    };
    let Ok(fd) = value.parse::<i32>() else {
        return 2.into();
    };
    if fd < 3 || fd.to_string() != value {
        return 2.into();
    }

    // The trusted launcher transferred this live descriptor to this process.
    let file = unsafe { File::from_raw_fd(fd) };
    let mut byte = [0_u8; 1];
    if file.read_exact_at(&mut byte, 0).is_ok() && byte[0] == b'W' {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
