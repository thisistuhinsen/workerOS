# worker-handoff for Rust

Read a regular file descriptor inherited from a trusted workerOS launcher on Linux x86-64 or AArch64. Requires Rust 1.85 or newer and has no Cargo dependencies.

```toml
[dependencies]
worker-handoff = { git = "https://github.com/thisistuhinsen/workerOS", tag = "v0.4.0" }
```

```rust
use std::io;
use worker_handoff::open_read;

fn main() -> io::Result<()> {
    let input = open_read("INPUT")?;
    let mut bytes = [0u8; 64];
    let count = input.read_at(&mut bytes, 0)?;
    println!("{}", String::from_utf8_lossy(&bytes[..count]));
    Ok(())
}
```

`open_read` checks the ABI version, binding name, access declaration, and decimal FD, device, and inode. It duplicates the inherited FD with close-on-exec and checks that the duplicate refers to the advertised read-only regular file. A read can return fewer bytes than requested. Positional reads preserve the shared file offset.

Dropping the reader closes its duplicate. The original inherited slot remains open until its owner closes it or the process exits. Run the worker with a trusted launcher and keep the original slot stable during `open_read`. The environment describes the handoff. Your launcher supplies authorization, supervision, and any required custody checks.
