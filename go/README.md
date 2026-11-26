# workerOS for Go

Go 1.22 or later on Linux `amd64` or `arm64`.

After the `v0.5.0` tag is published, install the reader in your Go module.

```sh
go get github.com/thisistuhinsen/workerOS/go/workerhandoff@v0.5.0
```

### Published v0.4.0 checksum fallback

The pinned checksums in this section apply only to v0.4.0. If Go reports that the checksum service could not fetch v0.4.0, confirm the
public tag points to `cd3d621c28247a66b1c6978396335cc97d8c0fa9`.

```sh
git ls-remote --refs https://github.com/thisistuhinsen/workerOS.git refs/tags/v0.4.0
```

In your own Go module, add these two entries to `go.sum`. Keep unrelated entries
and stop if v0.4.0 already has different checksums.

```text
github.com/thisistuhinsen/workerOS v0.4.0 h1:PUaqJ5Q5IoFOE8qGCYLNZmlgzD80UoT2GuvB82PSdis=
github.com/thisistuhinsen/workerOS v0.4.0/go.mod h1:GLxsXbnr8VyBiNpeAm1qFkJDH8XoyQ03m9nZpiImYH8=
```

```sh
GOPROXY=direct go get github.com/thisistuhinsen/workerOS/go/workerhandoff@v0.4.0
go mod verify
```

Go checks both the downloaded module and its `go.mod` against the pinned hashes.
Keep your checksum settings in place.

### Read from the inherited descriptor

Launch the worker with the workerOS inherited-FD ABI v1 and bind the original
under `INPUT`. From the Go worker, open that binding and read at a file offset.

```go
import "github.com/thisistuhinsen/workerOS/go/workerhandoff"

func readByte() (byte, error) {
    reader, err := workerhandoff.Open("INPUT")
    if err != nil {
        return 0, err
    }
    defer reader.Close()

    var data [1]byte
    _, err = reader.ReadAt(data[:], 0)
    return data[0], err
}
```

`Open` checks the launcher metadata against the live descriptor, including the
device, inode and readable access mode. The caller retains its inherited FD and
keeps it stable during `Open`. The `Reader` owns a close-on-exec duplicate.
`ReadAt` preserves the shared file position and checks the Linux monotonic
deadline before reading. An in-progress syscall can outlast that deadline.
Authorization and worker lifecycle remain with the launching application.
