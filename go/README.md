# workerOS for Go

Go 1.22 or later on Linux `amd64` or `arm64`.

```sh
go get github.com/thisistuhinsen/workerOS/go/workerhandoff@v0.4.0
```

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
