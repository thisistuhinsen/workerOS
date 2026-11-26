//go:build linux && (amd64 || arm64)

// Package workerhandoff reads regular files inherited from a workerOS ABI v1
// launcher on 64-bit Linux. The launcher supplies the descriptor and its scope.
// Environment metadata describes the grant. Applications supply authorization.
package workerhandoff

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	abiPrefix      = "WORKER_HANDOFF_"
	clockMonotonic = 1
	oPath          = 0x200000 // Linux O_PATH on amd64 and arm64.
)

// Reader owns a close-on-exec duplicate of an inherited descriptor.
type Reader struct {
	file     *os.File
	deadline uint64
}

// Open validates the ABI's named binding and the actual inherited descriptor.
// The caller retains the source descriptor and keeps it stable during Open.
// The returned Reader can be closed independently of the source.
func Open(binding string) (*Reader, error) {
	if !validBinding(binding) {
		return nil, fmt.Errorf("%w: expected an uppercase ASCII binding", os.ErrInvalid)
	}
	if os.Getenv(abiPrefix+"ABI") != "1" {
		return nil, fmt.Errorf("%w: expected worker handoff ABI 1", os.ErrInvalid)
	}
	source, err := number("FD_"+binding, 31, 3)
	if err != nil {
		return nil, err
	}
	device, err := number("DEV_"+binding, 64, 0)
	if err != nil {
		return nil, err
	}
	inode, err := number("INO_"+binding, 64, 1)
	if err != nil {
		return nil, err
	}
	deadline, err := number("DEADLINE_NS", 63, 1)
	if err != nil {
		return nil, err
	}
	var access uintptr
	switch os.Getenv(abiPrefix + "ACCESS_" + binding) {
	case "read":
		access = syscall.O_RDONLY
	case "read-write":
		access = syscall.O_RDWR
	default:
		return nil, fmt.Errorf("%w: expected a readable access mode", os.ErrInvalid)
	}
	if err := before(deadline); err != nil {
		return nil, err
	}

	dup, err := fcntl(uintptr(source), syscall.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, fmt.Errorf("duplicate inherited descriptor: %w", err)
	}
	if err := match(dup, device, inode, access); err != nil {
		syscall.Close(int(dup))
		return nil, err
	}
	if err := before(deadline); err != nil {
		syscall.Close(int(dup))
		return nil, err
	}
	file := os.NewFile(dup, "worker-handoff-"+binding)
	return &Reader{file: file, deadline: deadline}, nil
}

// ReadAt reads at offset without moving the inherited open file description's
// position. The Linux monotonic deadline is checked before starting the read.
// A read already in progress can outlast the deadline.
func (r *Reader) ReadAt(p []byte, offset int64) (int, error) {
	if r == nil || r.file == nil {
		return 0, os.ErrInvalid
	}
	if err := before(r.deadline); err != nil {
		return 0, err
	}
	return r.file.ReadAt(p, offset)
}

// Close releases the duplicate owned by r.
func (r *Reader) Close() error {
	if r == nil || r.file == nil {
		return os.ErrInvalid
	}
	return r.file.Close()
}

func validBinding(binding string) bool {
	if len(binding) == 0 || binding[0] < 'A' || binding[0] > 'Z' {
		return false
	}
	for index := 1; index < len(binding); index++ {
		c := binding[index]
		if c != '_' && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func number(field string, bits int, minimum uint64) (uint64, error) {
	key := abiPrefix + field
	raw := os.Getenv(key)
	value, err := strconv.ParseUint(raw, 10, bits)
	if err != nil || value < minimum || strconv.FormatUint(value, 10) != raw {
		return 0, fmt.Errorf("%w: expected canonical %s", os.ErrInvalid, key)
	}
	return value, nil
}

func fcntl(fd, command, argument uintptr) (uintptr, error) {
	value, _, err := syscall.Syscall(syscall.SYS_FCNTL, fd, command, argument)
	if err != 0 {
		return 0, err
	}
	return value, nil
}

func match(fd uintptr, device, inode uint64, access uintptr) error {
	var file syscall.Stat_t
	if err := syscall.Fstat(int(fd), &file); err != nil {
		return fmt.Errorf("inspect inherited descriptor: %w", err)
	}
	flags, err := fcntl(fd, syscall.F_GETFL, 0)
	if err != nil {
		return fmt.Errorf("inspect inherited access mode: %w", err)
	}
	if file.Mode&syscall.S_IFMT != syscall.S_IFREG || file.Dev != device || file.Ino != inode ||
		flags&(syscall.O_ACCMODE|oPath) != access {
		return fmt.Errorf("%w: descriptor must be the exact readable regular file", os.ErrInvalid)
	}
	return nil
}

func before(deadline uint64) error {
	var now syscall.Timespec
	_, _, err := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonic, uintptr(unsafe.Pointer(&now)), 0)
	if err != 0 {
		return fmt.Errorf("read Linux monotonic clock: %w", err)
	}
	if uint64(now.Sec)*1_000_000_000+uint64(now.Nsec) >= deadline {
		return os.ErrDeadlineExceeded
	}
	return nil
}
