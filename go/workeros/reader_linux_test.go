//go:build linux && (amd64 || arm64)

package workeros

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

func bind(t *testing.T, fd uintptr, key, access string) {
	t.Helper()
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(fd), &stat); err != nil {
		t.Fatal(err)
	}
	t.Setenv(abiPrefix+"ABI", "1")
	t.Setenv(abiPrefix+"DEADLINE_NS", "9223372036854775807")
	t.Setenv(abiPrefix+"FD_"+key, strconv.FormatUint(uint64(fd), 10))
	t.Setenv(abiPrefix+"DEV_"+key, strconv.FormatUint(stat.Dev, 10))
	t.Setenv(abiPrefix+"INO_"+key, strconv.FormatUint(stat.Ino, 10))
	t.Setenv(abiPrefix+"ACCESS_"+key, access)
}

func openFixture(t *testing.T, mode int) *os.File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "original")
	if err := os.WriteFile(path, []byte("worker"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, mode, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	return file
}

func TestReadAtOwnsOnlyTheDuplicate(t *testing.T) {
	source := openFixture(t, os.O_RDONLY)
	bind(t, source.Fd(), "INPUT_42", "read")
	if _, err := source.Seek(4, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	reader, err := Open("INPUT_42")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	if reader.file.Fd() == source.Fd() {
		t.Fatal("reader reused source descriptor")
	}
	fdFlags, err := fcntl(reader.file.Fd(), syscall.F_GETFD, 0)
	if err != nil || fdFlags&syscall.FD_CLOEXEC == 0 {
		t.Fatalf("expected a close-on-exec duplicate, flags %d, error %v", fdFlags, err)
	}
	buf := make([]byte, 4)
	if count, err := reader.ReadAt(buf, 0); count != len(buf) || err != nil || string(buf) != "work" {
		t.Fatalf("unexpected positional read %q, %d, %v", buf, count, err)
	}
	if count, err := reader.ReadAt(buf, 4); count != 2 || !errors.Is(err, io.EOF) || string(buf[:2]) != "er" {
		t.Fatalf("unexpected read at EOF %q, %d, %v", buf, count, err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if offset, err := source.Seek(0, io.SeekCurrent); offset != 4 || err != nil {
		t.Fatalf("source position changed or descriptor closed, offset %d, error %v", offset, err)
	}
}

func TestReadWriteSourceAndReadDeadline(t *testing.T) {
	source := openFixture(t, os.O_RDWR)
	bind(t, source.Fd(), "INPUT", "read-write")
	reader, err := Open("INPUT")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if n, err := reader.ReadAt(b[:], 0); n != 1 || err != nil || b[0] != 'w' {
		t.Fatalf("owned duplicate unavailable: %d, %q, %v", n, b, err)
	}
	reader.deadline = 1
	if n, err := reader.ReadAt(b[:], 0); n != 0 || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired read: %d, %v", n, err)
	}
}

func TestOpenRejectsInvalidMetadata(t *testing.T) {
	source := openFixture(t, os.O_RDONLY)
	for _, test := range []struct{ field, value string }{
		{"ABI", "01"}, {"FD_INPUT", "2"}, {"FD_INPUT", "2147483648"}, {"FD_INPUT", "03"},
		{"DEV_INPUT", "00"}, {"DEV_INPUT", "18446744073709551616"},
		{"INO_INPUT", "0"}, {"INO_INPUT", "+5"}, {"INO_INPUT", ""},
		{"DEADLINE_NS", "0"}, {"DEADLINE_NS", "9223372036854775808"},
		{"ACCESS_INPUT", "read-write"}, {"ACCESS_INPUT", "write"}, {"ACCESS_INPUT", "READ"},
	} {
		t.Run(test.field+"="+test.value, func(t *testing.T) {
			bind(t, source.Fd(), "INPUT", "read")
			t.Setenv(abiPrefix+test.field, test.value)
			if reader, err := Open("INPUT"); reader != nil || !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("expected refusal, got %v, %v", reader, err)
			}
		})
	}
	for _, key := range []string{"", "0INPUT", "_INPUT", "input", "IN-PUT", "INPUTß"} {
		if _, err := Open(key); !errors.Is(err, os.ErrInvalid) {
			t.Fatalf("accepted binding %q: %v", key, err)
		}
	}
	bind(t, source.Fd(), "INPUT", "read")
	t.Setenv(abiPrefix+"DEADLINE_NS", "1")
	if _, err := Open("INPUT"); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("expired open: %v", err)
	}
}

func TestOpenRejectsWrongDescriptor(t *testing.T) {
	source := openFixture(t, os.O_RDONLY)
	var original syscall.Stat_t
	if err := syscall.Fstat(int(source.Fd()), &original); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"DEV_INPUT", "INO_INPUT"} {
		t.Run(field, func(t *testing.T) {
			bind(t, source.Fd(), "INPUT", "read")
			wrong := original.Dev + 1
			if field == "INO_INPUT" {
				wrong = original.Ino ^ 1
			}
			t.Setenv(abiPrefix+field, strconv.FormatUint(wrong, 10))
			if _, err := Open("INPUT"); !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("identity mismatch: %v", err)
			}
		})
	}
	pipe, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	defer output.Close()
	path, err := syscall.Open(source.Name(), oPath|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(path)
	for name, fd := range map[string]uintptr{
		"pipe": pipe.Fd(), "write-only": openFixture(t, os.O_WRONLY).Fd(), "path-only": uintptr(path),
	} {
		t.Run(name, func(t *testing.T) {
			bind(t, fd, "INPUT", "read")
			if _, err := Open("INPUT"); !errors.Is(err, os.ErrInvalid) {
				t.Fatalf("unexpected %s descriptor: %v", name, err)
			}
		})
	}
}
