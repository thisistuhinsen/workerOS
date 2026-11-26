package main

import (
	"os"
	"strconv"
)

func main() {
	if os.Getenv("WORKER_HANDOFF_ABI") != "1" {
		os.Exit(2)
	}
	value := os.Getenv("WORKER_HANDOFF_FD_INPUT")
	n, err := strconv.ParseInt(value, 10, 32)
	if err != nil || n < 3 || strconv.FormatInt(n, 10) != value {
		os.Exit(2)
	}
	f := os.NewFile(uintptr(n), "inherited-input")
	if f == nil {
		os.Exit(1)
	}
	var b [1]byte
	count, readErr := f.ReadAt(b[:], 0)
	closeErr := f.Close()
	if count != 1 || readErr != nil || closeErr != nil || b[0] != 'W' {
		os.Exit(1)
	}
}
