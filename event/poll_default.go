//go:build (linux && !amd64 && !arm64 && !arm && !386) || slimcap_noasm
// +build linux,!amd64,!arm64,!arm,!386 slimcap_noasm

package event

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

const nPollEvents = uintptr(0x02)

func pollBlock(fds *unix.PollFd) unix.Errno {

	// #nosec: G103
	_, _, e := unix.Syscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(fds)),
		nPollEvents, uintptr(unsafe.Pointer(nil)), 0, 0, 0)

	return e
}
