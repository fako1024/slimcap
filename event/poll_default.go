//go:build linux && !amd64 && !arm64 && !arm && !386
// +build linux,!amd64,!arm64,!arm,!386

package event

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

func pollBlock(fds *unix.PollFd, nfds int) unix.Errno {

	// #nosec: G103
	_, _, e := unix.Syscall6(unix.SYS_PPOLL, uintptr(unsafe.Pointer(fds)),
		uintptr(nfds), uintptr(unsafe.Pointer(nil)), 0, 0, 0)

	return e
}
