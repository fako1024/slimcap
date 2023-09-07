//go:build (linux && amd64) || (linux && arm64) || (linux && arm)
// +build linux,amd64 linux,arm64 linux,arm

package event

import (
	"golang.org/x/sys/unix"

	_ "unsafe" // required to support go:linkname
)

//go:noescape
//go:nosplit
func pollBlock(fds *unix.PollFd, nfds int) unix.Errno

////////////////////////////////////

// The following stubs are required to allow unsafe access to their equivalent in the runtime package from assembly
// This might break in the future, but there various sources that claim that it's widely used (and even issues at least
// imply that it's ok to use in favor of exposing that functionality (c.f. https://github.com/golang/go/issues/29734)

//go:linkname entersyscallblock runtime.entersyscallblock
//go:noescape
func entersyscallblock() //nolint:deadcode

//go:linkname exitsyscall runtime.exitsyscall
//go:noescape
func exitsyscall() //nolint:deadcode
