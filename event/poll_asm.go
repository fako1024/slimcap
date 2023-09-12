//go:build (linux && amd64) || (linux && arm64) || (linux && arm) || (linux && 386)
// +build linux,amd64 linux,arm64 linux,arm linux,386

package event

import (
	_ "unsafe" // required to support go:linkname

	"golang.org/x/sys/unix"
)

//go:noescape
//go:nosplit
//go:norace
func pollBlock(fds *unix.PollFd) unix.Errno

////////////////////////////////////

// The following stub is required to allow unsafe access to their equivalent in the runtime package from assembly
// This might break in the future, but there various sources that claim that it's widely used (and even issues at least
// imply that it's ok to use in favor of exposing that functionality (c.f. https://github.com/golang/go/issues/29734)

//go:linkname entersyscallblock runtime.entersyscallblock
//go:noescape
func entersyscallblock() //nolint:deadcode
