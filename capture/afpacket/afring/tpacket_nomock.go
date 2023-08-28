//go:build linux && slimcap_nomock
// +build linux,slimcap_nomock

package afring

import "unsafe"

// / -> Block Header
func (t tPacketHeader) getStatus() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[8]))
}

func (t tPacketHeader) setStatus(status uint32) {
	*(*uint32)(unsafe.Pointer(&t.data[8])) = status
}
