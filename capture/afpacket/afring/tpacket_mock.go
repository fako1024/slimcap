//go:build linux && !slimcap_nomock
// +build linux,!slimcap_nomock

package afring

import (
	"sync/atomic"
	"unsafe"
)

// / -> Block Header
func (t tPacketHeader) getStatus() uint32 {
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&t.data[8])))
}

func (t tPacketHeader) setStatus(status uint32) {
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&t.data[8])), status)
}
