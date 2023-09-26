//go:build linux
// +build linux

package afring

import "golang.org/x/sys/unix"

type ringBuffer struct {
	ring []byte

	tpReq            tPacketRequest
	curTPacketHeader *tPacketHeader
	offset           int
}

func (b *ringBuffer) releaseAndAdvance() {
	b.curTPacketHeader.setStatus(unix.TP_STATUS_KERNEL)
	b.offset = (b.offset + 1) % int(b.tpReq.blockNr)
}

func (b *ringBuffer) loadTPacketHeader() {
	b.curTPacketHeader.data = b.ring[b.offset*int(b.tpReq.blockSize):]
}

func (b *ringBuffer) hasRunawayBlock() bool {
	if b.curTPacketHeader.getStatus()&unix.TP_STATUS_COPY != 0 {
		b.releaseAndAdvance()
		b.curTPacketHeader.data = nil
		return true
	}

	return false
}
