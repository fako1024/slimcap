package afpacket

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tPacketStatusKernel = 0
	tPacketStatusUser   = 1
	tPacketStatusCopy   = 2
)

var (
	tPacketDefaultFrameSize = 8192
	tPacketDefaultNBlocks   = 32
	tPacketDefaultBlockNr   = 1
)

// tPacketRequestV1 denotes the tpacket_req structure, c.f.
// https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
type tPacketRequestV1 struct {
	blockSize uint32
	blockNr   uint32
	frameSize uint32
	frameNr   uint32
}

func newTPacketRequestV1(frameSize, nBlocks, blockNr int) (req tPacketRequestV1, err error) {

	// Ensure the parameters are in alignment with the page size
	blockSize := frameSize * nBlocks
	if pageSize := unix.Getpagesize(); blockSize%pageSize != 0 {
		err = fmt.Errorf("TPacket block size (%d) is not page size aligned (page size: %d)", blockSize, pageSize)
		return
	}

	req = tPacketRequestV1{
		blockSize: uint32(blockSize),
		blockNr:   uint32(blockNr),
		frameSize: uint32(frameSize),
		frameNr:   (uint32(blockSize) * uint32(blockNr)) / uint32(frameSize),
	}

	return
}

func (t tPacketRequestV1) blockSizeNr() int {
	return int(t.blockSize * t.blockNr)
}

// tPacketHeaderV1 denotes the tpacket_hdr structure, c.f.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_packet.h
type tPacketHeaderV1 []byte

// TODO: Unsure if the getStatus / setStatus have to be atomic
func (t tPacketHeaderV1) getStatus() uint32 {
	return *(*uint32)(unsafe.Pointer(&t[0]))
}

func (t tPacketHeaderV1) setStatus(status uint32) {
	*(*uint32)(unsafe.Pointer(&t[0])) = status
}

func (t tPacketHeaderV1) snapLen() uint32 {
	return binary.LittleEndian.Uint32(t[12:16])
}

func (t tPacketHeaderV1) mac() uint16 {
	return binary.LittleEndian.Uint16(t[16:18])
}

func (t tPacketHeaderV1) packetType() byte {
	return t[42]
}

func (t tPacketHeaderV1) payloadNoCopy() []byte {
	return t[uint32(t.mac()) : uint32(t.mac())+t.snapLen()]
}

func (t tPacketHeaderV1) payloadCopy() []byte {
	rawPayload := t.payloadNoCopy()
	cpPayload := make([]byte, len(rawPayload))
	copy(cpPayload, rawPayload)
	return cpPayload
}

// tPacketStatsV1 denotes the tpacket_stats structure, c.f.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_packet.h
type tPacketStatsV1 struct {
	packets uint32
	drops   uint32
}
