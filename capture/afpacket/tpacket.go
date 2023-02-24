package afpacket

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tPacketAlignment = uint(unix.TPACKET_ALIGNMENT)
	tPacketHeaderLen = 48 // sizeof(tpacket3_hdr)
)

const (
	tPacketStatusKernel = 0
	tPacketStatusUser   = (1 << 0)
	tPacketStatusCopy   = (1 << 1)

	tPacketDefaultBlockNr   = 4         // sizeof(tpacket3_hdr)
	tPacketDefaultBlockSize = (1 << 20) // 1 MiB
	tPacketDefaultBlockTOV  = 100       // ms
)

var (
	pageSizeAlignment = uint(unix.Getpagesize())
)

// tPacketRequest denotes the V3 tpacket_req structure, c.f.
// https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
type tPacketRequest struct {
	blockSize uint32
	blockNr   uint32
	frameSize uint32
	frameNr   uint32

	retire_blk_tov   uint32
	sizeof_priv      uint32
	feature_req_word uint32
}

func newTPacketRequestForBuffer(blockSize, nBlocks, snapLen int) (req tPacketRequest, err error) {

	// The block size is the overall length of a block's continuous memory buffer. It should be chosen
	// to be a power of two (otherwise all excess memory would be wasted),
	blockSize = pageSizeAlign(blockSize)

	// The number of blocks defines how many ring buffer blocks (i.e. batches of frames / packets)
	// are created. This probably shouldn't be too high in order to minimize the number of syscalls
	// in favor of more frames / packets per block, maximizing the amount of in-memory operations.
	_ = nBlocks

	// The frame size is the _minimum_ size of a frame (i.e. individual packet) in a block
	// It is optimally set to the per-packet TPacket header length plus defined snaplen. However, it must
	// be a multiple of tPacketAlignment AND blockSize must be a multiple of the frameSize
	frameSize := blockSizeTPacketAlign(tPacketHeaderLen+snapLen, blockSize)

	return newTPacketRequest(blockSize, nBlocks, frameSize)
}

func newTPacketRequest(blockSize, blockNr, frameSize int) (req tPacketRequest, err error) {

	// Ensure the parameters are in alignment with the TPacket header length requirements:
	// blockSize must be a multiple of the page size
	// frameSize must be greater than tPacketHeaderLen
	// frameSize must be a multiple of tPacketAlignment
	// frameNr  must be exactly (blockSize*blockNr) / frameSize

	req = tPacketRequest{
		blockSize:      uint32(blockSize),
		blockNr:        uint32(blockNr),
		frameSize:      uint32(frameSize),
		frameNr:        (uint32(blockSize) * uint32(blockNr)) / uint32(frameSize),
		retire_blk_tov: tPacketDefaultBlockTOV,
	}

	return
}

func (t tPacketRequest) blockSizeNr() int {
	return int(t.blockSize * t.blockNr)
}

// tPacketHeader denotes the V3 tpacket_hdr structure, c.f.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_packet.h
type tPacketHeader struct {
	data      []byte
	ppos      uint32
	nPktsUsed uint32
}

// / -> Block Descriptor
func (t tPacketHeader) version() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[0]))
}

func (t tPacketHeader) privOffset() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[4]))
}

// / -> Block Header
func (t tPacketHeader) getStatus() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[8]))
}

func (t tPacketHeader) setStatus(status uint32) {
	*(*uint32)(unsafe.Pointer(&t.data[8])) = status
}

func (t tPacketHeader) nPkts() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[12]))
}

func (t tPacketHeader) offsetToFirstPkt() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[16]))
}

func (t tPacketHeader) blockLen() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[20]))
}

// According to linux/if_packet.h this is aligned to an 8-byte boundary instead of 4.
func (t tPacketHeader) seqNumber() uint64 {
	return *(*uint64)(unsafe.Pointer(&t.data[24]))
}

// 2 * 3 * uint32 for timestamps

// / -> Packet Header
func (t tPacketHeader) nextOffset() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[t.ppos]))
}

// 2 * uint32 for timestamps

func (t tPacketHeader) snapLen() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[t.ppos+12]))
}

func (t tPacketHeader) pktLen() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[t.ppos+16]))
}

func (t tPacketHeader) pktLenPut(data []byte) {
	copy(data, t.data[t.ppos+16:t.ppos+20])
}

func (t tPacketHeader) getPacketStatus() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[t.ppos+20]))
}

func (t tPacketHeader) setPacketStatus(status uint32) {
	*(*uint32)(unsafe.Pointer(&t.data[t.ppos+20])) = status
}

func (t tPacketHeader) mac() uint16 {
	return *(*uint16)(unsafe.Pointer(&t.data[t.ppos+24]))
}

func (t tPacketHeader) net() uint16 {
	return *(*uint16)(unsafe.Pointer(&t.data[t.ppos+26]))
}

func (t tPacketHeader) packetType() byte {
	return t.data[t.ppos+58]
}

func (t tPacketHeader) payloadNoCopy() []byte {
	mac := uint32(*(*uint16)(unsafe.Pointer(&t.data[t.ppos+24])))
	return t.data[t.ppos+mac : t.ppos+mac+t.snapLen()]
}

func (t tPacketHeader) payloadCopyPut(data []byte) {
	mac := uint32(*(*uint16)(unsafe.Pointer(&t.data[t.ppos+24])))
	copy(data, t.data[t.ppos+mac:t.ppos+mac+t.snapLen()])
}

func (t tPacketHeader) payloadCopy() []byte {
	rawPayload := t.payloadNoCopy()
	cpPayload := make([]byte, len(rawPayload))
	copy(cpPayload, rawPayload)
	return cpPayload
}

// tPacketStats denotes the V3 tpacket_stats structure, c.f.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_packet.h
type tPacketStats struct {
	packets      uint32
	drops        uint32
	queueFreezes uint32
}

func tPacketAlign(x int) int {
	return int((uint(x) + tPacketAlignment - 1) &^ (tPacketAlignment - 1))
}

func pageSizeAlign(x int) int {
	return int((uint(x) + pageSizeAlignment - 1) &^ (pageSizeAlignment - 1))
}

func blockSizeTPacketAlign(x, blockSize int) int {
	for i := uint(x); ; i++ {
		if i%tPacketAlignment == 0 && uint(blockSize)%i == 0 {
			return int(i)
		}
	}
}
