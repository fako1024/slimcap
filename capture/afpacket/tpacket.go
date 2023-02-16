package afpacket

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tPacketAlignment = uint(unix.TPACKET_ALIGNMENT)

	// TODO: This somehow doesn't seem right...
	tPacketHeaderLen = 31 // 66 seems to be the index we get from payloadCopy()
)

const (
	tPacketStatusKernel = 0
	tPacketStatusUser   = (1 << 0)
	tPacketStatusCopy   = (1 << 1)
)

var (
	pageSizeAlignment     = uint(unix.Getpagesize())
	tPacketDefaultBlockNr = 1
)

// tPacketRequest denotes the V3 tpacket_req structure, c.f.
// https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt
type tPacketRequest struct {
	blockSize uint32
	blockNr   uint32
	frameSize uint32
	frameNr   uint32

	retire_blk_tov   uint32 // TODO: What exactly does this do?
	sizeof_priv      uint32
	feature_req_word uint32
}

func newTPacketRequestForBuffer(bufSize, snapLen int) (req tPacketRequest, err error) {

	// Ensure the parameters are in alignment with the TPacket header length requirements
	frameSize := tPacketAlign(tPacketHeaderLen + snapLen)
	nBlocks := tPacketAlign(bufSize / frameSize)

	return newTPacketRequest(frameSize, nBlocks, tPacketDefaultBlockNr)
}

func newTPacketRequest(frameSize, nBlocks, blockNr int) (req tPacketRequest, err error) {

	// Ensure the parameters are in alignment with the page size
	blockSize := pageSizeAlign(frameSize * nBlocks)
	req = tPacketRequest{
		blockSize: uint32(blockSize),
		blockNr:   uint32(blockNr),
		frameSize: uint32(frameSize),
		frameNr:   (uint32(blockSize) * uint32(blockNr)) / uint32(frameSize),
	}

	return
}

func (t tPacketRequest) blockSizeNr() int {
	return int(t.blockSize * t.blockNr)
}

// tPacketHeader denotes the V3 tpacket_hdr structure, c.f.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_packet.h
type tPacketHeader struct {
	data []byte
	ppos uint32
}

// / -> Block Descriptor
func (t tPacketHeader) version() uint32 {
	return binary.LittleEndian.Uint32(t.data[0:4])
}

func (t tPacketHeader) privOffset() uint32 {
	return binary.LittleEndian.Uint32(t.data[4:8])
}

// / -> Block Header
func (t tPacketHeader) getStatus() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[8]))
}

func (t tPacketHeader) setStatus(status uint32) {
	*(*uint32)(unsafe.Pointer(&t.data[8])) = status
}

func (t tPacketHeader) nPkts() uint32 {
	return binary.LittleEndian.Uint32(t.data[12:16])
}

func (t tPacketHeader) offsetToFirstPkt() uint32 {
	return binary.LittleEndian.Uint32(t.data[16:20])
}

func (t tPacketHeader) blockLen() uint32 {
	return binary.LittleEndian.Uint32(t.data[20:24])
}

// According to linux/if_packet.h this is aligned to an 8-byte boundary instead of 4.
func (t tPacketHeader) seqNumber() uint64 {
	return binary.LittleEndian.Uint64(t.data[24:32])
}

// 2 * 3 * uint32 for timestamps

// / -> Packet Header
func (t tPacketHeader) nextOffset() uint32 {
	return binary.LittleEndian.Uint32(t.data[t.ppos : t.ppos+4])
}

// 2 * uint32 for timestamps

func (t tPacketHeader) snapLen() uint32 {
	return binary.LittleEndian.Uint32(t.data[t.ppos+12 : t.ppos+16])
}

func (t tPacketHeader) pktLen() uint32 {
	return binary.LittleEndian.Uint32(t.data[t.ppos+16 : t.ppos+20])
}

func (t tPacketHeader) getPacketStatus() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[t.ppos+20]))
}

func (t tPacketHeader) setPacketStatus(status uint32) {
	*(*uint32)(unsafe.Pointer(&t.data[t.ppos+20])) = status
}

func (t tPacketHeader) mac() uint16 {
	return binary.LittleEndian.Uint16(t.data[t.ppos+24 : t.ppos+26])
}

func (t tPacketHeader) net() uint16 {
	return binary.LittleEndian.Uint16(t.data[t.ppos+26 : t.ppos+28])
}

func (t tPacketHeader) packetType() byte {
	return t.data[t.ppos+58]
}

func (t tPacketHeader) payloadNoCopy() []byte {
	return t.data[t.ppos+uint32(t.mac()) : t.ppos+uint32(t.mac())+t.snapLen()]
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
