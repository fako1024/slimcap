//go:build linux
// +build linux

package afring

import (
	"fmt"
	"math"
	"unsafe"

	"github.com/fako1024/slimcap/capture"
	"golang.org/x/sys/unix"
)

const (
	tPacketAlignment = uint(unix.TPACKET_ALIGNMENT)
	tPacketHeaderLen = 48 // sizeof(tpacket3_hdr)
)

const (
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

	retireBlkTov   uint32
	sizeofPriv     uint32 //nolint:structcheck // (needed for correct sizeof(struct))
	featureReqWord uint32 //nolint:structcheck // (needed for correct sizeof(struct))
}

func newTPacketRequestForBuffer(blockSize, nBlocks, snapLen int) (req tPacketRequest, err error) {

	// The block size is the overall length of a block's continuous memory buffer. It should be chosen
	// to be a power of two (otherwise all excess memory would be wasted).
	if blockSize != pageSizeAlign(blockSize) {
		err = fmt.Errorf("block size %d not aligned to page size", blockSize)
		return
	}

	// The number of blocks defines how many ring buffer blocks (i.e. batches of frames / packets)
	// are created. This probably shouldn't be too high in order to minimize the number of syscalls
	// in favor of more frames / packets per block, maximizing the amount of in-memory operations.
	_ = nBlocks

	// The frame size is the _minimum_ size of a frame (i.e. individual packet) in a block
	// It is optimally set to the per-packet TPacket header length plus defined snaplen. However, it must
	// be a multiple of tPacketAlignment AND blockSize must be a multiple of the frameSize
	frameSize, err := blockSizeTPacketAlign(tPacketHeaderLen+snapLen, blockSize)
	if err != nil {
		return tPacketRequest{}, err
	}

	return newTPacketRequest(blockSize, nBlocks, frameSize)
}

func newTPacketRequest(blockSize, blockNr, frameSize int) (req tPacketRequest, err error) {

	// Ensure the parameters are in alignment with the TPacket header length requirements:
	// blockSize must be a multiple of the page size
	// frameSize must be greater than tPacketHeaderLen
	// frameSize must be a multiple of tPacketAlignment
	// frameNr  must be exactly (blockSize*blockNr) / frameSize
	req = tPacketRequest{
		blockSize:    uint32(blockSize),
		blockNr:      uint32(blockNr),
		frameSize:    uint32(frameSize),
		frameNr:      (uint32(blockSize) * uint32(blockNr)) / uint32(frameSize),
		retireBlkTov: tPacketDefaultBlockTOV,
	}

	return
}

func (t tPacketRequest) blockSizeNr() int {
	return int(t.blockSize * t.blockNr)
}

// tPacketHeader denotes a wrapper around the raw data of a TPacket block structure
type tPacketHeader struct {
	data      []byte
	ppos      uint32
	nPktsLeft uint32
}

// tPacketHeaderV3 denotes the V3 tpacket_hdr structure, c.f.
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_packet.h
// Note: The struct parses only the relevant portions of the header, the rest is
// skipped / ignored by means of dummy elements of the correct in-memory size
type tPacketHeaderV3 struct {
	snaplen uint32     // 12-16
	pktLen  uint32     // 16-20
	_       uint32     // skip
	pktPos  uint16     // 24-26
	_       [16]uint16 // skip
	pktType byte       // 58
}

func (t tPacketHeader) nPkts() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[12])) // #nosec G103
}

func (t tPacketHeader) offsetToFirstPkt() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[16])) // #nosec G103
}

func (t tPacketHeader) nextOffset() uint32 {
	return *(*uint32)(unsafe.Pointer(&t.data[t.ppos])) // #nosec G103
}

func (t tPacketHeader) pktLenPut(data []byte) {
	copy(data, t.data[t.ppos+16:t.ppos+20])
}

func (t tPacketHeader) packetType() byte {
	return t.data[t.ppos+58]
}

func (t tPacketHeader) payloadZeroCopy(offset byte) ([]byte, byte, uint32) {

	// Parse the V3 TPacketHeader and the first byte of the payload
	hdr := (*tPacketHeaderV3)(unsafe.Pointer(&t.data[t.ppos+12])) // #nosec G103
	pos := t.ppos + uint32(hdr.pktPos) + uint32(offset)

	// Return the payload / IP layer subslice & heeader parameters
	return t.data[pos : pos+hdr.snaplen],
		hdr.pktType,
		hdr.pktLen
}

func (t tPacketHeader) packetPut(data capture.Packet, ipLayerOffset byte) capture.Packet {

	// Parse the V3 TPacketHeader, the first byte of the payload and snaplen
	hdr := (*tPacketHeaderV3)(unsafe.Pointer(&t.data[t.ppos+12])) // #nosec G103
	pos := t.ppos + uint32(hdr.pktPos)
	snapLen := int(hdr.snaplen)

	// Allocate new capture.Packet if no buffer was provided
	if data == nil {
		data = make(capture.Packet, capture.PacketHdrOffset+snapLen)
	}

	// Extract / copy all required data / header parameters
	data[0] = hdr.pktType
	data[1] = ipLayerOffset
	t.pktLenPut(data[2:6])
	copy(data[6:], t.data[pos:pos+hdr.snaplen])

	// Ensure correct packet length
	if snapLen+capture.PacketHdrOffset < len(data) {
		data = data[:capture.PacketHdrOffset+snapLen]
	}

	return data
}

func (t tPacketHeader) payloadPut(data []byte, offset byte) ([]byte, capture.PacketType, uint32) {

	// Parse the V3 TPacketHeader, the first byte of the payload and snaplen
	hdr := (*tPacketHeaderV3)(unsafe.Pointer(&t.data[t.ppos+12])) // #nosec G103
	pos := t.ppos + uint32(hdr.pktPos) + uint32(offset)
	snapLen := int(hdr.snaplen)

	// Allocate new payload / IP layer if no buffer was provided
	if data == nil {
		data = make([]byte, snapLen)
	}

	// Copy payload / IP layer
	copy(data, t.data[pos:pos+hdr.snaplen])

	// Ensure correct data length
	if effectiveSnapLen := snapLen - int(offset); effectiveSnapLen < len(data) {
		data = data[:effectiveSnapLen]
	}

	// Return payload / IP layer & header parameters
	return data, hdr.pktType, hdr.pktLen
}

//////////////////////////////////////////////////////////////////////////////////////////////////

func pageSizeAlign(x int) int {
	return int((uint(x) + pageSizeAlignment - 1) &^ (pageSizeAlignment - 1))
}

func blockSizeTPacketAlign(x, blockSize int) (int, error) {

	// If the block size is not aligned there is no solution
	if uint(blockSize)%tPacketAlignment != 0 {
		return 0, fmt.Errorf("block size %d not aligned to tPacketAlignment (%d)", blockSize, tPacketAlignment)
	}

	// Ensure x is aligned to tPacketAlignment (if not, find the next value that is)
	i := uint(x)
	if i%tPacketAlignment != 0 {
		i += tPacketAlignment - (i % tPacketAlignment)
	}

	// Search for a solution by incrementing i by tPacketAlignment
	// until a value that satisfies the condition is found
	// or until the maximum value of uint is reached.
	for i <= math.MaxUint32 {
		if uint(blockSize)%i == 0 {
			return int(i), nil
		}
		i += tPacketAlignment
	}

	return 0, fmt.Errorf("no valid frame size found for capture length %d / block size %d", x, blockSize)
}

//////////////////////////////////////////////////////////////////////////////
// The following methods are currently unused but kept commented in case they
// become relevant in the future

// / -> Block Descriptor
// func (t tPacketHeader) version() uint32 {
// 	return *(*uint32)(unsafe.Pointer(&t.data[0]))
// }

// func (t tPacketHeader) privOffset() uint32 {
// 	return *(*uint32)(unsafe.Pointer(&t.data[4]))
// }

// func (t tPacketHeader) snapLen() uint32 {
// 	return *(*uint32)(unsafe.Pointer(&t.data[t.ppos+12])) // #nosec G103
// }

// func (t tPacketHeader) pktLen() uint32 {
// 	return *(*uint32)(unsafe.Pointer(&t.data[t.ppos+16])) // #nosec G103
// }

// func (t tPacketHeader) blockLen() uint32 {
// 	return *(*uint32)(unsafe.Pointer(&t.data[20]))
// }

// According to linux/if_packet.h this is aligned to an 8-byte boundary instead of 4.
// func (t tPacketHeader) seqNumber() uint64 {
// 	return *(*uint64)(unsafe.Pointer(&t.data[24]))
// }

// func (t tPacketHeader) getPacketStatus() uint32 {
// 	return *(*uint32)(unsafe.Pointer(&t.data[t.ppos+20]))
// }

// func (t tPacketHeader) setPacketStatus(status uint32) {
// 	*(*uint32)(unsafe.Pointer(&t.data[t.ppos+20])) = status
// }

// func (t tPacketHeader) mac() uint16 {
// 	return *(*uint16)(unsafe.Pointer(&t.data[t.ppos+24]))
// }

// func (t tPacketHeader) net() uint16 {
// 	return *(*uint16)(unsafe.Pointer(&t.data[t.ppos+26]))
// }

// func (t tPacketHeader) payloadNoCopyAtOffset(offset, to uint32) []byte {
// 	pos := t.ppos + uint32(*(*uint16)(unsafe.Pointer(&t.data[t.ppos+24]))) // #nosec G103
// 	return t.data[pos+offset : pos+to]
// }

// func (t tPacketHeader) payloadCopyPutAtOffset(data []byte, offset, to uint32) {
// 	pos := t.ppos + uint32(*(*uint16)(unsafe.Pointer(&t.data[t.ppos+24]))) // #nosec G103
// 	copy(data, t.data[pos+offset:pos+to])
// }
