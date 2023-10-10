package afring

import (
	"unsafe"

	"github.com/fako1024/slimcap/capture"
	"golang.org/x/sys/unix"
)

// NextPayloadZeroCopy receives the raw payload of the next packet from the source and returns it. The operation is blocking.
// The returned payload provides direct zero-copy access to the underlying data source (e.g. a ring buffer).
// Procedurally, the method extracts the next packet from either the current block or advances to the next
// one (fetching / returning its first packet).
func (s *Source) NextPayloadZeroCopy() (payload []byte, pktType capture.PacketType, pktLen uint32, err error) {

	pktHdr := s.curTPacketHeader

	// If there is an active block, attempt to simply consume a packet from it
	if pktHdr.data != nil {

		// If there are more packets remaining (i.e. there is a non-zero next offset), advance
		// the current position.
		// According to https://github.com/torvalds/linux/blame/master/net/packet/af_packet.c#L811 the
		// tp_next_offset field is guaranteed to be zero for the final packet of the block. In addition,
		// it cannot be zero otherwise (because that would be an invalid block).
		if nextPos := pktHdr.nextOffset(); nextPos != 0 {

			// Update position of next packet and jump to the end
			pktHdr.ppos += nextPos
			goto finalize
		}

		// If there is no next offset, release the TPacketHeader to the kernel and move on to the next block
		s.releaseAndAdvance()
	}

	// Load the data for the block
	s.loadTPacketHeader()

	// Check if the block is free to access in userland
	for pktHdr.getStatus()&unix.TP_STATUS_USER == 0 {

		// Run a PPOLL on the file descriptor (waiting for the block to become available)
		efdHasEvent, errno := s.eventHandler.Poll(unix.POLLIN | unix.POLLERR)

		// If an event was received, ensure that the respective error / code is returned
		// immediately
		if efdHasEvent {
			pktType, err = capture.PacketUnknown, s.handleEvent()
			return
		}

		// Handle potential PPOLL errors
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			pktType, err = capture.PacketUnknown, handlePollError(errno)
			return
		}

		// Handle rare cases of runaway packets (this call will advance to the next block
		// as a side effect in case of a detection)
		if s.hasRunawayBlock() {
			continue
		}
	}

	// Set the position of the first packet in this block and jump to end
	pktHdr.ppos = pktHdr.offsetToFirstPkt()

finalize:

	// Parse the V3 TPacketHeader and the first byte of the payload
	hdr := pktHdr.parseHeader()
	pos := pktHdr.ppos + uint32(hdr.pktMac)

	// Return the payload / IP layer subslice & heeader parameters
	return unsafe.Slice(&pktHdr.data[pos], hdr.snaplen),
		pktHdr.data[pktHdr.ppos+58],
		hdr.pktLen, nil
}

// NextIPPacketZeroCopy receives the IP layer of the next packet from the source and returns it. The operation is blocking.
// The returned IPLayer provides direct zero-copy access to the underlying data source (e.g. a ring buffer).
// Procedurally, the method extracts the next packet from either the current block or advances to the next
// one (fetching / returning its first packet IP layer).
func (s *Source) NextIPPacketZeroCopy() (ipLayer capture.IPLayer, pktType capture.PacketType, pktLen uint32, err error) {

	pktHdr := s.curTPacketHeader

	// If there is an active block, attempt to simply consume a packet from it
	if pktHdr.data != nil {

		// If there are more packets remaining (i.e. there is a non-zero next offset), advance
		// the current position.
		// According to https://github.com/torvalds/linux/blame/master/net/packet/af_packet.c#L811 the
		// tp_next_offset field is guaranteed to be zero for the final packet of the block. In addition,
		// it cannot be zero otherwise (because that would be an invalid block).
		if nextPos := pktHdr.nextOffset(); nextPos != 0 {

			// Update position of next packet and jump to the end
			pktHdr.ppos += nextPos
			goto finalize
		}

		// If there is no next offset, release the TPacketHeader to the kernel and move on to the next block
		s.releaseAndAdvance()
	}

	// Load the data for the block
	s.loadTPacketHeader()

	// Check if the block is free to access in userland
	for pktHdr.getStatus()&unix.TP_STATUS_USER == 0 {

		// Run a PPOLL on the file descriptor (waiting for the block to become available)
		efdHasEvent, errno := s.eventHandler.Poll(unix.POLLIN | unix.POLLERR)

		// If an event was received, ensure that the respective error / code is returned
		// immediately
		if efdHasEvent {
			pktType, err = capture.PacketUnknown, s.handleEvent()
			return
		}

		// Handle potential PPOLL errors
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			pktType, err = capture.PacketUnknown, handlePollError(errno)
			return
		}

		// Handle rare cases of runaway packets (this call will advance to the next block
		// as a side effect in case of a detection)
		if s.hasRunawayBlock() {
			continue
		}
	}

	// Set the position of the first packet in this block and jump to end
	pktHdr.ppos = pktHdr.offsetToFirstPkt()

finalize:

	// Parse the V3 TPacketHeader and the first byte of the payload
	hdr := pktHdr.parseHeader()
	pos := pktHdr.ppos + uint32(hdr.pktNet)

	// Extract the payload (zero-copy) & parameters
	return unsafe.Slice(&pktHdr.data[pos], hdr.snaplen-s.ipLayerOffsetNum),
		pktHdr.data[pktHdr.ppos+58],
		hdr.pktLen, nil
}
