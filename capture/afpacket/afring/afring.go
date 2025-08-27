//go:build linux
// +build linux

/*
Package afring implements a capture.Source and a capture.SourceZeroCopy that allows reading
network packets from Linux network interfaces via the AF_PACKET / TPacket ring buffer mechanism.
This implementation relies on performing optimized `PPOLL()` syscalls to the MMAP'ed socket to
fetch blocks of packets. The ring buffer is configurable (depending on the expected throughput).
This capture method is optimally suited for production-level packet capture since it achieves
blazing-fast capture rates (in particular in zero-copy mode).
*/
package afring

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/fako1024/gotools/link"
	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"github.com/fako1024/slimcap/event"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	DefaultSnapLen = (1 << 16) // DefaultSnapLen : 64 kiB
)

// Source denotes an AF_PACKET capture source making use of a ring buffer
type Source struct {
	eventHandler *event.Handler

	ipLayerOffset      byte
	snapLen            int
	blockSize, nBlocks int
	isPromisc          bool
	ignoreVLANs        bool
	link               *link.Link

	ipLayerOffsetNum uint32
	extraBPFInstr    []bpf.RawInstruction

	ringBuffer
	sync.Mutex
}

// NewSource instantiates a new AF_PACKET capture source making use of a ring buffer
func NewSource(iface string, options ...Option) (*Source, error) {

	if iface == "" {
		return nil, errors.New("no interface provided")
	}
	link, err := link.New(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to set up link on %s: %w", iface, err)
	}

	return NewSourceFromLink(link, options...)
}

// NewSourceFromLink instantiates a new AF_PACKET capture source making use of a ring buffer
// taking an existing link instance
func NewSourceFromLink(link *link.Link, options ...Option) (*Source, error) {

	// Fail if link is not up
	if isUp, err := link.IsUp(); err != nil || !isUp {
		return nil, fmt.Errorf("link %s is not up", link.Name)
	}

	// Define new source
	src := &Source{
		eventHandler:  new(event.Handler),
		snapLen:       DefaultSnapLen,
		blockSize:     tPacketDefaultBlockSize,
		nBlocks:       tPacketDefaultBlockNr,
		ipLayerOffset: link.Type.IPHeaderOffset(),
		link:          link,
	}
	src.ipLayerOffsetNum = uint32(src.ipLayerOffset)

	for _, opt := range options {
		opt(src)
	}

	// Define a new TPacket request
	var err error
	src.ringBuffer.tpReq, err = newTPacketRequestForBuffer(src.blockSize, src.nBlocks, src.snapLen)
	if err != nil {
		return nil, fmt.Errorf("failed to setup TPacket request on %s: %w", link.Name, err)
	}

	// Setup socket
	src.eventHandler.Fd, err = socket.New(link)
	if err != nil {
		return nil, fmt.Errorf("failed to setup AF_PACKET socket on %s: %w", link.Name, err)
	}

	// Set socket options
	if err := src.eventHandler.Fd.SetSocketOptions(link, src.snapLen, src.isPromisc, src.ignoreVLANs, src.extraBPFInstr...); err != nil {
		return nil, fmt.Errorf("failed to set AF_PACKET socket options on %s: %w", link.Name, err)
	}

	// Setup ring buffer
	src.ringBuffer.curTPacketHeader = new(tPacketHeader)
	src.ringBuffer.ring, src.eventHandler.Efd, err = setupRingBuffer(src.eventHandler.Fd, src.tpReq)
	if err != nil {
		_ = src.eventHandler.Fd.Close()
		return nil, fmt.Errorf("failed to setup AF_PACKET mmap'ed ring buffer on %s: %w", link.Name, err)
	}

	// Clear socket stats
	if _, err := src.eventHandler.Fd.GetSocketStats(); err != nil {
		_ = src.eventHandler.Fd.Close()
		return nil, fmt.Errorf("failed to clear AF_PACKET socket stats on %s: %w", link.Name, err)
	}

	return src, nil
}

// NewPacket creates an empty "buffer" packet to be used as destination for the NextPacket() / NextPayload() /
// NextIPPacket() methods (the latter two by calling .Payload() / .IPLayer() on the created buffer). It ensures
// that a valid packet of appropriate structure / length is created
func (s *Source) NewPacket() capture.Packet {
	p := make(capture.Packet, capture.PacketHdrOffset+s.snapLen)
	return p
}

// NextPacket receives the next packet from the source and returns it. The operation is blocking. In
// case a non-nil "buffer" Packet is provided it will be populated with the data (and returned). The
// buffer packet can be reused. Otherwise a new Packet is allocated.
func (s *Source) NextPacket(pBuf capture.Packet) (pkt capture.Packet, err error) {

	if err = s.nextPacket(); err != nil {
		return
	}

	pktHdr := s.curTPacketHeader

	// Parse the V3 TPacketHeader, the first byte of the payload and snaplen
	hdr := pktHdr.parseHeader()
	pos := pktHdr.ppos + uint32(hdr.pktMac)
	effectiveSnapLen := capture.PacketHdrOffset + int(hdr.snaplen)

	// If a buffer was provided, extend it to maximum capacity
	if pBuf == nil {

		// Allocate new capture.Packet if no buffer was provided
		pkt = make(capture.Packet, effectiveSnapLen)
	} else {
		pkt = pBuf[:cap(pBuf)]
	}

	// Extract / copy all required data / header parameters
	pktHdr.pktLenCopy(pkt[2:capture.PacketHdrOffset])
	pkt[0] = pktHdr.data[pktHdr.ppos+58]
	pkt[1] = s.ipLayerOffset
	copy(pkt[capture.PacketHdrOffset:], pktHdr.data[pos:pos+hdr.snaplen])

	// Ensure correct packet length
	if effectiveSnapLen < len(pkt) {
		pkt = pkt[:effectiveSnapLen]
	}

	return
}

// NextPayload receives the raw payload of the next packet from the source and returns it. The operation is blocking.
// In case a non-nil "buffer" byte slice / payload is provided it will be populated with the data (and returned).
// The buffer can be reused. Otherwise a new byte slice / payload is allocated.
func (s *Source) NextPayload(pBuf []byte) (payload []byte, pktType capture.PacketType, pktLen uint32, err error) {

	if err = s.nextPacket(); err != nil {
		pktType = capture.PacketUnknown
		return
	}

	pktHdr := s.curTPacketHeader

	// Parse the V3 TPacketHeader, the first byte of the payload and snaplen
	hdr := pktHdr.parseHeader()
	pos := pktHdr.ppos + uint32(hdr.pktMac)
	snapLen := int(hdr.snaplen)

	// If a buffer was provided, extend it to maximum capacity
	if pBuf != nil {
		payload = pBuf[:cap(pBuf)]
	} else {

		// Allocate new capture.Packet if no buffer was provided
		payload = make([]byte, snapLen)
	}

	// Copy payload / IP layer
	copy(payload, pktHdr.data[pos:pos+hdr.snaplen])

	// Ensure correct data length
	if snapLen < len(payload) {
		payload = payload[:snapLen]
	}

	// Populate the payload / buffer & parameters
	pktType, pktLen = pktHdr.data[pktHdr.ppos+58], hdr.pktLen

	return
}

// NextIPPacket receives the IP layer of the next packet from the source and returns it. The operation is blocking.
// In case a non-nil "buffer" IPLayer is provided it will be populated with the data (and returned).
// The buffer can be reused. Otherwise a new IPLayer is allocated.
func (s *Source) NextIPPacket(pBuf capture.IPLayer) (ipLayer capture.IPLayer, pktType capture.PacketType, pktLen uint32, err error) {

	if err = s.nextPacket(); err != nil {
		pktType = capture.PacketUnknown
		return
	}

	pktHdr := s.curTPacketHeader

	// Parse the V3 TPacketHeader and the first byte of the payload
	hdr := pktHdr.parseHeader()
	pos := pktHdr.ppos + uint32(hdr.pktNet)

	// Adjust effective snaplen (subtracting any potential mac layer)
	effectiveSnapLen := hdr.snaplen
	if s.ipLayerOffsetNum > 0 {
		effectiveSnapLen -= s.ipLayerOffsetNum
	}
	snapLen := int(effectiveSnapLen)

	// If a buffer was provided, extend it to maximum capacity
	if pBuf != nil {
		ipLayer = pBuf[:cap(pBuf)]
	} else {

		// Allocate new capture.Packet if no buffer was provided
		ipLayer = make([]byte, snapLen)
	}

	// Copy payload / IP layer
	copy(ipLayer, pktHdr.data[pos:pos+effectiveSnapLen])

	// Ensure correct data length
	if snapLen < len(ipLayer) {
		ipLayer = ipLayer[:snapLen]
	}

	// Populate the payload / buffer & parameters
	pktType, pktLen = pktHdr.data[pktHdr.ppos+58], hdr.pktLen

	return
}

// NextPacketFn executes the provided function on the next packet received on the source. If possible, the
// operation should provide a zero-copy way of interaction with the payload / metadata. All operations on the data
// must be completed prior to any subsequent call to any Next*() method.
func (s *Source) NextPacketFn(fn func(payload []byte, totalLen uint32, pktType capture.PacketType, ipLayerOffset byte) error) error {

	if err := s.nextPacket(); err != nil {
		return err
	}

	pktHdr := s.curTPacketHeader

	// Parse the V3 TPacketHeader and the first byte of the payload
	hdr := pktHdr.parseHeader()
	pos := pktHdr.ppos + uint32(hdr.pktMac)

	// #nosec G103
	return fn(unsafe.Slice(&pktHdr.data[pos], hdr.snaplen),
		hdr.pktLen,
		pktHdr.data[pktHdr.ppos+58],
		s.ipLayerOffset)
}

// Stats returns (and clears) the packet counters of the underlying source
func (s *Source) Stats() (capture.Stats, error) {

	s.Lock()
	ss, err := s.eventHandler.GetSocketStats()
	s.Unlock()

	if err != nil {
		return capture.Stats{}, err
	}
	return capture.Stats{
		PacketsReceived: uint64(ss.Packets),
		PacketsDropped:  uint64(ss.Drops),
		QueueFreezes:    uint64(ss.QueueFreezes),
	}, nil
}

// Unblock ensures that a potentially ongoing blocking poll operation is released (returning an ErrCaptureUnblock from
// any potentially ongoing call to Next*() that might currently be blocked)
func (s *Source) Unblock() error {
	if s == nil || s.eventHandler.Efd < 0 || !s.eventHandler.Fd.IsOpen() {
		return errors.New("cannot call Unblock() on nil / closed capture source")
	}

	return s.eventHandler.Efd.Signal(event.SignalUnblock)
}

// Close stops / closes the capture source
func (s *Source) Close() error {
	return s.closeAndUnmap()
}

func (s *Source) close() error {
	if s == nil || s.eventHandler.Efd < 0 || !s.eventHandler.Fd.IsOpen() {
		return errors.New("cannot call Close() on nil / closed capture source")
	}

	// Close file / event descriptors
	if err := s.eventHandler.Efd.Signal(event.SignalStop); err != nil {
		return err
	}

	return s.eventHandler.Fd.Close()
}

func (s *Source) closeAndUnmap() error {
	if err := s.close(); err != nil {
		return err
	}

	return unix.Munmap(s.ring)
}

// Link returns the underlying link
func (s *Source) Link() *link.Link {
	return s.link
}

// nextPacket provides access to the next packet from either the current block or advances to the next
// one (fetching its first packet).
func (s *Source) nextPacket() error {

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
			return nil
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
			return s.handleEvent()
		}

		// Handle potential PPOLL errors
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return handlePollError(errno)
		}

		// Handle rare cases of runaway packets (this call will advance to the next block
		// as a side effect in case of a detection)
		if s.hasRunawayBlock() {
			continue
		}
	}

	// Set the position of the first packet in this block and jump to end
	pktHdr.ppos = pktHdr.offsetToFirstPkt()

	return nil
}

func (s *Source) handleEvent() error {

	// Read event data / type from the eventFD
	efdData, err := s.eventHandler.Efd.ReadEvent()
	if err != nil {
		return fmt.Errorf("error reading event: %w", err)
	}

	// Unset the current block data to allow for re-entry in nextPacket[ZeroCopy]() where we left off if
	// required (e.g. on ErrCaptureUnblock)
	s.curTPacketHeader.data = nil

	if efdData[7] > 0 {
		return capture.ErrCaptureStopped
	}
	return capture.ErrCaptureUnblocked
}

func setupRingBuffer(sd socket.FileDescriptor, tPacketReq tPacketRequest) ([]byte, event.EvtFileDescriptor, error) {

	if !sd.IsOpen() {
		return nil, -1, socket.ErrInvalidSocket
	}

	// Setup event file descriptor used for stopping / unblocking the capture (we start with that to avoid
	// having to clean up the ring buffer in case the decriptor can't be created
	eventFD, err := event.New()
	if err != nil {
		return nil, -1, fmt.Errorf("failed to setup event file descriptor: %w", err)
	}

	// Set socket option to use PACKET_RX_RING
	// #nosec G103
	if err := sd.SetupRingBuffer(unsafe.Pointer(&tPacketReq), unsafe.Sizeof(tPacketReq)); err != nil {
		return nil, -1, fmt.Errorf("failed to call ring buffer instruction: %w", err)
	}

	// Setup memory mapping
	buf, err := unix.Mmap(int(sd), 0, tPacketReq.blockSizeNr(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, -1, fmt.Errorf("failed to set up mmap ring buffer: %w", err)
	}
	if buf == nil {
		return nil, -1, fmt.Errorf("mmap ring buffer is nil (error: %w)", err)
	}

	return buf, eventFD, nil
}

func handlePollError(errno unix.Errno) error {
	if errno == unix.EBADF {
		return capture.ErrCaptureStopped
	}
	return fmt.Errorf("error polling for next packet: %w (errno %d)", errno, int(errno))
}
