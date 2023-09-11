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

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"github.com/fako1024/slimcap/event"
	"github.com/fako1024/slimcap/link"
	"golang.org/x/sys/unix"
)

const (
	DefaultSnapLen = (1 << 16) // DefaultSnapLen : 64 kiB
)

type ringBuffer struct {
	ring []byte

	tpReq            tPacketRequest
	curTPacketHeader *tPacketHeader
	offset           int
}

func (b *ringBuffer) nextTPacketHeader() {
	b.curTPacketHeader.data = b.ring[b.offset*int(b.tpReq.blockSize):]
}

// Source denotes an AF_PACKET capture source making use of a ring buffer
type Source struct {
	eventHandler *event.Handler

	ipLayerOffset      byte
	snapLen            int
	blockSize, nBlocks int
	isPromisc          bool
	link               *link.Link

	unblocked bool

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
	if err := src.eventHandler.Fd.SetSocketOptions(link, src.snapLen, src.isPromisc); err != nil {
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
	p := make(capture.Packet, 6+s.snapLen)
	return p
}

// NextPacket receives the next packet from the source and returns it. The operation is blocking. In
// case a non-nil "buffer" Packet is provided it will be populated with the data (and returned). The
// buffer packet can be reused. Otherwise a new Packet is allocated.
func (s *Source) NextPacket(pBuf capture.Packet) (pkt capture.Packet, err error) {

	if err = s.nextPacket(); err != nil {
		return
	}

	// If a buffer was provided, extend it to maximum capacity
	if pBuf != nil {
		pkt = pBuf[:cap(pBuf)]
	}

	// Populate the packet / buffer
	pkt = s.curTPacketHeader.packetPut(pkt, s.ipLayerOffset)

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

	// If a buffer was provided, extend it to maximum capacity
	if pBuf != nil {
		payload = pBuf[:cap(pBuf)]
	}

	// Populate the payload / buffer & parameters
	payload, pktType, pktLen = s.curTPacketHeader.payloadPut(payload, 0)

	return
}

// NextPayloadZeroCopy receives the raw payload of the next packet from the source and returns it. The operation is blocking.
// The returned payload provides direct zero-copy access to the underlying data source (e.g. a ring buffer).
func (s *Source) NextPayloadZeroCopy() (payload []byte, pktType capture.PacketType, pktLen uint32, err error) {

	if err = s.nextPacket(); err != nil {
		pktType = capture.PacketUnknown
		return
	}

	// Extract the payload (zero-copy) & parameters
	payload, pktType, pktLen = s.curTPacketHeader.payloadZeroCopy(0)

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

	// If a buffer was provided, extend it to maximum capacity
	if pBuf != nil {
		ipLayer = pBuf[:cap(pBuf)]
	}

	// Populate the IP layer / buffer & parameters
	ipLayer, pktType, pktLen = s.curTPacketHeader.payloadPut(ipLayer, s.ipLayerOffset)

	return
}

// NextIPPacketZeroCopy receives the IP layer of the next packet from the source and returns it. The operation is blocking.
// The returned IPLayer provides direct zero-copy access to the underlying data source (e.g. a ring buffer).
func (s *Source) NextIPPacketZeroCopy() (ipLayer capture.IPLayer, pktType capture.PacketType, pktLen uint32, err error) {

	if err = s.nextPacket(); err != nil {
		pktType = capture.PacketUnknown
		return
	}

	// Extract the IP layer (zero-copy) & parameters
	ipLayer, pktType, pktLen = s.curTPacketHeader.payloadZeroCopy(s.ipLayerOffset)

	return
}

// NextPacketFn executes the provided function on the next packet received on the source. If possible, the
// operation should provide a zero-copy way of interaction with the payload / metadata. All operations on the data
// must be completed prior to any subsequent call to any Next*() method.
func (s *Source) NextPacketFn(fn func(payload []byte, totalLen uint32, pktType capture.PacketType, ipLayerOffset byte) error) error {

	if err := s.nextPacket(); err != nil {
		return err
	}

	// Extract the payload (zero-copy) & parameters
	payload, pktType, pktLen := s.curTPacketHeader.payloadZeroCopy(0)

	return fn(payload, pktLen, pktType, s.ipLayerOffset)
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

func (s *Source) nextPacket() error {

	// If the current TPacketHeader does not contain any more packets (or is uninitialized)
	// fetch a new one from the ring buffer
fetch:
	if s.curTPacketHeader.data == nil || s.unblocked {
		if !s.unblocked {
			s.nextTPacketHeader()
		}
		for s.curTPacketHeader.getStatus()&unix.TP_STATUS_USER == 0 || s.unblocked {

			// Unset the bypass marker
			if s.unblocked {
				s.unblocked = false
			}

			// Run a PPOLL on the file descriptor, fetching a new block into the ring buffer
			efdHasEvent, errno := s.eventHandler.Poll(unix.POLLIN | unix.POLLERR)

			// If an event was received, ensure that the respective error is returned
			// immediately (setting the `unblocked` marker to bypass checks done before
			// upon next entry into this method)
			if efdHasEvent {
				return s.handleEvent()
			}

			// Handle errors
			if errno != 0 {
				if errno == unix.EINTR {
					continue
				}
				if errno == unix.EBADF {
					return capture.ErrCaptureStopped
				}
				return fmt.Errorf("error polling for next packet: %w (errno %d)", errno, int(errno))
			}

			// Handle rare cases of runaway packets
			if s.curTPacketHeader.getStatus()&unix.TP_STATUS_COPY != 0 {
				s.curTPacketHeader.setStatus(unix.TP_STATUS_KERNEL)
				s.offset = (s.offset + 1) % int(s.tpReq.blockNr)
				s.nextTPacketHeader()

				continue
			}
		}

		// After fetching a new TPacketHeader, set the position of the first packet and the number of packets
		// in this TPacketHeader
		s.curTPacketHeader.ppos = s.curTPacketHeader.offsetToFirstPkt()
		s.curTPacketHeader.nPktsLeft = s.curTPacketHeader.nPkts()
	} else {

		// If there is no next offset, release the TPacketHeader to the kernel and fetch a new one
		nextPos := s.curTPacketHeader.nextOffset()
		if s.curTPacketHeader.nPktsLeft == 0 {
			s.curTPacketHeader.setStatus(unix.TP_STATUS_KERNEL)
			s.offset = (s.offset + 1) % int(s.tpReq.blockNr)
			s.curTPacketHeader.data = nil
			goto fetch
		}

		// Update position of next packet
		s.curTPacketHeader.ppos += nextPos
	}

	s.curTPacketHeader.nPktsLeft--

	// Apply filter (if any)
	if filter := s.link.FilterMask(); filter > 0 && filter&s.curTPacketHeader.packetType() != 0 {
		goto fetch
	}

	return nil
}

func (s *Source) handleEvent() error {

	// Read event data / type from the eventFD
	efdData, err := s.eventHandler.Efd.ReadEvent()
	if err != nil {
		return fmt.Errorf("error reading event: %w", err)
	}

	// Set the bypass marker to allow for re-entry in nextPacket() where we left off if
	// required (e.g. on ErrCaptureUnblock)
	s.unblocked = true
	if efdData[7] > 0 {
		return capture.ErrCaptureStopped
	}
	return capture.ErrCaptureUnblocked
}

func setupRingBuffer(sd socket.FileDescriptor, tPacketReq tPacketRequest) ([]byte, event.EvtFileDescriptor, error) {

	if !sd.IsOpen() {
		return nil, -1, errors.New("invalid socket")
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
