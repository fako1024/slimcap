//go:build linux
// +build linux

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
		src.eventHandler.Fd.Close()
		return nil, fmt.Errorf("failed to setup AF_PACKET mmap'ed ring buffer %s: %w", link.Name, err)
	}

	// Clear socket stats
	if _, err := src.eventHandler.Fd.GetSocketStats(); err != nil {
		src.eventHandler.Fd.Close()
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
func (s *Source) NextPacket(pBuf capture.Packet) (capture.Packet, error) {

	if err := s.nextPacket(); err != nil {
		return nil, err
	}
	var (
		data    capture.Packet
		snapLen = int(s.curTPacketHeader.snapLen())
	)

	// If a buffer was provided, et the correct length of the buffer and populate it
	// Otherwise, allocate a new Packet
	if pBuf != nil {
		data = pBuf[:cap(pBuf)]
	} else {
		data = make(capture.Packet, capture.PacketHdrOffset+snapLen)
	}

	// Populate the packet
	data[0] = s.curTPacketHeader.packetType()
	data[1] = s.ipLayerOffset
	s.curTPacketHeader.pktLenPut(data[2:6])
	s.curTPacketHeader.payloadCopyPutAtOffset(data[6:], 0, uint32(snapLen))
	if snapLen+capture.PacketHdrOffset < len(data) {
		data = data[:capture.PacketHdrOffset+snapLen]
	}

	return data, nil
}

// NextPayload receives the raw payload of the next packet from the source and returns it. The operation is blocking.
// In case a non-nil "buffer" byte slice / payload is provided it will be populated with the data (and returned).
// The buffer can be reused. Otherwise a new byte slice / payload is allocated.
func (s *Source) NextPayload(pBuf []byte) ([]byte, capture.PacketType, uint32, error) {

	if err := s.nextPacket(); err != nil {
		return nil, capture.PacketUnknown, 0, err
	}
	var (
		data    []byte
		snapLen = s.curTPacketHeader.snapLen()
	)

	// If a buffer was provided, et the correct length of the buffer and populate it
	// Otherwise, allocate a new byte slice - then populate the packet
	if pBuf != nil {
		data = s.curTPacketHeader.payloadNoCopyAtOffset(0, snapLen)
	} else {
		data = make([]byte, snapLen)
		s.curTPacketHeader.payloadCopyPutAtOffset(data, 0, snapLen)
	}

	if int(snapLen) < len(data) {
		data = data[:snapLen]
	}

	return data, s.curTPacketHeader.packetType(), s.curTPacketHeader.pktLen(), nil
}

// NextPayloadZeroCopy receives the raw payload of the next packet from the source and returns it. The operation is blocking.
// The returned payload provides direct zero-copy access to the underlying data source (e.g. a ring buffer).
func (s *Source) NextPayloadZeroCopy() ([]byte, capture.PacketType, uint32, error) {

	if err := s.nextPacket(); err != nil {
		return nil, capture.PacketUnknown, 0, err
	}

	return s.curTPacketHeader.payloadNoCopyAtOffset(0, s.curTPacketHeader.snapLen()),
		s.curTPacketHeader.packetType(),
		s.curTPacketHeader.pktLen(),
		nil
}

// NextIPPacket receives the IP layer of the next packet from the source and returns it. The operation is blocking.
// In case a non-nil "buffer" IPLayer is provided it will be populated with the data (and returned).
// The buffer can be reused. Otherwise a new IPLayer is allocated.
func (s *Source) NextIPPacket(pBuf capture.IPLayer) (capture.IPLayer, capture.PacketType, uint32, error) {

	if err := s.nextPacket(); err != nil {
		return nil, capture.PacketUnknown, 0, err
	}
	var (
		data    capture.IPLayer
		snapLen = s.curTPacketHeader.snapLen()
	)

	// If a buffer was provided, et the correct length of the buffer and populate it
	// Otherwise, allocate a new IPLayer
	if pBuf != nil {
		data = pBuf[:cap(pBuf)]
	} else {
		data = make(capture.IPLayer, snapLen)
	}

	// Populate the packet
	s.curTPacketHeader.payloadCopyPutAtOffset(data, uint32(s.ipLayerOffset), snapLen)
	if ipLayerSnaplen := snapLen - uint32(s.ipLayerOffset); int(ipLayerSnaplen) < len(data) {
		data = data[:ipLayerSnaplen]
	}

	return data, s.curTPacketHeader.packetType(), s.curTPacketHeader.pktLen(), nil
}

// NextIPPacketZeroCopy receives the IP layer of the next packet from the source and returns it. The operation is blocking.
// The returned IPLayer provides direct zero-copy access to the underlying data source (e.g. a ring buffer).
func (s *Source) NextIPPacketZeroCopy() (capture.IPLayer, capture.PacketType, uint32, error) {

	if err := s.nextPacket(); err != nil {
		return nil, capture.PacketUnknown, 0, err
	}

	return s.curTPacketHeader.payloadNoCopyAtOffset(uint32(s.ipLayerOffset), s.curTPacketHeader.snapLen()),
		s.curTPacketHeader.packetType(),
		s.curTPacketHeader.pktLen(),
		nil
}

// NextPacketFn executes the provided function on the next packet received on the source. If possible, the
// operation should provide a zero-copy way of interaction with the payload / metadata. All operations on the data
// must be completed prior to any subsequent call to any Next*() method.
func (s *Source) NextPacketFn(fn func(payload []byte, totalLen uint32, pktType capture.PacketType, ipLayerOffset byte) error) error {

	if err := s.nextPacket(); err != nil {
		return err
	}

	return fn(s.curTPacketHeader.payloadNoCopyAtOffset(0, s.curTPacketHeader.snapLen()),
		s.curTPacketHeader.pktLen(),
		s.curTPacketHeader.packetType(),
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
	if err := s.eventHandler.Fd.Close(); err != nil {
		return err
	}

	return nil
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
				return fmt.Errorf("error polling for next packet: %w (errno %d)", errno, errno)
			}

			// Handle rare cases of runaway packets
			if s.curTPacketHeader.getStatus()&unix.TP_STATUS_COPY != 0 {
				if s.curTPacketHeader.nPktsLeft != 0 {
					fmt.Println(s.link.Name, "WUT (after runaway packet)?", s.curTPacketHeader.nPktsLeft)
				}
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
			if nextPos != 0 {
				fmt.Println(s.link.Name, "WUT (after resetting)?", s.curTPacketHeader.nPktsLeft, nextPos)
			}
			s.curTPacketHeader.setStatus(unix.TP_STATUS_KERNEL)
			s.offset = (s.offset + 1) % int(s.tpReq.blockNr)
			s.curTPacketHeader.data = nil
			goto fetch
		}

		// Update position of next packet
		if nextPos > 9000 {
			fmt.Println(s.link.Name, "unexpectedly large next pos, will probably fail horribly", nextPos)
		}
		s.curTPacketHeader.ppos += nextPos
	}

	if s.curTPacketHeader.ppos > s.tpReq.blockSize {
		fmt.Println(s.link.Name, "exceeding block size")
	}

	if s.curTPacketHeader.pktLen() == 0 {
		fmt.Println(s.link.Name, "skipping empty TPacketHeader, please check if anything weird is happening in your application !!! Info:", s.curTPacketHeader.ppos, "/", s.tpReq.blockSize, *(*uint16)(unsafe.Pointer(&s.curTPacketHeader.data[s.curTPacketHeader.ppos+24])), s.curTPacketHeader.packetType(), s.curTPacketHeader.nextOffset())
		goto fetch
	}

	s.curTPacketHeader.nPktsLeft--
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
