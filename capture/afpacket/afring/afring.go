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
	DefaultSnapLen = (1 << 16) // 64 kiB
)

type ringBuffer struct {
	ring []byte

	tpReq            tPacketRequest
	curTPacketHeader *tPacketHeader
	offset           int
}

func (b *ringBuffer) nextTPacketHeader() *tPacketHeader {
	return &tPacketHeader{data: b.ring[b.offset*int(b.tpReq.blockSize):]}
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
		return nil, fmt.Errorf("failed to set up link on %s: %s", iface, err)
	}

	return NewSourceFromLink(link, options...)
}

// NewSourceFromLink instantiates a new AF_PACKET capture source making use of a ring buffer
// taking an existing link instance
func NewSourceFromLink(link *link.Link, options ...Option) (*Source, error) {

	// Fail if link is not up
	if !link.IsUp() {
		return nil, fmt.Errorf("link %s is not up", link.Name)
	}

	// Define new source
	src := &Source{
		eventHandler:  new(event.Handler),
		snapLen:       DefaultSnapLen,
		blockSize:     tPacketDefaultBlockSize,
		nBlocks:       tPacketDefaultBlockNr,
		ipLayerOffset: link.Type.IpHeaderOffset(),
		link:          link,
		Mutex:         sync.Mutex{},
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

// NewPacket creates an empty "buffer" package to be used as destination for the NextPacketInto()
// method. It ensures that a valid packet of appropriate structure / length is created
func (s *Source) NewPacket() capture.Packet {
	p := make(capture.Packet, 6+s.snapLen)
	return p
}

// NextPacket receives the next packet from the wire and returns it. The operation is blocking. In
// case a non-nil "buffer" Packet is provided it will be populated with the data (and returned). The
// buffer packet can be reused. Otherwise a new Packet of the Source-specific type is allocated.
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
	s.curTPacketHeader.payloadCopyPut(data[6:])
	if snapLen+capture.PacketHdrOffset < len(data) {
		data = data[:capture.PacketHdrOffset+snapLen]
	}

	return data, nil
}

// NextIPPacketFn executes the provided function on the next packet received on the wire and only
// return the ring buffer block to the kernel upon completion of the function. If possible, the
// operation should provide a zero-copy way of interaction with the payload / metadata.
func (s *Source) NextPacketFn(fn func(payload []byte, totalLen uint32, pktType capture.PacketType, ipLayerOffset byte) error) error {

	if err := s.nextPacket(); err != nil {
		return err
	}

	return fn(s.curTPacketHeader.payloadNoCopy(), s.curTPacketHeader.pktLen(), s.curTPacketHeader.packetType(), s.ipLayerOffset)
}

// NextIPPacket receives the next packet's IP layer from the wire and returns it. The operation is blocking.
// In case a non-nil "buffer" IPLayer is provided it will be populated with the data (and returned). The
// buffer packet can be reused. Otherwise a new IPLayer is allocated.
func (s *Source) NextIPPacket(pBuf capture.IPLayer) (capture.IPLayer, capture.PacketType, uint32, error) {

	if err := s.nextPacket(); err != nil {
		return nil, 0, 0, err
	}
	var (
		data    capture.IPLayer
		snapLen = int(s.curTPacketHeader.snapLen()) - int(s.ipLayerOffset)
	)

	// If a buffer was provided, et the correct length of the buffer and populate it
	// Otherwise, allocate a new IPLayer
	if pBuf != nil {
		data = pBuf[:cap(pBuf)]
	} else {
		data = make(capture.IPLayer, snapLen)
	}

	// Populate the packet
	s.curTPacketHeader.payloadCopyPutAtOffset(data, uint32(s.ipLayerOffset))
	if snapLen < len(data) {
		data = data[:snapLen]
	}

	return data, s.curTPacketHeader.packetType(), s.curTPacketHeader.pktLen(), nil
}

// Stats returns (and clears) the packet counters of the underlying socket
func (s *Source) Stats() (capture.Stats, error) {
	s.Lock()
	defer s.Unlock()

	ss, err := s.eventHandler.GetSocketStats()
	if err != nil {
		return capture.Stats{}, err
	}
	return capture.Stats{
		PacketsReceived: int(ss.Packets),
		PacketsDropped:  int(ss.Drops),
		QueueFreezes:    int(ss.QueueFreezes),
	}, nil
}

// Unblock ensures that a potentially ongoing blocking PPOLL is released (returning an ErrCaptureUnblock)
func (s *Source) Unblock() error {
	if s == nil || s.eventHandler.Efd < 0 || s.eventHandler.Fd < 0 {
		return errors.New("cannot call Unblock() on nil / closed capture source")
	}

	return s.eventHandler.Efd.Signal(event.SignalUnblock)
}

// Close stops / closes the capture source
func (s *Source) Close() error {
	if s == nil || s.eventHandler.Efd < 0 || s.eventHandler.Fd < 0 {
		return errors.New("cannot call Close() on nil / closed capture source")
	}

	if err := s.eventHandler.Efd.Signal(event.SignalStop); err != nil {
		return err
	}

	if err := s.eventHandler.Fd.Close(); err != nil {
		return err
	}

	s.eventHandler.Fd = -1

	return nil
}

// Free releases any pending resources from the capture source (must be called after Close())
func (s *Source) Free() error {
	if s == nil {
		return errors.New("cannot call Free() on nil capture source")
	}
	if s.eventHandler.Fd >= 0 {
		return errors.New("cannot call Free() on open capture source, call Close() first")
	}

	if s.ring != nil {
		return unix.Munmap(s.ring)
	}

	return nil
}

// Link returns the underlying link
func (s *Source) Link() *link.Link {
	return s.link
}

func (s *Source) nextPacket() error {

	// If the socket is invalid the capture is obviously closed and we return the respective
	// error
	if s.eventHandler.Fd < 0 {
		return capture.ErrCaptureStopped
	}

	// If the current TPacketHeader does not contain any more packets (or is uninitialized)
	// fetch a new one from the ring buffer
fetch:
	if s.curTPacketHeader == nil || s.unblocked {
		if !s.unblocked {
			s.curTPacketHeader = s.nextTPacketHeader()
		}
		for s.curTPacketHeader.getStatus()&unix.TP_STATUS_USER == 0 || s.unblocked {

			// Unset the bypass marker
			if s.unblocked {
				s.unblocked = false
			}

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
				return fmt.Errorf("error polling for next packet: %d", errno)
			}

			// Handle rare cases of runaway packets
			if s.curTPacketHeader.getStatus()&tPacketStatusCopy != 0 {
				if s.curTPacketHeader.nPktsUsed != s.curTPacketHeader.nPkts() {
					fmt.Println(s.link.Name, "WUT (after runaway packet)?", s.curTPacketHeader.nPktsUsed, s.curTPacketHeader.nPkts())
				}
				s.curTPacketHeader.setStatus(tPacketStatusKernel)
				s.offset = (s.offset + 1) % int(s.tpReq.frameNr)
				s.curTPacketHeader = s.nextTPacketHeader()

				continue
			}
		}

		// After fetching a new TPacketHeader, set the position of the first packet
		s.curTPacketHeader.ppos = s.curTPacketHeader.offsetToFirstPkt()
	} else {

		// If there is no next offset, release the TPacketHeader to the kernel and fetch a new one
		nextPos := s.curTPacketHeader.nextOffset()
		if s.curTPacketHeader.nPktsUsed == s.curTPacketHeader.nPkts() {
			if nextPos != 0 {
				fmt.Println(s.link.Name, "WUT (after resetting)?", s.curTPacketHeader.nPktsUsed, s.curTPacketHeader.nPkts(), nextPos)
			}
			s.curTPacketHeader.setStatus(tPacketStatusKernel)
			s.offset = (s.offset + 1) % int(s.tpReq.blockNr)
			s.curTPacketHeader = nil
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
		fmt.Println(s.link.Name, "skipping empty TPacketHeader, please check if anything weird is happening in your application !!! Info:", s.curTPacketHeader.ppos, "/", s.tpReq.blockSize, s.curTPacketHeader.mac(), s.curTPacketHeader.packetType(), s.curTPacketHeader.nextOffset())
		goto fetch
	}

	s.curTPacketHeader.nPktsUsed++
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
	switch efdData {
	case event.SignalUnblock:
		return capture.ErrCaptureUnblock
	case event.SignalStop:
		return capture.ErrCaptureStopped
	default:
		return fmt.Errorf("unknown event during poll for next packet: %v", efdData)
	}
}

func setupRingBuffer(sd socket.FileDescriptor, tPacketReq tPacketRequest) ([]byte, event.EvtFileDescriptor, error) {

	if sd <= 0 {
		return nil, -1, errors.New("invalid socket")
	}

	// Setup event file descriptor used for stopping / unblocking the capture (we start with that to avoid
	// having to clean up the ring buffer in case the decriptor can't be created
	eventFD, err := event.New()
	if err != nil {
		return nil, -1, fmt.Errorf("failed to setup event file descriptor: %w", err)
	}

	// Set socket option to use PACKET_RX_RING
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
