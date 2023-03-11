package afpacket

import (
	"errors"
	"fmt"
	"sync"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/event"
	"github.com/fako1024/slimcap/link"
	"golang.org/x/sys/unix"
)

const (
	tPacketVersion = unix.TPACKET_V3
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

// RingBufSource denotes an AF_PACKET capture source making use of a ring buffer
type RingBufSource struct {
	socketFD event.FileDescriptor
	eventFD  event.EvtFileDescriptor

	ipLayerOffset      byte
	snapLen            int
	blockSize, nBlocks int
	isPromisc          bool
	link               *link.Link

	ringBuffer

	sync.Mutex
}

// NewRingBufSource instantiates a new AF_PACKET capture source making use of a ring buffer
func NewRingBufSource(iface string, options ...Option) (*RingBufSource, error) {

	if iface == "" {
		return nil, errors.New("no interface provided")
	}
	link, err := link.New(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to set up link on %s: %s", iface, err)
	}

	return NewRingBufSourceFromLink(link, options...)
}

// NewRingBufSourceFromLink instantiates a new AF_PACKET capture source making use of a ring buffer
// taking an existing link instance
func NewRingBufSourceFromLink(link *link.Link, options ...Option) (*RingBufSource, error) {

	// Fail if link is not up
	if !link.IsUp() {
		return nil, fmt.Errorf("link %s is not up", link.Name)
	}

	// Define new source
	src := &RingBufSource{
		snapLen:       DefaultSnapLen,
		blockSize:     tPacketDefaultBlockSize,
		nBlocks:       tPacketDefaultBlockNr,
		ipLayerOffset: link.LinkType.IpHeaderOffset(),
		link:          link,
		Mutex:         sync.Mutex{},
	}

	for _, opt := range options {
		if err := opt(src); err != nil {
			return nil, fmt.Errorf("failed to set option: %w", err)
		}
	}

	// Define a new TPacket request
	var err error
	src.ringBuffer.tpReq, err = newTPacketRequestForBuffer(src.blockSize, src.nBlocks, src.snapLen)
	if err != nil {
		return nil, fmt.Errorf("failed to setup TPacket request on %s: %w", link.Name, err)
	}

	// Setup socket
	src.socketFD, err = setupSocket(link)
	if err != nil {
		return nil, fmt.Errorf("failed to setup AF_PACKET socket on %s: %w", link.Name, err)
	}

	// Set socket options
	if err := setSocketOptions(src.socketFD, link, src.snapLen, src.isPromisc); err != nil {
		return nil, fmt.Errorf("failed to set AF_PACKET socket options on %s: %w", link.Name, err)
	}

	// Setup ring buffer
	src.ringBuffer.ring, src.eventFD, err = setupRingBuffer(src.socketFD, src.tpReq)
	if err != nil {
		unix.Close(src.socketFD)
		return nil, fmt.Errorf("failed to setup AF_PACKET mmap'ed ring buffer %s: %w", link.Name, err)
	}

	// Clear socket stats
	if _, err := getSocketStats(src.socketFD); err != nil {
		unix.Close(src.socketFD)
		return nil, fmt.Errorf("failed to clear AF_PACKET socket stats on %s: %w", link.Name, err)
	}

	return src, nil
}

// NewPacket creates an empty "buffer" package to be used as destination for the NextPacketInto()
// method. It ensures that a valid packet of appropriate structure / length is created
func (s *RingBufSource) NewPacket() capture.Packet {
	p := make(capture.Packet, 6+s.snapLen)
	return p
}

// NextPacket receives the next packet from the wire and returns it. The operation is blocking. In
// case a non-nil "buffer" Packet is provided it will be populated with the data (and returned). The
// buffer packet can be reused. Otherwise a new Packet of the Source-specific type is allocated.
func (s *RingBufSource) NextPacket(pBuf capture.Packet) (capture.Packet, error) {

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
func (s *RingBufSource) NextPacketFn(fn func(payload []byte, totalLen uint32, pktType capture.PacketType, ipLayerOffset byte) error) error {

	if err := s.nextPacket(); err != nil {
		return err
	}

	return fn(s.curTPacketHeader.payloadNoCopy(), s.curTPacketHeader.pktLen(), s.curTPacketHeader.packetType(), s.ipLayerOffset)
}

// Stats returns (and clears) the packet counters of the underlying socket
func (s *RingBufSource) Stats() (capture.Stats, error) {
	s.Lock()
	defer s.Unlock()

	ss, err := getSocketStats(s.socketFD)
	if err != nil {
		return capture.Stats{}, err
	}
	return capture.Stats{
		PacketsReceived: int(ss.packets),
		PacketsDropped:  int(ss.drops),
		QueueFreezes:    int(ss.queueFreezes),
	}, nil
}

// Unblock ensures that a potentially ongoing blocking PPOLL is released (returning an ErrCaptureUnblock)
func (s *RingBufSource) Unblock() error {
	if s == nil || s.eventFD < 0 || s.socketFD < 0 {
		return errors.New("cannot call Unblock() on nil / closed capture source")
	}

	return s.eventFD.Signal(event.SignalUnblock)
}

// Close stops / closes the capture source
func (s *RingBufSource) Close() error {
	if s == nil || s.eventFD < 0 || s.socketFD < 0 {
		return errors.New("cannot call Close() on nil / closed capture source")
	}

	if err := s.eventFD.Signal(event.SignalStop); err != nil {
		return err
	}

	if err := unix.Close(s.socketFD); err != nil {
		return err
	}

	s.socketFD = -1

	return nil
}

// Free releases any pending resources from the capture source (must be called after Close())
func (s *RingBufSource) Free() error {
	if s == nil {
		return errors.New("cannot call Free() on nil capture source")
	}
	if s.socketFD >= 0 {
		return errors.New("cannot call Free() on open capture source, call Close() first")
	}

	if s.ring != nil {
		return unix.Munmap(s.ring)
	}

	return nil
}

// Link returns the underlying link
func (s *RingBufSource) Link() *link.Link {
	return s.link
}

func (s *RingBufSource) nextPacket() error {

	// If the socket is invalid the capture is obviously closed and we return the respective
	// error
	if s.socketFD < 0 {
		return capture.ErrCaptureStopped
	}

	// If the current TPacketHeader does not contain any more packets (or is uninitialized)
	// fetch a new one from the ring buffer
fetch:
	if s.curTPacketHeader == nil {
		s.curTPacketHeader = s.nextTPacketHeader()
		for s.curTPacketHeader.getStatus()&unix.TP_STATUS_USER == 0 {
			efdHasEvent, errno := event.Poll(s.eventFD, s.socketFD, unix.POLLIN|unix.POLLERR)
			if errno != 0 {
				if errno == unix.EINTR {
					continue
				}
				return fmt.Errorf("error polling for next packet: %d", errno)
			}
			if efdHasEvent {
				return s.handleEvent()
			}

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
		if nextPos == 0 {
			if s.curTPacketHeader.nPktsUsed != s.curTPacketHeader.nPkts() {
				fmt.Println(s.link.Name, "WUT (after resetting)?", s.curTPacketHeader.nPktsUsed, s.curTPacketHeader.nPkts())
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

func (s *RingBufSource) handleEvent() error {
	efdData, err := s.eventFD.ReadEvent()
	if err != nil {
		return fmt.Errorf("error reading event: %w", err)
	}

	switch efdData {
	case event.SignalUnblock:
		return capture.ErrCaptureUnblock
	case event.SignalStop:
		return capture.ErrCaptureStopped
	default:
		return fmt.Errorf("unknown event during poll for next packet: %d", efdData)
	}
}
