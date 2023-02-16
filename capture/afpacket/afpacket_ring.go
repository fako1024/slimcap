package afpacket

import (
	"encoding/binary"
	"fmt"
	"reflect"
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
	return &tPacketHeader{data: b.ring[b.offset*int(b.tpReq.blockNr):]}
}

// RingBufSource denotes an AF_PACKET capture source making use of a ring buffer
type RingBufSource struct {
	socketFD event.FileDescriptor
	eventFD  event.EvtFileDescriptor

	ipLayerOffset byte
	snapLen       int
	bufSize       int
	isPromisc     bool
	link          link.Link

	ringBuffer

	sync.Mutex
}

// NewRingBufSource instantiates a new AF_PACKET capture source making use of a ring buffer
func NewRingBufSource(iface link.Link, options ...Option) (*RingBufSource, error) {

	// Define new source
	src := &RingBufSource{
		snapLen:       DefaultSnapLen,
		bufSize:       defaultBufSize,
		ipLayerOffset: iface.LinkType.IpHeaderOffset(),
		link:          iface,
		Mutex:         sync.Mutex{},
	}

	for _, opt := range options {
		if err := opt(src); err != nil {
			return nil, fmt.Errorf("failed to set option: %w", err)
		}
	}

	// Define a new TPacket request
	var err error
	src.ringBuffer.tpReq, err = newTPacketRequestForBuffer(src.bufSize, src.snapLen)
	if err != nil {
		return nil, fmt.Errorf("failed to setup TPacket request on %s: %w", iface.Name, err)
	}

	// Setup socket
	src.socketFD, err = setupSocket(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to setup AF_PACKET socket on %s: %w", iface.Name, err)
	}

	// Set socket options
	if err := setSocketOptions(src.socketFD, iface, src.snapLen, src.isPromisc); err != nil {
		return nil, fmt.Errorf("failed to set AF_PACKET socket options on %s: %w", iface.Name, err)
	}

	// Setup ring buffer
	src.ringBuffer.ring, src.eventFD, err = setupRingBuffer(src.socketFD, src.tpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to setup AF_PACKET mmap'ed ring buffer %s: %w", iface.Name, err)
	}

	// Clear socket stats
	if _, err := getSocketStats(src.socketFD); err != nil {
		return nil, fmt.Errorf("failed to clear AF_PACKET socket stats on %s: %w", iface.Name, err)
	}

	return src, nil
}

func (s *RingBufSource) NewPacket() capture.Packet {
	p := make(Packet, 6+s.snapLen)
	return &p
}

func (s *RingBufSource) NextPacket() (capture.Packet, error) {

	if err := s.nextPacket(); err != nil {
		return nil, err
	}

	data := make(Packet, 6+s.curTPacketHeader.snapLen())
	data[0] = s.curTPacketHeader.packetType()
	data[1] = byte(s.ipLayerOffset)
	binary.LittleEndian.PutUint32(data[2:6], s.curTPacketHeader.pktLen())
	copy(data[6:], s.curTPacketHeader.payloadNoCopy())

	return &data, nil
}

func (s *RingBufSource) NextPacketInto(p capture.Packet) error {

	if err := s.nextPacket(); err != nil {
		return err
	}

	if data, ok := p.(*Packet); ok {
		if data.Len()+6 < int(s.curTPacketHeader.snapLen()) {
			return fmt.Errorf("destination buffer / packet too small, need %d bytes, have %d", int(s.curTPacketHeader.snapLen())+6, data.Len())
		}
		(*data)[0] = s.curTPacketHeader.packetType()
		(*data)[1] = byte(s.ipLayerOffset)
		binary.LittleEndian.PutUint32((*data)[2:6], s.curTPacketHeader.pktLen())
		copy((*data)[6:], s.curTPacketHeader.payloadNoCopy())
		*data = (*data)[:6+s.curTPacketHeader.snapLen()]
	} else {
		return fmt.Errorf("incompatible packet type `%s` for RingBufSource", reflect.TypeOf(p).String())
	}

	return nil
}

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
	}, nil
}

// Close stops / closes the capture source
func (s *RingBufSource) Close() error {
	if err := s.eventFD.Stop(); err != nil {
		return err
	}

	if s.ring != nil {
		if err := unix.Munmap(s.ring); err != nil {
			return err
		}
	}
	s.ring = nil

	return unix.Close(s.socketFD)
}

// Link returns the underlying link
func (s *RingBufSource) Link() link.Link {
	return s.link
}

func (s *RingBufSource) nextPacket() error {

	// If the current TPacketHeader does not contain any more packets (or is uninitialized)
	// fetch a new one from the ring buffer
fetch:
	if s.curTPacketHeader == nil {
		s.curTPacketHeader = s.nextTPacketHeader()
		for s.curTPacketHeader.getStatus()&unix.TP_STATUS_USER == 0 {
			wasCancelled, errno := event.Poll(s.eventFD, s.socketFD, unix.POLLIN|unix.POLLERR)
			if errno != 0 {
				if errno == unix.EINTR {
					continue
				}
				return fmt.Errorf("error polling for next packet: %d", errno)
			}
			if wasCancelled {
				return capture.ErrCaptureStopped
			}

			if s.curTPacketHeader.getStatus()&tPacketStatusCopy != 0 {
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
			s.curTPacketHeader.setStatus(tPacketStatusKernel)
			s.offset = (s.offset + 1) % int(s.tpReq.blockNr)
			s.curTPacketHeader = nil
			goto fetch
		}

		// Update position of next packet
		s.curTPacketHeader.ppos += nextPos
	}

	return nil
}
