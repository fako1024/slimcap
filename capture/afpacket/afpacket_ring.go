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
	tPacketVersion = unix.TPACKET_V1
)

type ringBuffer struct {
	ring []byte

	tpReq  tPacketRequestV1
	offset int
}

func (b *ringBuffer) nextTPacketHeader() tPacketHeaderV1 {
	return tPacketHeaderV1(b.ring[b.offset*int(b.tpReq.frameSize):])
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
	src.ringBuffer.tpReq, err = newTPacketRequestV1ForBuffer(src.bufSize, src.snapLen)
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

func (s *RingBufSource) NextPacket() (capture.Packet, error) {

	tp, err := s.nextPacket()
	if err != nil {
		return nil, err
	}
	defer func() {
		tp.setStatus(tPacketStatusKernel)
		s.offset = (s.offset + 1) % int(s.tpReq.frameNr)
	}()

	data := make(Packet, 6+tp.snapLen())
	data[0] = tp.packetType()
	data[1] = byte(s.ipLayerOffset)
	binary.LittleEndian.PutUint32(data[2:6], tp.pktLen())
	copy(data[6:], tp.payloadNoCopy())

	return &data, nil
}

func (s *RingBufSource) NextPacketInto(p capture.Packet) error {

	tp, err := s.nextPacket()
	if err != nil {
		return err
	}
	defer func() {
		tp.setStatus(tPacketStatusKernel)
		s.offset = (s.offset + 1) % int(s.tpReq.frameNr)
	}()

	if data, ok := p.(*Packet); ok {
		(*data)[0] = tp.packetType()
		(*data)[1] = byte(s.ipLayerOffset)
		binary.LittleEndian.PutUint32((*data)[2:6], tp.pktLen())
		copy((*data)[6:], tp.payloadNoCopy())
		*data = (*data)[:6+tp.snapLen()]
	} else {
		return fmt.Errorf("incompatible packet type `%s` for RingBufSource", reflect.TypeOf(p).String())
	}

	return nil
}

func (s *RingBufSource) NextPacketFn(fn func(payload []byte, totalLen uint32, pktType capture.PacketType, ipLayerOffset byte) error) error {

	tp, err := s.nextPacket()
	if err != nil {
		return err
	}
	defer func() {
		tp.setStatus(tPacketStatusKernel)
		s.offset = (s.offset + 1) % int(s.tpReq.frameNr)
	}()

	return fn(tp.payloadNoCopy(), tp.pktLen(), tp.packetType(), s.ipLayerOffset)
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

func (s *RingBufSource) nextPacket() (tPacketHeaderV1, error) {
	tp := s.nextTPacketHeader()
	for tp.getStatus()&unix.TP_STATUS_USER == 0 {

		wasCancelled, errno := event.Poll(s.eventFD, s.socketFD, unix.POLLIN|unix.POLLERR)
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return nil, fmt.Errorf("error polling for next packet: %d", errno)
		}
		if wasCancelled {
			return nil, capture.ErrCaptureStopped
		}

		if tp.getStatus()&tPacketStatusCopy != 0 {
			tp.setStatus(tPacketStatusKernel)
			s.offset = (s.offset + 1) % int(s.tpReq.frameNr)
			tp = s.nextTPacketHeader()

			continue
		}
	}

	return tp, nil
}
