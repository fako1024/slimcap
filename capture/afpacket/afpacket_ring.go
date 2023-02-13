package afpacket

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/event"
	"github.com/fako1024/slimcap/link"
	"github.com/sirupsen/logrus"
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

	ipLayerOffset int
	snapLen       int
	bufSize       int
	isPromisc     bool

	ringBuffer

	sync.Mutex
}

// NewRingBufSource instantiates a new AF_PACKET capture source making use of a ring buffer
func NewRingBufSource(iface link.Link, options ...Option) (*RingBufSource, error) {

	// Define new source
	src := &RingBufSource{
		snapLen:       defaultSnapLen,
		bufSize:       defaultBufSize,
		ipLayerOffset: iface.LinkType.IpHeaderOffset(),
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

// NextRawPacketPayload polls for the next packet on the wire and returns its
// raw payload along with the packet type flag (including all layers)
func (s *RingBufSource) NextRawPacketPayload() ([]byte, byte, error) {

	tp := s.nextTPacketHeader()
	for tp.getStatus()&unix.TP_STATUS_USER == 0 {

		wasCancelled, errno := event.Poll(s.eventFD, s.socketFD, unix.POLLIN|unix.POLLERR)
		if errno != 0 {
			if errno == unix.EINTR {
				continue
			}
			return nil, 0, fmt.Errorf("error polling for next packet: %d", errno)
		}
		if wasCancelled {
			return nil, 0, capture.ErrCaptureStopped
		}

		if tp.getStatus()&tPacketStatusCopy != 0 {
			tp.setStatus(tPacketStatusKernel)
			s.offset = (s.offset + 1) % int(s.tpReq.frameNr)
			tp = s.nextTPacketHeader()

			continue
		}
	}

	tp.setStatus(tPacketStatusKernel)
	s.offset = (s.offset + 1) % int(s.tpReq.frameNr)

	// Return a copy of the raw data
	return tp.payloadCopy(), tp.packetType(), nil
}

// NextIPPacket polls for the next packet on the wire and returns its
// IP layer payload (taking into account the underlying interface / link)
// Packets without a valid IPv4 / IPv6 layer are discarded
func (s *RingBufSource) NextIPPacket() ([]byte, byte, error) {
	for {
		pkt, pktType, err := s.NextRawPacketPayload()
		if err != nil {
			return nil, 0, err
		}

		if len(pkt) < link.IPLayerOffsetEthernet {
			return nil, 0, fmt.Errorf("received packet of length %d too short", len(pkt))
		}

		// TODO: Remove block once we have confirmed the BPF Filtering is working
		// If this is supposed to be a physical / ethernet type link, validate it
		if s.ipLayerOffset == link.IPLayerOffsetEthernet {
			if !link.EtherType(binary.BigEndian.Uint16(pkt[12:14])).HasValidIPLayer() {
				logrus.StandardLogger().Warnf("Detected unexpected packet with invalid IP layer")
				continue
			}
		}

		// Skip ahead of the physical layer (if present) and return
		return pkt[s.ipLayerOffset:], pktType, nil
	}
}

// NextIPPacketFn executed the provided function on the next packet received
// on the wire
func (s *RingBufSource) NextIPPacketFn(fn func(payload []byte, pktType byte) error) error {

	tp := s.nextTPacketHeader()
	for tp.getStatus()&unix.TP_STATUS_USER == 0 {

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

		if tp.getStatus()&tPacketStatusCopy != 0 {
			tp.setStatus(tPacketStatusKernel)
			s.offset = (s.offset + 1) % int(s.tpReq.frameNr)
			tp = s.nextTPacketHeader()

			continue
		}
	}

	// Execute the provided function before returning the frame to the kernel
	if err := fn(tp.payloadNoCopy()[s.ipLayerOffset:], tp.packetType()); err != nil {
		return err
	}

	tp.setStatus(tPacketStatusKernel)
	s.offset = (s.offset + 1) % int(s.tpReq.frameNr)

	return nil
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
