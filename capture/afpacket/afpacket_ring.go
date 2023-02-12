package afpacket

import (
	"encoding/binary"
	"fmt"

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
	isZeroCopy bool

	socketFD event.FileDescriptor
	eventFD  event.EvtFileDescriptor

	ipLayerOffset int

	ringBuffer
}

// NewRingBufSource instantiates a new AF_PACKET capture source making use of a ring buffer
func NewRingBufSource(iface link.Link, options ...Option) (*RingBufSource, error) {

	// TODO: make buffer parameters configurable
	// Define a new TPacket request
	tPacketReq, err := newTPacketRequestV1(tPacketDefaultFrameSize, tPacketDefaultNBlocks, tPacketDefaultBlockNr)
	if err != nil {
		return nil, fmt.Errorf("failed to setup TPacket request on %s: %w", iface.Name, err)
	}

	// Setup socket
	sd, err := setupSocket(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to setup AF_PACKET socket on %s: %w", iface.Name, err)
	}

	// Set socket options
	if err := setSocketOptions(sd, iface); err != nil {
		return nil, fmt.Errorf("failed to set AF_PACKET socket options on %s: %w", iface.Name, err)
	}

	// Setup ring buffer
	buf, eventFD, err := setupRingBuffer(sd, tPacketReq)
	if err != nil {
		return nil, fmt.Errorf("failed to setup AF_PACKET mmap'ed ring buffer %s: %w", iface.Name, err)
	}

	// Clear socket stats
	if _, err := getSocketStats(sd); err != nil {
		return nil, fmt.Errorf("failed to clear AF_PACKET socket stats on %s: %w", iface.Name, err)
	}

	// Define new source
	src := &RingBufSource{
		ringBuffer: ringBuffer{
			ring:  buf,
			tpReq: tPacketReq,
		},
		socketFD:      sd,
		ipLayerOffset: iface.LinkType.IpHeaderOffset(),
		eventFD:       eventFD,
	}

	// Apply functional options, if any
	for _, opt := range options {
		opt(src)
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

	// Return the raw data, depending on the zero-copy status
	if s.isZeroCopy {
		return tp.payloadNoCopy(), tp.packetType(), nil
	}
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

// Stats returns (and clears) the packet counters of the underlying socket
func (s *RingBufSource) Stats() (capture.Stats, error) {
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
