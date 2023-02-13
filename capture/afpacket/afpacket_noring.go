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

// Source denotes a plain AF_PACKET capture source
type Source struct {
	socketFD event.FileDescriptor

	ipLayerOffset int
	snapLen       int
	isPromisc     bool

	buf []byte

	sync.Mutex
}

// NewSource instantiates a new AF_PACKET capture source
func NewSource(iface link.Link, options ...Option) (*Source, error) {

	// Setup socket
	sd, err := setupSocket(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to setup AF_PACKET socket on %s: %w", iface.Name, err)
	}

	// Define new source
	src := &Source{
		snapLen:       defaultSnapLen,
		socketFD:      sd,
		ipLayerOffset: iface.LinkType.IpHeaderOffset(),
		Mutex:         sync.Mutex{},
	}

	// Apply functional options, if any
	for _, opt := range options {
		if err := opt(src); err != nil {
			return nil, fmt.Errorf("failed to set option: %w", err)
		}
	}
	src.buf = make([]byte, src.snapLen)

	// Set socket options
	if err := setSocketOptions(sd, iface, src.snapLen, src.isPromisc); err != nil {
		return nil, fmt.Errorf("failed to set AF_PACKET socket options on %s: %w", iface.Name, err)
	}

	// Clear socket stats
	if _, err := getSocketStats(sd); err != nil {
		return nil, fmt.Errorf("failed to clear AF_PACKET socket stats on %s: %w", iface.Name, err)
	}

	return src, nil
}

// NextRawPacketPayload receives the next packet from the wire and returns its
// raw payload along with the packet type flag (including all layers)
func (s *Source) NextRawPacketPayload() ([]byte, byte, error) {

	// Receive a packet from the write
	n, sockAddr, err := unix.Recvfrom(s.socketFD, s.buf, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("error receiving next packet from socket: %w", err)
	}

	// Determine the packet type (direction)
	var pktType uint8
	if llsa, ok := sockAddr.(*unix.SockaddrLinklayer); ok {
		pktType = llsa.Pkttype
	} else {
		return nil, 0, fmt.Errorf("failed to determine packet type")
	}

	// Return the raw data, depending on the zero-copy status
	return copyData(s.buf[:n]), byte(pktType), nil
}

// NextIPPacket receives the next packet from the wire and returns its
// IP layer payload (taking into account the underlying interface / link)
// Packets without a valid IPv4 / IPv6 layer are discarded
func (s *Source) NextIPPacket() ([]byte, byte, error) {
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
func (s *Source) NextIPPacketFn(fn func(payload []byte, pktType byte) error) error {

	// Receive a packet from the write
	n, sockAddr, err := unix.Recvfrom(s.socketFD, s.buf, 0)
	if err != nil {
		return fmt.Errorf("error receiving next packet from socket: %w", err)
	}

	// Determine the packet type (direction)
	var pktType uint8
	if llsa, ok := sockAddr.(*unix.SockaddrLinklayer); ok {
		pktType = llsa.Pkttype
	} else {
		return fmt.Errorf("failed to determine packet type")
	}

	// Execute the provided function before making the buffer available for writing again
	return fn(s.buf[s.ipLayerOffset:n], pktType)
}

// Stats returns (and clears) the packet counters of the underlying socket
func (s *Source) Stats() (capture.Stats, error) {
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
func (s *Source) Close() error {
	return unix.Close(s.socketFD)
}

func copyData(buf []byte) []byte {
	cpBuf := make([]byte, len(buf))
	copy(cpBuf, buf)
	return cpBuf
}
