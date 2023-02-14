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

// Source denotes a plain AF_PACKET capture source
type Source struct {
	socketFD event.FileDescriptor

	ipLayerOffset byte
	snapLen       int
	isPromisc     bool
	link          link.Link

	buf Packet

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
		snapLen:       DefaultSnapLen,
		socketFD:      sd,
		ipLayerOffset: iface.LinkType.IpHeaderOffset(),
		link:          iface,
		Mutex:         sync.Mutex{},
	}

	// Apply functional options, if any
	for _, opt := range options {
		if err := opt(src); err != nil {
			return nil, fmt.Errorf("failed to set option: %w", err)
		}
	}
	src.buf = make(Packet, src.snapLen)

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

func (s *Source) NextPacket() (capture.Packet, error) {

	n, err := s.nextPacketInto(&s.buf)
	if err != nil {
		return nil, err
	}

	return copyData((s.buf)[:n+6]), nil
}

func (s *Source) NextPacketInto(p capture.Packet) error {

	data, ok := p.(*Packet)
	if !ok {
		return fmt.Errorf("incompatible packet type `%s` for Source", reflect.TypeOf(p).String())
	}

	n, err := s.nextPacketInto(data)
	if err != nil {
		return err
	}

	(*data) = (*data)[:n+6]
	return nil
}

func (s *Source) NextPacketFn(fn func(payload []byte, totalLen uint32, pktType capture.PacketType, ipLayerOffset byte) error) error {

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

	return fn(s.buf[:n], 0, pktType, s.ipLayerOffset) // TODO: How do we get the total packet size from a plain socket?
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

// Link returns the underlying link
func (s *Source) Link() link.Link {
	return s.link
}

func (s *Source) nextPacketInto(data *Packet) (int, error) {

	// Receive a packet from the write
	n, sockAddr, err := unix.Recvfrom(s.socketFD, (*data)[6:], 0)
	if err != nil {
		return -1, fmt.Errorf("error receiving next packet from socket: %w", err)
	}

	// Determine the packet type (direction)
	if llsa, ok := sockAddr.(*unix.SockaddrLinklayer); ok {
		(*data)[0] = llsa.Pkttype
	} else {
		return -1, fmt.Errorf("failed to determine packet type")
	}

	(*data)[1] = byte(s.ipLayerOffset)
	binary.LittleEndian.PutUint32((*data)[2:6], 0) // TODO: How do we get the total packet size from a plain socket?

	return n, nil
}

func copyData(buf []byte) *Packet {
	cpBuf := make(Packet, len(buf))
	copy(cpBuf, buf)
	return &cpBuf
}
