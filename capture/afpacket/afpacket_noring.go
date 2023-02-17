package afpacket

import (
	"fmt"
	"reflect"
	"sync"
	"unsafe"

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
	src.buf = make(Packet, src.snapLen+packetHdrOffset)

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

// NewPacket creates an empty "buffer" package to be used as destination for the NextPacketInto()
// method. It ensures that a valid packet of appropriate structure / length is created
func (s *Source) NewPacket() capture.Packet {
	p := make(Packet, s.snapLen+packetHdrOffset)
	return &p
}

// NextPacket receives the next packet from the wire and returns it. The operation is blocking. In
// case a non-nil "buffer" Packet is provided it will be populated with the data (and returned). The
// buffer packet can be reused. Otherwise a new Packet of the Source-specific type is allocated.
func (s *Source) NextPacket(pBuf capture.Packet) (capture.Packet, error) {

	n, err := s.nextPacketInto(&s.buf)
	if err != nil {
		return nil, err
	}

	// If no buffer was provided, return a copy of the packet
	if pBuf == nil {
		return copyData((s.buf)[:n+packetHdrOffset]), nil
	}

	// Assert the correct type and valid length of the buffer
	data, ok := pBuf.(*Packet)
	if ok {
		*data = (*data)[:cap(*data)]
	} else {
		return nil, fmt.Errorf("incompatible packet type `%s` for RingBufSource", reflect.TypeOf(pBuf).String())
	}
	copy(*data, (s.buf)[:n+packetHdrOffset])

	return data, nil
}

// NextIPPacketFn executed the provided function on the next packet received on the wire and only
// return the ring buffer block to the kernel upon completion of the function. If possible, the
// operation should provide a zero-copy way of interaction with the payload / metadata.
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

	totalLen, err := s.determineTotalPktLen(s.buf)
	if err != nil {
		return err
	}

	return fn(s.buf[:n], uint32(totalLen), pktType, s.ipLayerOffset) // TODO: How do we get the total packet size from a plain socket?
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

	totalLen, err := s.determineTotalPktLen((*data)[6:])
	if err != nil {
		return -1, err
	}

	(*data)[1] = byte(s.ipLayerOffset)
	*(*uint32)(unsafe.Pointer(&(*data)[2])) = uint32(totalLen)

	return n, nil
}

func copyData(buf []byte) *Packet {
	cpBuf := make(Packet, len(buf))
	copy(cpBuf, buf)
	return &cpBuf
}

// Unfortunately there is no ancillary information about the raw / original total size
// of a packet when receiving it directly from the socket. Consequently we have to determine
// the packet size from the IP layer (if available) in case there is a snaplen < 65536 set
func (s *Source) determineTotalPktLen(payload []byte) (uint16, error) {

	// If the snaplen is greater or equal the maximum size of the total length we can
	// trust the amount of data read into the buffer
	if s.snapLen >= 65536 {
		return uint16(len(payload)), nil
	}

	// In case the packet may have been truncated attempt to extract the total packet
	// length from the IP layer
	if int(payload[s.ipLayerOffset]>>4) == 4 {
		return toUint16(payload[s.ipLayerOffset+2 : s.ipLayerOffset+4]), nil
	} else if int(payload[s.ipLayerOffset]>>4) == 6 {
		return toUint16(payload[s.ipLayerOffset+4 : s.ipLayerOffset+6]), nil
	}

	// TODO: What about jumbo packets? At least for IPv6 such packets carry additional
	// data in other places of the payload
	return 0, fmt.Errorf("cannot determine total packet length")
}

func toUint16(b []byte) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[1]) | uint16(b[0])<<8
}
