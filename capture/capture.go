package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"github.com/fako1024/slimcap/link"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (

	// PacketHdrOffset denotes the header offset / length for storing information about the packet
	PacketHdrOffset = 6

	// ErrCaptureStopped denotes that the capture was stopped
	ErrCaptureStopped error = errors.New("capture was stopped")

	// ErrCaptureUnblock denotes that the capture received am unblocking signal
	ErrCaptureUnblock error = errors.New("capture was released / unblocked")
)

// Stats denotes a packet capture stats structure providing basic counters
type Stats struct {
	PacketsReceived int
	PacketsDropped  int
	QueueFreezes    int
}

// PacketType denotes the packet type (indicating traffic direction)
type PacketType = byte

// IPLayer denotes the subset of bytes representing an IP layer
type IPLayer []byte

// Type returns the IP layer type (e.g. IPv4 / IPv6)
func (i IPLayer) Type() byte {
	return i[0] >> 4
}

// Protocol returns the IP layer protocol
func (i IPLayer) Protocol() byte {
	if ipLayerType := i.Type(); ipLayerType == 4 {
		return i[9]
	} else if ipLayerType == 6 {
		return i[6]
	}

	return 0x0
}

// String returns a human-readable string representation of the packet IP layer
func (i IPLayer) String() (res string) {

	ipLayerType := i[0] >> 4
	var (
		sport, dport uint16
	)

	if ipLayerType == 4 {
		protocol := i[9]
		if protocol == 6 || protocol == 17 {
			dport = binary.BigEndian.Uint16(i[ipv4.HeaderLen+2 : ipv4.HeaderLen+4])
			sport = binary.BigEndian.Uint16(i[ipv4.HeaderLen : ipv4.HeaderLen+2])
		}
		return fmt.Sprintf("%s:%d => %s:%d (proto: %d)",
			net.IP(i[12:16]).String(),
			sport,
			net.IP(i[16:20]).String(),
			dport,
			protocol,
		)
	} else if ipLayerType == 6 {
		protocol := i[6]
		if protocol == 6 || protocol == 17 {
			dport = binary.BigEndian.Uint16(i[ipv6.HeaderLen+2 : ipv6.HeaderLen+4])
			sport = binary.BigEndian.Uint16(i[ipv6.HeaderLen : ipv6.HeaderLen+2])
		}
		return fmt.Sprintf("%s:%d => %s:%d (proto: %d)",
			net.IP(i[8:24]).String(),
			sport,
			net.IP(i[24:40]).String(),
			dport,
			protocol,
		)
	}

	return fmt.Sprintf("unknown IP layer type (%d)", ipLayerType)
}

// Source denotes a generic packet capture source
type Source interface {

	// NewPacket creates an empty "buffer" package to be used as destination for the NextPacketInto()
	// method. It ensures that a valid packet of appropriate structure / length is created
	NewPacket() Packet

	// NextPacket receives the next packet from the wire and returns it. The operation is blocking. In
	// case a non-nil "buffer" Packet is provided it will be populated with the data (and returned). The
	// buffer packet can be reused. Otherwise a new Packet is allocated.
	NextPacket(pBuf Packet) (Packet, error)

	// NextIPPacketFn executes the provided function on the next packet received on the wire and only
	// return the ring buffer block to the kernel upon completion of the function. If possible, the
	// operation should provide a zero-copy way of interaction with the payload / metadata.
	NextPacketFn(func(payload []byte, totalLen uint32, pktType PacketType, ipLayerOffset byte) error) error

	// NextIPPacket receives the next packet's IP layer from the wire and returns it. The operation is blocking.
	// In case a non-nil "buffer" IPLayer is provided it will be populated with the data (and returned). The
	// buffer packet can be reused. Otherwise a new IPLayer is allocated.
	NextIPPacket(pBuf IPLayer) (IPLayer, PacketType, uint32, error)

	// Stats returns (and clears) the packet counters of the underlying socket
	Stats() (Stats, error)

	// Link returns the underlying link
	Link() *link.Link

	// Unblock ensures that a potentially ongoing blocking PPOLL is released (returning an ErrCaptureUnblock)
	Unblock() error

	// Close stops / closes the capture source
	Close() error

	// Free releases any pending resources from the capture source (must be called after Close())
	Free() error
}

// Packet denotes a packet retrieved via the AF_PACKET ring buffer,
// [Fulfils the capture.Packet interface]
// [0:1] - Packet Type
// [1:2] - IP Layer Offset
// [2:6] - Total packet length
type Packet []byte

// NewIPPacket instantiates a new IP packet from a given payload and packet type / length
func NewIPPacket(buf Packet, payload []byte, pktType PacketType, totalLen int) Packet {

	if buf == nil {
		buf = make(Packet, len(payload)+PacketHdrOffset)
	}
	buf = buf[:cap(buf)]

	buf[0] = pktType
	*(*uint32)(unsafe.Pointer(&buf[2])) = uint32(totalLen)
	copy(buf[PacketHdrOffset:], payload)

	return buf
}

// TotalLen returnsthe total packet length, including all headers
func (p *Packet) TotalLen() uint32 {
	return *(*uint32)(unsafe.Pointer(&(*p)[2]))
}

// Len returns the actual data length of the packet payload as consumed from the wire
// (may be truncated due to)
func (p *Packet) Len() int {
	return len((*p)) - PacketHdrOffset
}

// Payload returns the raw payload / network layers of the packet
func (p *Packet) Payload() []byte {
	return (*p)[PacketHdrOffset:]
}

// IIPLayer returns the IP layer of the packet (up to snaplen, if set)
func (p *Packet) IPLayer() IPLayer {
	return IPLayer((*p)[int((*p)[1])+PacketHdrOffset:])
}

// Type denotes the packet type (i.e. the packet direction w.r.t. the interface)
func (p *Packet) Type() PacketType {
	return (*p)[0]
}
