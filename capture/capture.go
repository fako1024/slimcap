package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/fako1024/slimcap/link"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var (

	// ErrCaptureStopped denotes that the capture was stopped
	ErrCaptureStopped error = errors.New("capture was stopped")
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
	// buffer packet can be reused. Otherwise a new Packet of the Source-specific type is allocated.
	NextPacket(pBuf Packet) (Packet, error)

	// NextIPPacketFn executes the provided function on the next packet received on the wire and only
	// return the ring buffer block to the kernel upon completion of the function. If possible, the
	// operation should provide a zero-copy way of interaction with the payload / metadata.
	NextPacketFn(func(payload []byte, totalLen uint32, pktType PacketType, ipLayerOffset byte) error) error

	// Stats returns (and clears) the packet counters of the underlying socket
	Stats() (Stats, error)

	// Link returns the underlying link
	Link() *link.Link

	// Close stops / closes the capture source
	Close() error
}

// Packet denotes a generic packet capture from an underlying Source. The interface ensures
// interoperability and allows to implement source-specific handlers for the respective methods
type Packet interface {

	// TotalLen returnsthe total packet length, including all headers
	TotalLen() uint32

	// Len returns the actual data length of the packet as consumed from the wire
	Len() int

	// IPLayer returns the raw payload of the packet (up to snaplen, if set), including all received layers
	Payload() []byte

	// IIPLayer returns the IP layer of the packet (up to snaplen, if set)
	IPLayer() IPLayer

	// Type denotes the packet type (i.e. the packet direction w.r.t. the interface)
	Type() PacketType
}
