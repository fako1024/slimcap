package capture

import (
	"errors"

	"github.com/fako1024/slimcap/link"
)

var (

	// ErrCaptureStopped denotes that the capture was stopped
	ErrCaptureStopped error = errors.New("capture was stopped")
)

// Stats denotes a packet capture stats structure providing basic counters
type Stats struct {
	PacketsReceived int
	PacketsDropped  int
}

// PacketType denotes the packet type (indicating traffic direction)
type PacketType = byte

// Source denotes a generic packet capture source
type Source interface {

	// NextRawPacketPayload receives the next packet from the wire and returns its
	// raw payload along with the packet type flag (including all layers)
	// Note: This method returns a copy of the underlying data
	NextPacket() (Packet, error)

	// NextIPPacket receives the next packet from the wire and returns its
	// IP layer payload (taking into account the underlying interface / link)
	// Packets without a valid IPv4 / IPv6 layer are discarded
	// Note: This method returns a copy of the underlying data
	NextPacketInto(p Packet) error

	// NextIPPacketFn executed the provided function on the next packet received
	// on the wire
	// Note: If possible, the method will perform a zero-copy operation
	NextPacketFn(func(payload []byte, totalLen uint32, pktType PacketType, ipLayerOffset byte) error) error

	// Stats returns (and clears) the packet counters of the underlying socket
	Stats() (Stats, error)

	// Link returns the underlying link
	Link() link.Link

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
	IPLayer() []byte

	// Type denotes the packet type (i.e. the packet direction w.r.t. the interface)
	Type() PacketType
}
