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
	QueueFreezes    int
}

// PacketType denotes the packet type (indicating traffic direction)
type PacketType = byte

// Source denotes a generic packet capture source
type Source interface {

	// NewPacket creates an empty "buffer" package to be used as destination for the NextPacketInto()
	// method. It ensures that a valid packet of appropriate structure / length is created
	NewPacket() Packet

	// NextPacket receives the next packet from the wire and returns it. The operation is blocking. In
	// case a non-nil "buffer" Packet is provided it will be populated with the data (and returned). The
	// buffer packet can be reused. Otherwise a new Packet of the Source-specific type is allocated.
	NextPacket(pBuf Packet) (Packet, error)

	// NextIPPacketFn executed the provided function on the next packet received on the wire and only
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
	IPLayer() []byte

	// Type denotes the packet type (i.e. the packet direction w.r.t. the interface)
	Type() PacketType
}
