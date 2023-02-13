package capture

import "errors"

var (

	// ErrCaptureStopped denotes that the capture was stopped
	ErrCaptureStopped error = errors.New("capture was stopped")
)

// Stats denotes a packet capture stats structure providing basic counters
type Stats struct {
	PacketsReceived int
	PacketsDropped  int
}

type Source interface {

	// NextRawPacketPayload receives the next packet from the wire and returns its
	// raw payload along with the packet type flag (including all layers)
	// Note: This method returns a copy of the underlying data
	NextRawPacketPayload() ([]byte, byte, error)

	// NextIPPacket receives the next packet from the wire and returns its
	// IP layer payload (taking into account the underlying interface / link)
	// Packets without a valid IPv4 / IPv6 layer are discarded
	// Note: This method returns a copy of the underlying data
	NextIPPacket() ([]byte, byte, error)

	// NextIPPacketFn executed the provided function on the next packet received
	// on the wire
	// Note: If possible, the method will perform a zero-copy operation
	NextIPPacketFn(func(payload []byte, pktType byte) error) error

	// Stats returns (and clears) the packet counters of the underlying socket
	Stats() (Stats, error)

	// Close stops / closes the capture source
	Close() error
}
