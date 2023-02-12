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
	NextRawPacketPayload() ([]byte, byte, error)

	// NextIPPacket receives the next packet from the wire and returns its
	// IP layer payload (taking into account the underlying interface / link)
	// Packets without a valid IPv4 / IPv6 layer are discarded
	NextIPPacket() ([]byte, byte, error)

	// Stats returns (and clears) the packet counters of the underlying socket
	Stats() (Stats, error)

	// Close stops / closes the capture source
	Close() error
}
