package link

const (

	// EtherTypeIPv4 denotes an IPv4 ethernet frame
	EtherTypeIPv4 EtherType = 0x0800

	// EtherTypeIPv6 denotes an IPv6 ethernet frame
	EtherTypeIPv6 EtherType = 0x86DD
)

// EtherType denotes the protocol encapsulated in the payload of the ethernet frame
type EtherType uint16

// HasValidIPLayer determines if the ethernet frame has a valid IPv4 or IPv6 layer
func (t EtherType) HasValidIPLayer() bool {
	return t == EtherTypeIPv4 || t == EtherTypeIPv6
}
