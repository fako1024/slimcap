/*
Package capture provides the high level / central interface definitions for all slimcap capture
sources and core structures. Two Interfaces are supported:

  - Source : The most general definition of methods any capture source must provide
  - SourceZeroCopy : An extended interface definition adding capabilities for zero-copy operations

In addition to the capture source interfaces it provides the most basic implementation of a network
packet, including basic interaction methods (e.g. packet length, payload, type, ...).
*/
package capture

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"unsafe"

	"github.com/fako1024/gotools/link"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (

	// PacketHdrOffset denotes the header offset / length for storing information about the packet
	PacketHdrOffset = 6
)

var (

	// ErrCaptureStopped denotes that the capture was stopped
	ErrCaptureStopped = errors.New("capture was stopped")

	// ErrCaptureUnblocked denotes that the capture received an unblocking signal
	ErrCaptureUnblocked = errors.New("capture was released / unblocked")
)

// Stats denotes a packet capture stats structure providing basic counters
type Stats struct {
	PacketsReceived uint64
	PacketsDropped  uint64
	QueueFreezes    uint64
}

// PacketType denotes the packet type (indicating traffic direction)
// https://github.com/torvalds/linux/blob/master/include/uapi/linux/if_packet.h
type PacketType = byte

const (
	PacketThisHost  PacketType = iota // PacketThisHost : To us (unicast)
	PacketBroadcast                   // PacketBroadcast : To all
	PacketMulticast                   // PacketMulticast : To group
	PacketOtherHost                   // PacketOtherHost : To someone else
	PacketOutgoing                    // PacketOutgoing : Outgoing of any type

	PacketUnknown PacketType = 255 // PacketUnknown : Unknown packet type / direction
)

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

	switch ipLayerType {
	case 4:
		protocol := i[9]
		if protocol == 6 || protocol == 17 {
			if len(i) >= ipv4.HeaderLen+4 {
				dport = binary.BigEndian.Uint16(i[ipv4.HeaderLen+2 : ipv4.HeaderLen+4])
			}
			if len(i) >= ipv4.HeaderLen+2 {
				sport = binary.BigEndian.Uint16(i[ipv4.HeaderLen : ipv4.HeaderLen+2])
			}
		}
		return fmt.Sprintf("%s:%d => %s:%d (proto: %d)",
			net.IP(i[12:16]).String(),
			sport,
			net.IP(i[16:20]).String(),
			dport,
			protocol,
		)
	case 6:
		protocol := i[6]
		if protocol == 6 || protocol == 17 {
			if len(i) >= ipv6.HeaderLen+4 {
				dport = binary.BigEndian.Uint16(i[ipv6.HeaderLen+2 : ipv6.HeaderLen+4])
			}
			if len(i) >= ipv6.HeaderLen+2 {
				sport = binary.BigEndian.Uint16(i[ipv6.HeaderLen : ipv6.HeaderLen+2])
			}
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

	// NewPacket creates an empty "buffer" packet to be used as destination for the NextPacket() / NextPayload() /
	// NextIPPacket() methods (the latter two by calling .Payload() / .IPLayer() on the created buffer). It ensures
	// that a valid packet of appropriate structure / length is created
	NewPacket() Packet

	// NextPacket receives the next packet from the source and returns it. The operation is blocking. In
	// case a non-nil "buffer" Packet is provided it will be populated with the data (and returned). The
	// buffer packet can be reused. Otherwise a new Packet is allocated.
	NextPacket(pBuf Packet) (Packet, error)

	// NextPayload receives the raw payload of the next packet from the source and returns it. The operation is blocking.
	// In case a non-nil "buffer" byte slice / payload is provided it will be populated with the data (and returned).
	// The buffer can be reused. Otherwise a new byte slice / payload is allocated.
	NextPayload(pBuf []byte) ([]byte, byte, uint32, error)

	// NextIPPacket receives the IP layer of the next packet from the source and returns it. The operation is blocking.
	// In case a non-nil "buffer" IPLayer is provided it will be populated with the data (and returned).
	// The buffer can be reused. Otherwise a new IPLayer is allocated.
	NextIPPacket(pBuf IPLayer) (IPLayer, PacketType, uint32, error)

	// NextPacketFn executes the provided function on the next packet received on the source. If possible, the
	// operation should provide a zero-copy way of interaction with the payload / metadata. All operations on the data
	// must be completed prior to any subsequent call to any Next*() method.
	NextPacketFn(func(payload []byte, totalLen uint32, pktType PacketType, ipLayerOffset byte) error) error

	// Stats returns (and clears) the packet counters of the underlying source
	Stats() (Stats, error)

	// Link returns the underlying link
	Link() *link.Link

	// Unblock ensures that a potentially ongoing blocking poll operation is released (returning an ErrCaptureUnblock from
	// any potentially ongoing call to Next*() that might currently be blocked)
	Unblock() error

	// Close stops / closes the capture source
	Close() error
}

// SourceZeroCopy denotes a generic packet capture source that supports zero-copy operations
type SourceZeroCopy interface {

	// NextPayloadZeroCopy receives the raw payload of the next packet from the source and returns it. The operation is blocking.
	// The returned payload provides direct zero-copy access to the underlying data source (e.g. a ring buffer).
	NextPayloadZeroCopy() ([]byte, PacketType, uint32, error)

	// NextIPPacketZeroCopy receives the IP layer of the next packet from the source and returns it. The operation is blocking.
	// The returned IPLayer provides direct zero-copy access to the underlying data source (e.g. a ring buffer).
	NextIPPacketZeroCopy() (IPLayer, PacketType, uint32, error)

	// Wrap generic Source
	Source
}

// Packet denotes a packet retrieved via the AF_PACKET ring buffer,
// [Fulfils the capture.Packet interface]
// [0:1] - Packet Type
// [1:2] - IP Layer Offset
// [2:6] - Total packet length
type Packet []byte

// NewIPPacket instantiates a new IP packet from a given payload and packet type / length
func NewIPPacket(buf Packet, payload []byte, pktType PacketType, totalLen int, ipLayerOffset byte) Packet {

	if buf == nil {
		buf = make(Packet, len(payload)+PacketHdrOffset)
	}
	buf = buf[:cap(buf)]

	buf[0] = pktType
	buf[1] = ipLayerOffset
	*(*uint32)(unsafe.Pointer(&buf[2])) = uint32(totalLen) // #nosec G103
	n := copy(buf[PacketHdrOffset:], payload)

	return buf[:PacketHdrOffset+n]
}

// TotalLen returnsthe total packet length, including all headers
func (p *Packet) TotalLen() uint32 {
	return *(*uint32)(unsafe.Pointer(&(*p)[2])) // #nosec G103
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

// IPLayer returns the IP layer of the packet (up to snaplen, if set)
func (p *Packet) IPLayer() IPLayer {
	return IPLayer((*p)[int((*p)[1])+PacketHdrOffset:])
}

// IPLayerOffset returns the offset of the IP layer of the packet (w.r.t. its beginning)
func (p *Packet) IPLayerOffset() byte {
	return (*p)[1]
}

// Type denotes the packet type (i.e. the packet direction w.r.t. the interface)
func (p *Packet) Type() PacketType {
	return (*p)[0]
}

// IsInbound denotes if the packet is inbound w.r.t. the interface
func (p *Packet) IsInbound() bool {
	return (*p)[0] != PacketOutgoing
}

// BuildPacket provides basic capabilities to construct packets (e.g. for testing purposes)
func BuildPacket(sip, dip net.IP, sport, dport uint16, proto byte, addPayload []byte, pktType PacketType, totalLen int) (Packet, error) {

	if sipV4, dipV4 := sip.To4(), dip.To4(); sipV4 != nil && dipV4 != nil {

		var pkt []byte
		if sport > 0 && dport > 0 {
			pkt = make([]byte, link.IPLayerOffsetEthernet+ipv4.HeaderLen+4+len(addPayload))
			binary.BigEndian.PutUint16(pkt[link.IPLayerOffsetEthernet+ipv4.HeaderLen:link.IPLayerOffsetEthernet+ipv4.HeaderLen+2], sport)
			binary.BigEndian.PutUint16(pkt[link.IPLayerOffsetEthernet+ipv4.HeaderLen+2:link.IPLayerOffsetEthernet+ipv4.HeaderLen+4], dport)
			copy(pkt[link.IPLayerOffsetEthernet+ipv4.HeaderLen+4:], addPayload)
		} else {
			pkt = make([]byte, link.IPLayerOffsetEthernet+ipv4.HeaderLen+len(addPayload))
			copy(pkt[link.IPLayerOffsetEthernet+ipv4.HeaderLen:], addPayload)
		}
		binary.BigEndian.PutUint16(pkt[link.IPLayerOffsetEthernet+2:link.IPLayerOffsetEthernet+4], uint16(totalLen))

		pkt[link.IPLayerOffsetEthernet] = (4 << 4)
		copy(pkt[link.IPLayerOffsetEthernet+12:link.IPLayerOffsetEthernet+16], sipV4)
		copy(pkt[link.IPLayerOffsetEthernet+16:link.IPLayerOffsetEthernet+20], dipV4)
		pkt[link.IPLayerOffsetEthernet+9] = proto

		return NewIPPacket(nil, pkt, pktType, totalLen, link.IPLayerOffsetEthernet), nil
	}

	if sipV6, dipV6 := sip.To16(), dip.To16(); sipV6 != nil && dipV6 != nil {

		pkt := make([]byte, link.IPLayerOffsetEthernet+ipv6.HeaderLen+4+len(addPayload))

		if sport > 0 && dport > 0 {
			binary.BigEndian.PutUint16(pkt[link.IPLayerOffsetEthernet+ipv6.HeaderLen:link.IPLayerOffsetEthernet+ipv6.HeaderLen+2], sport)
			binary.BigEndian.PutUint16(pkt[link.IPLayerOffsetEthernet+ipv6.HeaderLen+2:link.IPLayerOffsetEthernet+ipv6.HeaderLen+4], dport)
			copy(pkt[link.IPLayerOffsetEthernet+ipv6.HeaderLen+4:], addPayload)
		} else {
			copy(pkt[link.IPLayerOffsetEthernet+ipv6.HeaderLen:], addPayload)
		}
		binary.BigEndian.PutUint16(pkt[link.IPLayerOffsetEthernet+4:link.IPLayerOffsetEthernet+6], uint16(totalLen))

		pkt[link.IPLayerOffsetEthernet] = (6 << 4)
		copy(pkt[link.IPLayerOffsetEthernet+8:link.IPLayerOffsetEthernet+24], sipV6)
		copy(pkt[link.IPLayerOffsetEthernet+24:link.IPLayerOffsetEthernet+40], dipV6)
		pkt[link.IPLayerOffsetEthernet+6] = proto

		return NewIPPacket(nil, pkt, pktType, totalLen, link.IPLayerOffsetEthernet), nil
	}

	return nil, errors.New("invalid IPv4 / IPv6 combination / input")
}
