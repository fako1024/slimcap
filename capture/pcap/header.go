package pcap

import (
	"math/bits"
)

const (
	HeaderSize       = 24 // HeaderSize : Overall in-memory size of the main pcap file header
	PacketHeaderSize = 16 // PacketHeaderSize : I-memory size of the packet specific header

	MagicNativeEndianess  = uint32(0xa1b2c3d4) // MagicNativeEndianess : endianess of local system
	MagicSwappedEndianess = uint32(0xd4c3b2a1) // MagicSwappedEndianess : endianess of non-local / swapped system
)

// Header denotes the main pcap file header:
// https://wiki.wireshark.org/Development/LibpcapFileFormat
type Header struct {
	MagicNumber  uint32
	VersionMajor uint16
	VersionMinor uint16
	Thiszone     int32
	Sigfigs      uint32
	Snaplen      uint32
	Network      uint32
}

// SwapEndianess switches / swaps the endianess of the header
func (h Header) SwapEndianess() Header {
	return Header{
		MagicNumber:  bits.ReverseBytes32(h.MagicNumber),
		VersionMajor: bits.ReverseBytes16(h.VersionMajor),
		VersionMinor: bits.ReverseBytes16(h.VersionMinor),
		Thiszone:     int32(bits.ReverseBytes32(uint32(h.Thiszone))),
		Sigfigs:      bits.ReverseBytes32(h.Sigfigs),
		Snaplen:      bits.ReverseBytes32(h.Snaplen),
		Network:      bits.ReverseBytes32(h.Network),
	}
}

// PacketHeader denotes the packet specific header:
// https://wiki.wireshark.org/Development/LibpcapFileFormat
type PacketHeader struct {
	TSSec       int32
	TSUsec      int32
	CaptureLen  int32
	OriginalLen int32
}

// SwapEndianess switches / swaps the endianess of the packet specific header
func (h PacketHeader) SwapEndianess() PacketHeader {
	return PacketHeader{
		TSSec:       int32(bits.ReverseBytes32(uint32(h.TSSec))),
		TSUsec:      int32(bits.ReverseBytes32(uint32(h.TSUsec))),
		CaptureLen:  int32(bits.ReverseBytes32(uint32(h.CaptureLen))),
		OriginalLen: int32(bits.ReverseBytes32(uint32(h.OriginalLen))),
	}
}
