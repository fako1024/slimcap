package pcap

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/link"
)

// Source denotes a pcap file capture source
type Source struct {
	io.Reader

	header        Header
	buf           []byte
	ipLayerOffset byte

	link *link.Link

	nPackets      int
	swapEndianess bool
}

// NewSource instantiates a new pcap file capture source based on any io.Reader
func NewSource(iface string, r io.Reader) (*Source, error) {

	if r == nil {
		return nil, errors.New("nil io.Reader provided")
	}
	obj := Source{
		Reader: r,
		buf:    make([]byte, HeaderSize),
	}

	// Parse the main header
	if err := obj.read(obj.buf); err != nil {
		return nil, err
	}

	// If required, swap endianess as defined here:
	// https://wiki.wireshark.org/Development/LibpcapFileFormat
	obj.header = *(*Header)(unsafe.Pointer(&obj.buf[0]))
	if obj.header.MagicNumber == MagicSwappedEndianess {
		obj.header = obj.header.SwapEndianess()
		obj.swapEndianess = true
	}

	// After swapping, the header magic must be valid
	if obj.header.MagicNumber != MagicNativeEndianess {
		return nil, fmt.Errorf("invalid pcap header magic: %x", obj.header.MagicNumber)
	}

	// Populate (fake) link information
	obj.link = &link.Link{
		Type: link.Type(obj.header.Network),
		Interface: &net.Interface{
			Name:  iface,
			Flags: net.FlagUp,
		},
	}
	obj.ipLayerOffset = obj.link.Type.IpHeaderOffset()

	return &obj, nil
}

// NewSourceFromFile instantiates a new pcap file capture source based on a file name
func NewSourceFromFile(path string) (*Source, error) {
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, err
	}

	return NewSource(filepath.Base(path), f)
}

// NewPacket creates an empty "buffer" packet to be used as destination for the NextPacket() / NextPayload() /
// NextIPPacket() methods (the latter two by calling .Payload() / .IPLayer() on the created buffer). It ensures
// that a valid packet of appropriate structure / length is created
func (s *Source) NewPacket() capture.Packet {
	p := make(capture.Packet, int(s.header.Snaplen)+capture.PacketHdrOffset)
	return p
}

// NextPacket receives the next packet from the source and returns it. The operation is blocking. In
// case a non-nil "buffer" Packet is provided it will be populated with the data (and returned). The
// buffer packet can be reused. Otherwise a new Packet is allocated.
func (s *Source) NextPacket(pBuf capture.Packet) (capture.Packet, error) {

	pktHeader, err := s.nextPacket()
	if err != nil {
		return nil, err
	}

	return capture.NewIPPacket(pBuf, s.buf, capture.PacketUnknown, int(pktHeader.OriginalLen), s.ipLayerOffset), nil
}

// NextPayload receives the raw payload of the next packet from the source and returns it. The operation is blocking.
// In case a non-nil "buffer" byte slice / payload is provided it will be populated with the data (and returned).
// The buffer can be reused. Otherwise a new byte slice / payload is allocated.
func (s *Source) NextPayload(pBuf []byte) ([]byte, capture.PacketType, uint32, error) {

	pktHeader, err := s.nextPacket()
	if err != nil {
		return nil, capture.PacketUnknown, 0, err
	}

	return s.buf, capture.PacketUnknown, uint32(pktHeader.OriginalLen), nil
}

// NextIPPacket receives the IP layer of the next packet from the source and returns it. The operation is blocking.
// In case a non-nil "buffer" IPLayer is provided it will be populated with the data (and returned).
// The buffer can be reused. Otherwise a new IPLayer is allocated.
func (s *Source) NextIPPacket(pBuf capture.IPLayer) (capture.IPLayer, capture.PacketType, uint32, error) {

	pktHeader, err := s.nextPacket()
	if err != nil {
		return nil, capture.PacketUnknown, 0, err
	}

	return s.buf[s.ipLayerOffset:], capture.PacketUnknown, uint32(pktHeader.OriginalLen), nil
}

// NextPacketFn executes the provided function on the next packet received on the source. If possible, the
// operation should provide a zero-copy way of interaction with the payload / metadata. All operations on the data
// must be completed prior to any subsequent call to any Next*() method.
func (s *Source) NextPacketFn(fn func(payload []byte, totalLen uint32, pktType capture.PacketType, ipLayerOffset byte) error) error {

	pktHeader, err := s.nextPacket()
	if err != nil {
		return err
	}

	return fn(s.buf, uint32(pktHeader.OriginalLen), capture.PacketUnknown, s.ipLayerOffset)
}

// Stats returns (and clears) the packet counters of the underlying source
func (s *Source) Stats() (capture.Stats, error) {
	stats := capture.Stats{
		PacketsReceived: s.nPackets,
	}
	s.nPackets = 0
	return stats, nil
}

// Link returns the underlying link
func (s *Source) Link() *link.Link {
	return s.link
}

// Unblock ensures that a potentially ongoing blocking poll operation is released (returning an ErrCaptureUnblock from
// any potentially ongoing call to Next*() that might currently be blocked)
func (s *Source) Unblock() error {
	return nil
}

// Close stops / closes the capture source
func (s *Source) Close() error {
	if readCloser, ok := s.Reader.(io.ReadCloser); ok {
		return readCloser.Close()
	}
	return nil
}

// Free releases any pending resources from the capture source (must be called after Close())
func (s *Source) Free() error {
	s.buf = nil
	return nil
}

////////////////////////////////////////////////////////////////////////

func (s *Source) nextPacket() (pktHeader PacketHeader, err error) {
	pktHeader, err = s.nextPacketHeader()
	if err != nil {
		return
	}
	if s.swapEndianess {
		pktHeader = pktHeader.SwapEndianess()
	}

	if err = s.nextPacketData(int(pktHeader.CaptureLen)); err == nil {
		s.nPackets++
	}

	return
}

func (s *Source) nextPacketHeader() (PacketHeader, error) {
	if err := s.read(s.buf[:PacketHeaderSize]); err != nil {
		return PacketHeader{}, err
	}
	return *(*PacketHeader)(unsafe.Pointer(&s.buf[0])), nil
}

func (s *Source) nextPacketData(snapLen int) error {
	if cap(s.buf) < snapLen {
		s.buf = make([]byte, snapLen)
	}
	s.buf = s.buf[:snapLen]

	return s.read(s.buf)
}

func (s *Source) read(buf []byte) error {
	n, err := io.ReadAtLeast(s.Reader, buf, len(buf))
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("unexpected number of bytes read, want %d, have %d", len(buf), n)
	}
	return nil
}
