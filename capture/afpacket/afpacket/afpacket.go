//go:build linux
// +build linux

/*
Package afpacket implements a capture.Source that allows reading network packets from
Linux network interfaces via the AF_PACKET mechanism. This implementation relies on performing
repeated `recvfrom()` calls to the allocated socket to fetch packets one by one. Consequently,
the performance / trhoughput is limited and it should only be used for educational / experimental
purposed. For production-level packet capture, use the `afring` package instead.
*/
package afpacket

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"github.com/fako1024/slimcap/event"
	"github.com/fako1024/slimcap/link"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	DefaultSnapLen = (1 << 16) // DefaultSnapLen : 64 kiB
)

// Source denotes a plain AF_PACKET capture source
type Source struct {
	eventHandler *event.Handler

	ipLayerOffset byte
	snapLen       int
	isPromisc     bool
	ignoreVlan    bool
	link          *link.Link

	buf           []byte
	extraBPFInstr []bpf.RawInstruction

	sync.Mutex
}

// NewSource instantiates a new AF_PACKET capture source
func NewSource(iface string, options ...Option) (*Source, error) {

	if iface == "" {
		return nil, errors.New("no interface provided")
	}
	link, err := link.New(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to set up link on %s: %w", iface, err)
	}

	return NewSourceFromLink(link, options...)
}

// NewSourceFromLink instantiates a new AF_PACKET capture source taking an existing link instance
func NewSourceFromLink(link *link.Link, options ...Option) (*Source, error) {

	// Fail if link is not up
	if isUp, err := link.IsUp(); err != nil || !isUp {
		return nil, fmt.Errorf("link %s is not up", link.Name)
	}

	// Define new source
	src := &Source{
		eventHandler:  new(event.Handler),
		snapLen:       DefaultSnapLen,
		ipLayerOffset: link.Type.IPHeaderOffset(),
		link:          link,
	}

	// Apply functional options, if any
	for _, opt := range options {
		opt(src)
	}

	src.buf = make(capture.Packet, src.snapLen+capture.PacketHdrOffset)

	// Setup socket
	var err error
	src.eventHandler.Fd, err = socket.New(link)
	if err != nil {
		return nil, fmt.Errorf("failed to setup AF_PACKET socket on %s: %w", link.Name, err)
	}

	// Setup event file descriptor used for stopping / unblocking the capture
	src.eventHandler.Efd, err = event.New()
	if err != nil {
		return nil, fmt.Errorf("failed to setup event file descriptor: %w", err)
	}

	// Set socket options
	if err := src.eventHandler.Fd.SetSocketOptions(link, src.snapLen, src.isPromisc, src.ignoreVlan, src.extraBPFInstr...); err != nil {
		return nil, fmt.Errorf("failed to set AF_PACKET socket options on %s: %w", link.Name, err)
	}

	// Clear socket stats
	if _, err := src.eventHandler.Fd.GetSocketStats(); err != nil {
		return nil, fmt.Errorf("failed to clear AF_PACKET socket stats on %s: %w", link.Name, err)
	}

	return src, nil
}

// NewPacket creates an empty "buffer" packet to be used as destination for the NextPacket() / NextPayload() /
// NextIPPacket() methods (the latter two by calling .Payload() / .IPLayer() on the created buffer). It ensures
// that a valid packet of appropriate structure / length is created
func (s *Source) NewPacket() capture.Packet {
	p := make(capture.Packet, s.snapLen+capture.PacketHdrOffset)
	return p
}

// NextPacket receives the next packet from the source and returns it. The operation is blocking. In
// case a non-nil "buffer" Packet is provided it will be populated with the data (and returned). The
// buffer packet can be reused. Otherwise a new Packet is allocated.
func (s *Source) NextPacket(pBuf capture.Packet) (capture.Packet, error) {

	n, err := s.nextPacketInto(s.buf)
	if err != nil {
		return nil, err
	}

	// If no buffer was provided, return a copy of the packet
	if pBuf == nil {
		return copyPacket(s.buf[:n+capture.PacketHdrOffset]), nil
	}

	// Set the correct length of the buffer and populate it
	pBuf = pBuf[:cap(pBuf)]
	copy(pBuf, s.buf[:n+capture.PacketHdrOffset])

	return pBuf, nil
}

// NextPayload receives the raw payload of the next packet from the source and returns it. The operation is blocking.
// In case a non-nil "buffer" byte slice / payload is provided it will be populated with the data (and returned).
// The buffer can be reused. Otherwise a new byte slice / payload is allocated.
func (s *Source) NextPayload(pBuf []byte) ([]byte, byte, uint32, error) {

	// If a buffer was provided, store the payload directly in it
	if pBuf != nil {

		// Set the correct length of the buffer and populate it
		pBuf = pBuf[:cap(pBuf)]
		n, pktType, totalLen, err := s.nextPayloadInto(pBuf)
		if err != nil {
			return nil, capture.PacketUnknown, 0, err
		}

		return pBuf[:n], pktType, totalLen, nil
	}

	// If no buffer was provided, return a copy of the packet
	n, pktType, totalLen, err := s.nextPayloadInto(s.buf)
	if err != nil {
		return nil, capture.PacketUnknown, 0, err
	}

	return copyIPLayer(s.buf[:n]), pktType, totalLen, nil
}

// NextIPPacket receives the IP layer of the next packet from the source and returns it. The operation is blocking.
// In case a non-nil "buffer" IPLayer is provided it will be populated with the data (and returned).
// The buffer can be reused. Otherwise a new IPLayer is allocated.
func (s *Source) NextIPPacket(pBuf capture.IPLayer) (capture.IPLayer, capture.PacketType, uint32, error) {

	// If a buffer was provided, store the IP layer directly in it
	if pBuf != nil {

		// Set the correct length of the buffer and populate it
		pBuf = pBuf[:cap(pBuf)]
		n, pktType, totalLen, err := s.nextPayloadInto(pBuf)
		if err != nil {
			return nil, capture.PacketUnknown, 0, err
		}

		return pBuf[s.ipLayerOffset:n], pktType, totalLen, nil
	}

	// If no buffer was provided, return a copy of the packet
	n, pktType, totalLen, err := s.nextPayloadInto(s.buf)
	if err != nil {
		return nil, capture.PacketUnknown, 0, err
	}

	return copyIPLayer(s.buf[s.ipLayerOffset:n]), pktType, totalLen, nil
}

// NextPacketFn executes the provided function on the next packet received on the source. If possible, the
// operation should provide a zero-copy way of interaction with the payload / metadata. All operations on the data
// must be completed prior to any subsequent call to any Next*() method.
func (s *Source) NextPacketFn(fn func(payload []byte, totalLen uint32, pktType capture.PacketType, ipLayerOffset byte) error) error {

	if !s.eventHandler.Fd.IsOpen() {
		return capture.ErrCaptureStopped
	}

retry:
	efdHasEvent, errno := s.eventHandler.Poll(unix.POLLIN | unix.POLLERR)

	// If an event was received, ensure that the respective error is returned
	// immediately (setting the `unblocked` marker to bypass checks done before
	// upon next entry into this method)
	if efdHasEvent {
		return s.handleEvent()
	}

	// Handle errors
	if errno != 0 {
		if errno == unix.EINTR {
			goto retry
		}
		return fmt.Errorf("error polling for next packet: %w", errno)
	}

	// Receive a packet from the wire (According to PPOLL there should be at least one)
	// so we do not block
	n, pktType, err := s.eventHandler.Recvfrom(s.buf, unix.MSG_DONTWAIT)
	if err != nil {
		return fmt.Errorf("error receiving next packet from socket: %w", err)
	}

	totalLen, err := s.determineTotalPktLen(s.buf)
	if err != nil {
		return err
	}

	return fn(s.buf[:n], uint32(totalLen), pktType, s.ipLayerOffset)
}

// Stats returns (and clears) the packet counters of the underlying source
func (s *Source) Stats() (capture.Stats, error) {

	s.Lock()
	ss, err := s.eventHandler.GetSocketStats()
	s.Unlock()

	if err != nil {
		return capture.Stats{}, err
	}
	return capture.Stats{
		PacketsReceived: uint64(ss.Packets),
		PacketsDropped:  uint64(ss.Drops),
	}, nil
}

// Link returns the underlying link
func (s *Source) Link() *link.Link {
	return s.link
}

// Unblock ensures that a potentially ongoing blocking poll operation is released (returning an ErrCaptureUnblock from
// any potentially ongoing call to Next*() that might currently be blocked)
func (s *Source) Unblock() error {
	if s == nil || s.eventHandler.Efd < 0 || s.eventHandler.Fd < 0 {
		return errors.New("cannot call Unblock() on nil / closed capture source")
	}

	return s.eventHandler.Efd.Signal(event.SignalUnblock)
}

// Close stops / closes the capture source
func (s *Source) Close() error {
	if s == nil || s.eventHandler.Efd < 0 || s.eventHandler.Fd < 0 {
		return errors.New("cannot call Close() on nil / closed capture source")
	}

	if err := s.eventHandler.Efd.Signal(event.SignalStop); err != nil {
		return err
	}

	return s.eventHandler.Fd.Close()
}

func (s *Source) nextPacketInto(data capture.Packet) (int, error) {

	if !s.eventHandler.Fd.IsOpen() {
		return -1, capture.ErrCaptureStopped
	}

retry:
	efdHasEvent, errno := s.eventHandler.Poll(unix.POLLIN | unix.POLLERR)

	// If an event was received, ensure that the respective error is returned
	// immediately (setting the `unblocked` marker to bypass checks done before
	// upon next entry into this method)
	if efdHasEvent {
		return -1, s.handleEvent()
	}

	// Handle errors
	if errno != 0 {
		if errno == unix.EINTR {
			goto retry
		}
		return -1, fmt.Errorf("error polling for next packet: %w", errno)
	}

	// Receive a packet from the wire (According to PPOLL there should be at least one)
	// so we do not block
	n, pktType, err := s.eventHandler.Recvfrom(data[6:], unix.MSG_DONTWAIT)
	if err != nil {
		return -1, fmt.Errorf("error receiving next packet from socket: %w", err)
	}
	data[0] = pktType

	totalLen, err := s.determineTotalPktLen(data[6:])
	if err != nil {
		return -1, fmt.Errorf("failed to determine packet length: %w", err)
	}

	data[1] = s.ipLayerOffset
	*(*uint32)(unsafe.Pointer(&data[2])) = uint32(totalLen) // #nosec: G103

	return n, nil
}

func (s *Source) nextPayloadInto(data capture.IPLayer) (int, capture.PacketType, uint32, error) {

	if !s.eventHandler.Fd.IsOpen() {
		return -1, capture.PacketUnknown, 0, capture.ErrCaptureStopped
	}

retry:
	efdHasEvent, errno := s.eventHandler.Poll(unix.POLLIN | unix.POLLERR)

	// If an event was received, ensure that the respective error is returned
	// immediately (setting the `unblocked` marker to bypass checks done before
	// upon next entry into this method)
	if efdHasEvent {
		return -1, capture.PacketUnknown, 0, s.handleEvent()
	}

	// Handle errors
	if errno != 0 {
		if errno == unix.EINTR {
			goto retry
		}
		return -1, capture.PacketUnknown, 0, fmt.Errorf("error polling for next packet: %w", errno)
	}

	// Receive a packet from the wire (According to PPOLL there should be at least one)
	// so we do not block
	n, pktType, err := s.eventHandler.Recvfrom(data, unix.MSG_DONTWAIT)
	if err != nil {
		return -1, capture.PacketUnknown, 0, fmt.Errorf("error receiving next packet from socket: %w", err)
	}

	totalLen, err := s.determineTotalPktLen(data)
	if err != nil {
		return -1, 0, 0, err
	}

	return n, pktType, uint32(totalLen), nil
}

func copyPacket(buf []byte) capture.Packet {
	cpBuf := make(capture.Packet, len(buf))
	copy(cpBuf, buf)
	return cpBuf
}

func copyIPLayer(buf []byte) capture.IPLayer {
	cpBuf := make(capture.IPLayer, len(buf))
	copy(cpBuf, buf)
	return cpBuf
}

func (s *Source) handleEvent() error {

	// Read event data / type from the eventFD
	efdData, err := s.eventHandler.Efd.ReadEvent()
	if err != nil {
		return fmt.Errorf("error reading event: %w", err)
	}

	if efdData[7] > 0 {
		return capture.ErrCaptureStopped
	}
	return capture.ErrCaptureUnblocked
}

// Unfortunately there is no ancillary information about the raw / original total size
// of a packet when receiving it directly from the socket. Consequently we have to determine
// the packet size from the IP layer (if available) in case there is a snaplen < 65536 set
func (s *Source) determineTotalPktLen(payload []byte) (uint16, error) {

	// If the snaplen is greater or equal the maximum size of the total length we can
	// trust the amount of data read into the buffer
	if s.snapLen >= 65536 {
		return uint16(len(payload)), nil
	}

	// In case the packet may have been truncated attempt to extract the total packet
	// length from the IP layer
	if int(payload[s.ipLayerOffset]>>4) == 4 {
		return toUint16(payload[s.ipLayerOffset+2 : s.ipLayerOffset+4]), nil
	} else if int(payload[s.ipLayerOffset]>>4) == 6 {
		return toUint16(payload[s.ipLayerOffset+4 : s.ipLayerOffset+6]), nil
	}

	return 0, fmt.Errorf("cannot determine total packet length")
}

func toUint16(b []byte) uint16 {
	_ = b[1] // bounds check hint to compiler; see golang.org/issue/14808
	return uint16(b[1]) | uint16(b[0])<<8
}
