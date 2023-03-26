package afpacket

import (
	"errors"
	"io"
	"net"
	"sync"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"github.com/fako1024/slimcap/event"
	"github.com/fako1024/slimcap/link"
)

const (
	packetBufferDepth = 1000 // More or less arbitrary internal buffer depth
)

// MockSource denotes a fully mocked direct AF_PACKET source, behaving just like one
// Since it wraps a regular Source, it can be used as a stand-in replacement without any further
// code modifications:
//
// src, err := afpacket.NewSource("eth0", <options>...)
// ==>
// src, err := afpacket.NewMockSource("eth0", <options>...)
type MockSource struct {
	*Source

	mockPackets chan capture.Packet
	mockFd      *socket.MockFileDescriptor
}

// AddPacket adds a new mock packet to the source
// This can happen prior to calling run or continuously while consuming data
func (m *MockSource) AddPacket(pkt capture.Packet) {
	m.mockPackets <- pkt

	// We count packets as "seen" when they enter the pipeline, not when they are
	// consumed from the buffer
	m.mockFd.IncrementPacketCount(1)
}

// AddPacketFromSource consumes a single packet from the provided source and adds it to the source
// This can happen prior to calling run or continuously while consuming data
func (m *MockSource) AddPacketFromSource(src capture.Source) error {
	pkt, err := src.NextPacket(nil)
	if err != nil {
		return err
	}

	m.AddPacket(pkt)

	return nil
}

// NewMockSource instantiates a new mock direct AF_PACKET source, wrapping a regular Source
func NewMockSource(iface string, options ...Option) (*MockSource, error) {

	mockHandler, mockFd, err := event.NewMockHandler()
	if err != nil {
		return nil, err
	}

	src := &Source{
		snapLen:       DefaultSnapLen,
		ipLayerOffset: link.Type(link.TypeEthernet).IpHeaderOffset(),
		link: &link.Link{
			Type: link.TypeEthernet,
			Interface: &net.Interface{
				Index:        1,
				MTU:          1500,
				Name:         iface,
				HardwareAddr: []byte{},
				Flags:        net.FlagUp,
			},
		},
		Mutex:        sync.Mutex{},
		eventHandler: mockHandler,
	}

	for _, opt := range options {
		opt(src)
	}

	src.buf = make(capture.Packet, src.snapLen+capture.PacketHdrOffset)

	return &MockSource{
		Source:      src,
		mockPackets: make(chan capture.Packet, packetBufferDepth),
		mockFd:      mockFd,
	}, nil
}

// Pipe continuously pipes packets from the provided source through this one
func (m *MockSource) Pipe(src capture.Source) chan error {
	errChan := make(chan error)
	go func(errs chan error) {
		for {
			if err := m.AddPacketFromSource(src); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, capture.ErrCaptureStopped) {
					m.Done()
					return
				}
				errs <- err
				return
			}
		}
	}(errChan)
	go m.run(errChan)

	return errChan
}

// Run executes processing of packets in the background, mimicking the function of an actual kernel
// packet ring buffer
func (m *MockSource) Run() chan error {
	errChan := make(chan error)
	go m.run(errChan)

	return errChan
}

// Done notifies the mock source that no more mock packets will be added, causing the ring buffer
// filling routine / channel to terminate once all packets have been written to the ring buffer
func (m *MockSource) Done() {
	close(m.mockPackets)
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

func (m *MockSource) run(errChan chan error) {

	defer close(errChan)

	for pkt := range m.mockPackets {

		m.mockFd.Put(pkt)

		// Queue / trigger an event equivalent to receiving a new packet via the PPOLL syscall
		if err := event.ToMockHandler(m.eventHandler).SignalAvailableData(); err != nil {
			errChan <- err
			return
		}
	}

	errChan <- nil
}
