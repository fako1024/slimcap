package afpacket

import (
	"net"
	"sync"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"github.com/fako1024/slimcap/event"
	"github.com/fako1024/slimcap/link"
)

type MockSource struct {
	*Source

	mockPackets chan capture.Packet
	mockFd      *socket.MockFileDescriptor
}

func (m *MockSource) AddPacket(pkt capture.Packet) {
	m.mockPackets <- pkt

	// Similar to the actual kernel ring buffer, we count packets as "seen" when they enter
	// the pipeline, not when they are consumed from the buffer
	m.mockFd.IncrementPacketCount(1)
}

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
		mockPackets: make(chan capture.Packet, 100000),
		mockFd:      mockFd,
	}, nil
}

// Run executes processing of packets in the background, mimicking the function of an actual kernel
// packet ring buffer
func (m *MockSource) Run() chan error {
	errChan := make(chan error)
	go func() {

		defer close(errChan)

		for pkt := range m.mockPackets {

			m.mockFd.Put(pkt)

			// Queue / trigger an event equivalent to receiving a new block via the PPOLL syscall
			if err := event.ToMockHandler(m.eventHandler).SignalAvailableData(); err != nil {
				errChan <- err
				return
			}
		}
	}()

	return errChan
}

// Done notifies the mock source that no more mock packets will be added, causing the ring buffer
// filling routine / channel to terminate once all packets have been written to the ring buffer
func (m *MockSource) Done() {
	close(m.mockPackets)
}
