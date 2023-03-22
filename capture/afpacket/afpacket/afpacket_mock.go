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

// var globalSconn net.Conn
// var globalLconn net.Conn

// func htons(h int) (n int) {
// 	a := uint16(42)
// 	if *(*byte)(unsafe.Pointer(&a)) == 42 { // little-endian
// 		a = uint16(h)
// 		n = int(a>>8 | a<<8)
// 	} else { // big-endian
// 		n = h
// 	}
// 	return
// }

func NewMockSource(iface string, options ...Option) (*MockSource, error) {

	mockHandler, mockFd, err := event.NewMockHandler()
	if err != nil {
		return nil, err
	}

	// os.Remove("/tmp/test.sock")
	// lis, err := net.Listen("unix", "/tmp/test.sock")
	// if err != nil {
	// 	return nil, err
	// }

	// testFd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM, htons(unix.ETH_P_ALL))
	// if err != nil {
	// 	fmt.Println("Error", err)
	// 	return nil, err
	// }
	// _ = testFd

	// go func() {
	// 	time.Sleep(100 * time.Millisecond)
	// 	sconn, err := net.Dial("unix", "/tmp/test.sock")
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	globalSconn = sconn
	// 	select {}
	// }()

	// conn, err := lis.Accept()
	// if err != nil {
	// 	panic(err)
	// }
	// globalLconn = conn

	// fd, err := getConnFd(conn.(*net.UnixConn))
	// if err != nil {
	// 	return nil, err
	// }

	// conn, err := net.Dial("unix", "/tmp/test.sock")
	// if err != nil {
	// 	return nil, err
	// }
	// defer conn.Close()

	// evtFD, err := event.New()
	// if err != nil {
	// 	return nil, err
	// }

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
