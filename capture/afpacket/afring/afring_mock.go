package afring

import (
	"net"
	"sync"
	"time"
	"unsafe"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"github.com/fako1024/slimcap/event"
	"github.com/fako1024/slimcap/link"
	"golang.org/x/sys/unix"
)

// MockSource denotes a fully mocked ring buffer source, behaving just like one
// Since it wraps a regular Source, it can be used as a stand-in replacement without any further
// code modifications:
//
// src, err := afring.NewSource("eth0", <options>...)
// ==>
// src, err := afring.NewMockSource("eth0", <options>...)
type MockSource struct {
	*Source

	blockBuf    []byte
	blockBufPos int

	mockBlocks     chan []byte
	mockBlockCount int

	mockFd *socket.MockFileDescriptor
}

// NewMockSource instantiates a new mock ring buffer source, wrapping a regular Source
func NewMockSource(iface string, options ...Option) (*MockSource, error) {

	mockHandler, mockFd, err := event.NewMockHandler()
	if err != nil {
		return nil, err
	}

	src := &Source{
		snapLen:   DefaultSnapLen,
		blockSize: tPacketDefaultBlockSize,
		nBlocks:   tPacketDefaultBlockNr,

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
		ringBuffer:   ringBuffer{},
		eventHandler: mockHandler,
	}

	for _, opt := range options {
		opt(src)
	}

	if src.ringBuffer.tpReq, err = newTPacketRequestForBuffer(src.blockSize, src.nBlocks, src.snapLen); err != nil {
		return nil, err
	}
	src.ringBuffer.tpReq.retire_blk_tov = tPacketDefaultBlockTOV
	src.ringBuffer.ring = make([]byte, src.ringBuffer.tpReq.blockNr*src.ringBuffer.tpReq.blockSize)

	return &MockSource{
		Source:     src,
		mockBlocks: make(chan []byte, src.nBlocks),
		mockFd:     mockFd,
	}, nil
}

// AddPacket adds a new mock packet to the source
// This can happen prior to calling run or continuously while consuming data, mimicking the
// function of an actual ring buffer. Consequently, if the ring buffer is full and elements not
// yet consumed this function may block
func (m *MockSource) AddPacket(pkt capture.Packet) {

	tPacketData := make([]byte, 82+m.snapLen)

	*(*uint32)(unsafe.Pointer(&tPacketData[12])) = uint32(m.snapLen)
	*(*uint32)(unsafe.Pointer(&tPacketData[16])) = uint32(pkt.TotalLen())
	*(*uint32)(unsafe.Pointer(&tPacketData[24])) = uint32(82) // mac

	tPacketData[58] = pkt.Type()                      // pktType
	copy(tPacketData[82:82+m.snapLen], pkt.Payload()) // payload

	// If the block buffer is full (or there is no block yet), allocate a new one and populate
	// the basic TPacketHeader fields
	if len(m.blockBuf) == 0 || m.blockBufPos+len(tPacketData) > m.blockSize {
		if len(m.blockBuf) > 0 {
			m.FinalizeBlock()
		}
		m.blockBuf = make([]byte, m.blockSize)
		m.blockBufPos = tPacketHeaderLen

		*(*uint32)(unsafe.Pointer(&m.blockBuf[0])) = 3                     // version
		*(*uint32)(unsafe.Pointer(&m.blockBuf[8])) = unix.TP_STATUS_KERNEL // status
		*(*uint32)(unsafe.Pointer(&m.blockBuf[16])) = tPacketHeaderLen     // offsetToFirstPkt
	}

	// If this is not the first package of the block, set the nextOffset of the previous packet
	if m.blockBufPos > tPacketHeaderLen {
		*(*uint32)(unsafe.Pointer(&m.blockBuf[m.blockBufPos-82-m.snapLen])) = uint32(82 + m.snapLen) // nextOffset
	}
	*(*uint32)(unsafe.Pointer(&m.blockBuf[12])) = *(*uint32)(unsafe.Pointer(&m.blockBuf[12])) + 1 // nPkts
	copy(m.blockBuf[m.blockBufPos:], tPacketData)                                                 // TPacket data
	m.blockBufPos += len(tPacketData)

	// Similar to the actual kernel ring buffer, we count packets as "seen" when they enter
	// the pipeline, not when they are consumed from the buffer
	m.mockFd.IncrementPacketCount(1)
}

// FinalizeBlock flushes the current block buffer and puts it onto the channel
// for consumption
func (m *MockSource) FinalizeBlock() {
	if len(m.blockBuf) > 0 {
		m.mockBlocks <- m.blockBuf
	}
}

// Run executes processing of packets in the background, mimicking the function of an actual kernel
// packet ring buffer
func (m *MockSource) Run() chan error {
	errChan := make(chan error)
	go func() {

		defer close(errChan)

		for block := range m.mockBlocks {

			// Simulate TPacket block retirement
			time.Sleep(time.Duration(m.ringBuffer.tpReq.retire_blk_tov) * time.Millisecond)
			thisBlock := m.mockBlockCount % m.nBlocks

			// Ensure that the packet has already been consumed to avoid race conditions (since there is no
			// feedback from the receiver we can only poll until the packet status is not TP_STATUS_USER)
			for *(*uint32)(unsafe.Pointer(&m.ringBuffer.ring[thisBlock*m.blockSize+8])) == unix.TP_STATUS_USER {
				time.Sleep(100 * time.Millisecond)
			}

			// Store the next block in the ring buffer and mark it to be available to the reader
			copy(m.ringBuffer.ring[thisBlock*m.blockSize:thisBlock*m.blockSize+m.blockSize], block)
			*(*uint32)(unsafe.Pointer(&m.ringBuffer.ring[thisBlock*m.blockSize+8])) = unix.TP_STATUS_USER

			// Queue / trigger an event equivalent to receiving a new block via the PPOLL syscall
			if err := event.ToMockHandler(m.eventHandler).SignalAvailableData(); err != nil {
				errChan <- err
				return
			}

			m.mockBlockCount++
		}
	}()

	return errChan
}

// Done notifies the mock source that no more mock packets will be added, causing the ring buffer
// filling routine / channel to terminate once all packets have been written to the ring buffer
func (m *MockSource) Done() {
	close(m.mockBlocks)
}
