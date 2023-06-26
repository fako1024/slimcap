package afring

import (
	"errors"
	"io"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"github.com/fako1024/slimcap/event"
	"github.com/fako1024/slimcap/link"
	"golang.org/x/sys/unix"
)

const (
	mac                     = 82
	blockStatusPollInterval = 10 * time.Millisecond
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

	curBlockPos int

	mockBlocks     chan int
	mockBlockCount int

	MockFd *socket.MockFileDescriptor

	packetAddCallbackFn func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte)
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

		ipLayerOffset: link.TypeEthernet.IPHeaderOffset(),
		link:          &link.EmptyEthernetLink,
		ringBuffer: ringBuffer{
			curTPacketHeader: new(tPacketHeader),
		},
		eventHandler: mockHandler,
	}

	for _, opt := range options {
		opt(src)
	}

	if src.ringBuffer.tpReq, err = newTPacketRequestForBuffer(src.blockSize, src.nBlocks, src.snapLen); err != nil {
		return nil, err
	}
	src.ringBuffer.tpReq.retireBlkTov = tPacketDefaultBlockTOV
	src.ringBuffer.ring = make([]byte, src.ringBuffer.tpReq.blockNr*src.ringBuffer.tpReq.blockSize)

	return &MockSource{
		Source:     src,
		mockBlocks: make(chan int, src.nBlocks),
		MockFd:     mockFd,
	}, nil
}

// PacketAddCallbackFn provides an optional callback function that is called when a packet is added
// to the mock source (e.g. to build a reference for comparison)
func (m *MockSource) PacketAddCallbackFn(fn func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte)) *MockSource {
	m.packetAddCallbackFn = fn
	return m
}

// AddPacket adds a new mock packet to the source
// This can happen prior to calling run or continuously while consuming data, mimicking the
// function of an actual ring buffer. Consequently, if the ring buffer is full and elements not
// yet consumed this function may block
func (m *MockSource) AddPacket(pkt capture.Packet) error {
	return m.addPacket(pkt.Payload(), pkt.TotalLen(), pkt.Type(), pkt.IPLayerOffset())
}

// AddPacketFromSource consumes a single packet from the provided source and adds it to the source
// This can happen prior to calling run or continuously while consuming data, mimicking the
// function of an actual ring buffer. Consequently, if the ring buffer is full and elements not
// yet consumed this function may block
func (m *MockSource) AddPacketFromSource(src capture.Source) error {
	return src.NextPacketFn(m.addPacket)
}

func (m *MockSource) addPacket(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) error {
	thisBlock := m.mockBlockCount % m.nBlocks

	// If the block buffer is full (or there is no block yet), allocate a new one and populate
	// the basic TPacketHeader fields
	if m.curBlockPos == 0 || m.curBlockPos+mac+m.snapLen > m.blockSize {
		if m.curBlockPos > 0 {
			m.FinalizeBlock(false)
		}
		thisBlock = m.mockBlockCount % m.nBlocks

		// Ensure that the packet has already been consumed to avoid race conditions (since there is no
		// feedback from the receiver we can only poll until the packet status is not TP_STATUS_KERNEL)
		for m.getBlockStatus(thisBlock) != unix.TP_STATUS_KERNEL {
			time.Sleep(blockStatusPollInterval)
		}

		m.markBlock(thisBlock, unix.TP_STATUS_CSUMNOTREADY)
		m.curBlockPos = tPacketHeaderLen
		*(*uint32)(unsafe.Pointer(&m.ringBuffer.ring[thisBlock*m.blockSize])) = 3                   // version
		*(*uint32)(unsafe.Pointer(&m.ringBuffer.ring[thisBlock*m.blockSize+12])) = 0                // nPkts
		*(*uint32)(unsafe.Pointer(&m.ringBuffer.ring[thisBlock*m.blockSize+16])) = tPacketHeaderLen // offsetToFirstPkt
	}

	block := m.ringBuffer.ring[thisBlock*m.blockSize : thisBlock*m.blockSize+m.blockSize]

	*(*uint32)(unsafe.Pointer(&block[m.curBlockPos+12])) = uint32(m.snapLen) // snapLen
	*(*uint32)(unsafe.Pointer(&block[m.curBlockPos+16])) = totalLen          // totalLen
	*(*uint32)(unsafe.Pointer(&block[m.curBlockPos+24])) = uint32(mac)       // mac
	block[m.curBlockPos+58] = pktType                                        // pktType
	copy(block[m.curBlockPos+mac:m.curBlockPos+mac+m.snapLen], payload)      // payload

	// Ensure that there is no "stray" nextOffset set from a previous perusal of this ring buffer block which
	// might remain in case the block is finalized
	*(*uint32)(unsafe.Pointer(&block[m.curBlockPos])) = 0

	// If this is not the first package of the block, set the nextOffset of the previous packet
	if m.curBlockPos > tPacketHeaderLen {
		*(*uint32)(unsafe.Pointer(&block[m.curBlockPos-mac-m.snapLen])) = uint32(mac + m.snapLen) // nextOffset
	}

	*(*uint32)(unsafe.Pointer(&block[12])) = *(*uint32)(unsafe.Pointer(&block[12])) + 1 // nPkts
	m.curBlockPos += mac + m.snapLen

	// Similar to the actual kernel ring buffer, we count packets as "seen" when they enter
	// the pipeline, not when they are consumed from the buffer
	m.MockFd.IncrementPacketCount(1)

	// If a callback function was provided, execute it
	if m.packetAddCallbackFn != nil {
		m.packetAddCallbackFn(payload, totalLen, pktType, ipLayerOffset)
	}

	return nil
}

// FinalizeBlock flushes the current block buffer and puts it onto the channel
// for consumption
func (m *MockSource) FinalizeBlock(force bool) {
	if m.curBlockPos > 0 || force {
		m.mockBlocks <- m.mockBlockCount
		m.curBlockPos = 0
		m.mockBlockCount++
	}
}

// CanAddPackets returns if any more packets can be added to the mock source (allowing to
// non-blockingly assert if the buffer / channel is full or will be on the next operation)
func (m *MockSource) CanAddPackets() bool {
	return len(m.mockBlocks) != m.nBlocks &&
		(len(m.mockBlocks) != m.nBlocks-1 || m.curBlockPos+mac+m.snapLen <= m.blockSize)
}

// Pipe continuously pipes packets from the provided source through this one, mimicking
// the ring buffer / TPacketHeader block retirement setting for population of the ring buffer
func (m *MockSource) Pipe(src capture.Source, doneReadingChan chan struct{}) (errChan chan error) {
	errChan = make(chan error)

	go func(errs chan error, done chan struct{}) {
		for {
			if err := m.AddPacketFromSource(src); err != nil {
				if errors.Is(err, io.EOF) || errors.Is(err, capture.ErrCaptureStopped) {
					m.FinalizeBlock(false)
					m.Done()

					if done != nil {
						done <- struct{}{}
					}
					return
				}

				errs <- err
				return
			}
		}
	}(errChan, doneReadingChan)

	go m.run(errChan)

	return
}

// Run executes processing of packets in the background, mimicking the function of an actual kernel
// packet ring buffer
func (m *MockSource) Run() <-chan error {
	errChan := make(chan error)
	go m.run(errChan)

	return errChan
}

// Done notifies the mock source that no more mock packets will be added, causing the ring buffer
// filling routine / channel to terminate once all packets have been written to the ring buffer
func (m *MockSource) Done() {
	close(m.mockBlocks)
}

// ForceBlockRelease releases all blocks to the kernel (in order to "unblock" any potential mock capture
// from the consuming routine without having to attempt a failed packet consumption)
func (m *MockSource) ForceBlockRelease() {
	for i := 0; i < m.nBlocks; i++ {
		m.markBlock(i, unix.TP_STATUS_KERNEL)
	}
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

func (m *MockSource) run(errChan chan<- error) {
	defer close(errChan)

	for block := range m.mockBlocks {

		// If the ring buffer is empty it was apparently closed / free'd
		if len(m.ringBuffer.ring) == 0 {
			break
		}

		// Mark the next block in the ring buffer, making it available to the reader / userspace
		m.markBlock(block%m.nBlocks, unix.TP_STATUS_USER)

		// Queue / trigger an event equivalent to receiving a new block via the PPOLL syscall
		if err := event.ToMockHandler(m.eventHandler).SignalAvailableData(); err != nil {
			errChan <- err
			return
		}
	}

	errChan <- nil
}

func (m *MockSource) getBlockStatus(n int) (status uint32) {
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&m.ringBuffer.ring[n*m.blockSize+8])))
}

func (m *MockSource) markBlock(n int, status uint32) {
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&m.ringBuffer.ring[n*m.blockSize+8])), status)
}

func (m *MockSource) hasUserlandBlock() bool {
	for i := 0; i < m.nBlocks; i++ {
		if m.getBlockStatus(i) != unix.TP_STATUS_KERNEL {
			return true
		}
	}
	return false
}

// Close stops / closes the capture source
func (m *MockSource) Close() error {

	// Ensure that all blocks / packets have been consumed
	for m.hasUserlandBlock() {
		time.Sleep(10 * time.Millisecond)
	}

	// Close the capture source (but skip the unmap() operation as it would fail
	// on the conventional ring buffer slice)
	return m.Source.close()
}
