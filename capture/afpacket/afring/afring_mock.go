package afring

import (
	"errors"
	"io"
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

	mockFd   *socket.MockFileDescriptor
	isClosed bool
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

		ipLayerOffset: link.TypeEthernet.IpHeaderOffset(),
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
		mockBlocks: make(chan int, src.nBlocks),
		mockFd:     mockFd,
	}, nil
}

// AddPacket adds a new mock packet to the source
// This can happen prior to calling run or continuously while consuming data, mimicking the
// function of an actual ring buffer. Consequently, if the ring buffer is full and elements not
// yet consumed this function may block
func (m *MockSource) AddPacket(pkt capture.Packet) error {
	return m.addPacket(pkt.Payload(), pkt.TotalLen(), pkt.Type(), 0)
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

	// If this is not the first package of the block, set the nextOffset of the previous packet
	if m.curBlockPos > tPacketHeaderLen {
		*(*uint32)(unsafe.Pointer(&block[m.curBlockPos-mac-m.snapLen])) = uint32(mac + m.snapLen) // nextOffset
	}
	*(*uint32)(unsafe.Pointer(&block[12])) = *(*uint32)(unsafe.Pointer(&block[12])) + 1 // nPkts
	m.curBlockPos += mac + m.snapLen

	// Similar to the actual kernel ring buffer, we count packets as "seen" when they enter
	// the pipeline, not when they are consumed from the buffer
	m.mockFd.IncrementPacketCount(1)
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
func (m *MockSource) Pipe(src capture.Source) chan error {
	errChan := make(chan error)
	go func(errs chan error) {
		pipe := make(chan error)

		// Run the next capture attempt in a goroutine to allow timing out the operation
		for {
			go func() {
				pipe <- m.AddPacketFromSource(src)
			}()

		retry:
			select {
			// Simulate TPacket block retirement
			case <-time.After(time.Duration(m.ringBuffer.tpReq.retire_blk_tov) * time.Millisecond):

				// To ensure the process cannot enter a deadlock, block finalization is forced (just as
				// it would be the case for the actual ring buffer) even if no packets were received
				m.FinalizeBlock(true)
				goto retry

			case err := <-pipe:
				if err != nil {
					if errors.Is(err, io.EOF) || errors.Is(err, capture.ErrCaptureStopped) {
						m.FinalizeBlock(false)
						m.Done()
						return
					}
					errs <- err
					return
				}
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

// RunNoDrain acts as a high-throughput mode to allow continuous reading the same data currently in the
// mock buffer without consuming it and with minimal overhead from handling the mock socket / semaphore
// It is intended to be used in benchmarks using the mock source to minimize measurement noise from the
// mock implementation itself
func (m *MockSource) RunNoDrain(releaseInterval time.Duration) chan error {

	m.FinalizeBlock(false)

	errChan := make(chan error)
	go func(errs chan error) {

		defer close(errs)

		// Queue / trigger a single event equivalent to receiving a new block via the PPOLL syscall and
		// instruct the mock socket to not release the semaphore. That way data can be consumed immediately
		// at all times
		m.mockFd.SetNoRelease(true)
		if err := event.ToMockHandler(m.eventHandler).SignalAvailableData(); err != nil {
			errs <- err
			return
		}

		// Continuously mark all blocks as available to the user at the given interval
		for {
			for i := 0; i < m.nBlocks; i++ {

				// If the ring buffer is empty it was apparently closed / free'd
				if m.isClosed || len(m.ringBuffer.ring) == 0 {
					errs <- nil
					return
				}

				m.markBlock(i, unix.TP_STATUS_USER)
				time.Sleep(releaseInterval)
			}
		}
	}(errChan)

	return errChan
}

// Done notifies the mock source that no more mock packets will be added, causing the ring buffer
// filling routine / channel to terminate once all packets have been written to the ring buffer
func (m *MockSource) Done() {
	close(m.mockBlocks)
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

func (m *MockSource) run(errChan chan error) {
	defer close(errChan)

	for block := range m.mockBlocks {

		// If the ring buffer is empty it was apparently closed / free'd
		if m.isClosed || len(m.ringBuffer.ring) == 0 {
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
	return *(*uint32)(unsafe.Pointer(&m.ringBuffer.ring[n*m.blockSize+8]))
}

func (m *MockSource) markBlock(n int, status uint32) {
	*(*uint32)(unsafe.Pointer(&m.ringBuffer.ring[n*m.blockSize+8])) = status
}

// Close stops / closes the capture source
func (m *MockSource) Close() error {
	m.isClosed = true
	return m.Source.Close()
}

// Free releases any pending resources from the capture source (must be called after Close())
func (m *MockSource) Free() error {
	m.ringBuffer.ring = nil
	return nil
}
