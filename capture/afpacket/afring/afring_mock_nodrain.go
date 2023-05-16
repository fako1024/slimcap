package afring

import (
	"sync/atomic"
	"time"

	"github.com/fako1024/slimcap/event"
	"golang.org/x/sys/unix"
)

// MockSourceNoDrain denotes a fully mocked, high-throughput ring buffer source, behaving just like one
// with the notable exception that blocks / packets are not drained but reused instead.
// Since it wraps a regular Source, it can be used as a stand-in replacement without any further
// code modifications:
//
// src, err := afring.NewSource("eth0", <options>...)
// ==>
// src, err := afring.NewMockSourceNoDrain("eth0", <options>...)
type MockSourceNoDrain struct {
	*MockSource

	closing     atomic.Bool
	doneClosing chan struct{}
}

// NewMockSourceNoDrain instantiates a new high-throughput mock ring buffer source, wrapping a regular Source
func NewMockSourceNoDrain(iface string, options ...Option) (*MockSourceNoDrain, error) {
	mockSrc, err := NewMockSource(iface, options...)
	if err != nil {
		return nil, err
	}

	return &MockSourceNoDrain{
		MockSource:  mockSrc,
		doneClosing: make(chan struct{}, 1),
	}, nil
}

// Run acts as a high-throughput mode to allow continuous reading the same data currently in the
// mock buffer without consuming it and with minimal overhead from handling the mock socket / semaphore
// It is intended to be used in benchmarks using the mock source to minimize measurement noise from the
// mock implementation itself
func (m *MockSourceNoDrain) Run(releaseInterval time.Duration) <-chan error {

	m.FinalizeBlock(false)
	m.MockFd.SetNoRelease(true)

	errChan := make(chan error)
	go func(errs chan error) {

		defer close(errs)

		// Queue / trigger a single event equivalent to receiving a new block via the PPOLL syscall and
		// instruct the mock socket to not release the semaphore. That way data can be consumed immediately
		// at all times
		if err := event.ToMockHandler(m.eventHandler).SignalAvailableData(); err != nil {
			errs <- err
			return
		}

		// Continuously mark all blocks as available to the user at the given interval
		for {
			for i := 0; i < m.nBlocks; i++ {

				// If the mocks source is closing retun
				if m.closing.Load() {
					m.doneClosing <- struct{}{}
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
// filling routine to terminate
func (m *MockSourceNoDrain) Done() {
	m.closing.Store(true)
}

//////////////////////////////////////////////////////////////////////////////////////////////////////

// Close stops / closes the capture source
func (m *MockSourceNoDrain) Close() error {

	m.Done()

	// Ensure that the Run() routine has terminated to avoid a race condition
	<-m.doneClosing

	return m.Source.Close()
}