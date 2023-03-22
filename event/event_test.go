package event

import (
	"errors"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestSemaphoreMock(t *testing.T) {

	handler, _, err := NewMockHandler()
	require.Nil(t, err)

	errChan := make(chan error)
	go func(errChan chan error) {
		for i := 0; i < 6; i++ {
			hasEvent, err := handler.Poll(unix.POLLIN | unix.POLLERR)
			require.Equal(t, syscall.Errno(0), err)

			if hasEvent {
				errChan <- nil
				return
			}
		}

		errChan <- errors.New("should not reach here")
		return
	}(errChan)

	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		require.Nil(t, ToMockHandler(handler).SignalAvailableData())
	}

	handler.Efd.Signal(EvtData(SignalUnblock))
	require.Nil(t, <-errChan)
}
