//go:build linux && !slimcap_nomock
// +build linux,!slimcap_nomock

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

		retry:
			hasEvent, errno := handler.Poll(unix.POLLIN | unix.POLLERR)
			if errno != 0 {
				if errno == unix.EINTR {
					goto retry
				}
				errChan <- errors.New(unix.ErrnoName(errno))
			}

			if hasEvent {
				errChan <- nil
				return
			}
		}

		errChan <- errors.New("should not reach here")
	}(errChan)

	for i := 0; i < 5; i++ {
		time.Sleep(50 * time.Millisecond)
		require.Nil(t, ToMockHandler(handler).SignalAvailableData())
	}

	require.Nil(t, handler.Efd.Signal(SignalUnblock))
	require.Nil(t, <-errChan)
}

func TestPollOnClosedFD(t *testing.T) {
	handler, _, err := NewMockHandler()
	require.Nil(t, err)
	require.Nil(t, handler.Efd.Signal(SignalStop))
	require.Nil(t, handler.Fd.Close())

	efdHasEvent, errno := handler.Poll(unix.POLLIN | unix.POLLERR)
	require.True(t, efdHasEvent)
	require.Equal(t, syscall.Errno(0x0), errno)
	_, err = handler.Efd.ReadEvent()
	require.Nil(t, err)

	for i := 0; i < 10; i++ {
		efdHasEvent, errno := handler.Poll(unix.POLLIN | unix.POLLERR)
		require.False(t, efdHasEvent)
		require.Equal(t, syscall.Errno(0x9), errno)
	}
}
