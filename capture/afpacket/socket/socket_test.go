//go:build linux && !slimcap_nomock
// +build linux,!slimcap_nomock

package socket

import (
	"errors"
	"sync"
	"testing"

	"github.com/fako1024/gotools/link"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

const nPolls = 1000000

func TestBasicInteraction(t *testing.T) {

	sock, err := NewMock()
	require.Nil(t, err)
	require.True(t, sock.IsOpen())

	sock.IncrementPacketCount(1)

	stats, err := sock.GetSocketStats()
	require.Nil(t, err)
	require.EqualValues(t, TPacketStats{Packets: 1}, stats)

	require.Nil(t, sock.Close())
	require.False(t, sock.IsOpen())

	stats, err = sock.GetSocketStats()
	require.ErrorIs(t, err, ErrInvalidSocket)
	require.EqualValues(t, TPacketStats{}, stats)
}

func TestPacketCounter(t *testing.T) {

	sock, err := NewMock()
	require.Nil(t, err)

	wg := sync.WaitGroup{}
	wg.Add(2)

	go func() {
		for i := 0; i < nPolls; i++ {
			sock.IncrementPacketCount(1)
		}
		wg.Done()
	}()

	go func(t *testing.T) {
		var nPacketsSeen uint32
		for {
			stats, err := sock.GetSocketStats()
			require.Nil(t, err)

			nPacketsSeen += stats.Packets
			if nPacketsSeen == nPolls {
				wg.Done()
				return
			}
		}
	}(t)

	wg.Wait()

	require.Nil(t, sock.Close())
}

func TestSetPromiscuousModeUsesPacketSocketOptions(t *testing.T) {
	origSetPacketMembership := setPacketMembership
	t.Cleanup(func() {
		setPacketMembership = origSetPacketMembership
	})

	var called bool
	setPacketMembership = func(fd, level, opt int, mreq *unix.PacketMreq) error {
		called = true
		require.Equal(t, 1234, fd)
		require.Equal(t, unix.SOL_PACKET, level)
		require.Equal(t, unix.PACKET_ADD_MEMBERSHIP, opt)
		require.EqualValues(t, 42, mreq.Ifindex)
		require.EqualValues(t, unix.PACKET_MR_PROMISC, mreq.Type)
		return nil
	}

	err := setPromiscuousMode(FileDescriptor(1234), &link.Link{Index: 42})
	require.Nil(t, err)
	require.True(t, called)
}

func TestSetPromiscuousModePropagatesError(t *testing.T) {
	origSetPacketMembership := setPacketMembership
	t.Cleanup(func() {
		setPacketMembership = origSetPacketMembership
	})

	expectedErr := errors.New("membership failure")
	setPacketMembership = func(fd, level, opt int, mreq *unix.PacketMreq) error {
		return expectedErr
	}

	err := setPromiscuousMode(FileDescriptor(1234), &link.Link{Index: 42})
	require.ErrorIs(t, err, expectedErr)
}
