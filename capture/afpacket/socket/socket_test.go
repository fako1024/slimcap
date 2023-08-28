//go:build linux && !slimcap_nomock
// +build linux,!slimcap_nomock

package socket

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
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
	require.EqualError(t, err, "invalid socket")
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
