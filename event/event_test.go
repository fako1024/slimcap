//go:build linux
// +build linux

package event

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMultiEvents(t *testing.T) {
	handler, err := New()
	require.Nil(t, err)

	for i := 0; i < 300; i++ {
		require.Nil(t, handler.Signal(SignalUnblock))
	}
	require.Nil(t, handler.Signal(SignalStop))
	evtData, err := handler.ReadEvent()
	require.Nil(t, err)
	require.Equal(t, EvtData{44, 1, 0, 0, 0, 0, 0, 1}, evtData)

	require.Nil(t, handler.Signal(SignalUnblock))
	evtData, err = handler.ReadEvent()
	require.Nil(t, err)
	require.Equal(t, EvtData{1, 0, 0, 0, 0, 0, 0, 0}, evtData)

	require.Nil(t, handler.Signal(SignalStop))
	evtData, err = handler.ReadEvent()
	require.Nil(t, err)
	require.Equal(t, EvtData{0, 0, 0, 0, 0, 0, 0, 1}, evtData)
}
