//go:build !slimcap_nomock
// +build !slimcap_nomock

package pcap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/afring"
	"github.com/fako1024/slimcap/filter"
	"github.com/stretchr/testify/require"
)

func TestMockPipe(t *testing.T) {

	for _, dirent := range testData {
		file, err := os.Open(filepath.Join(testDataPath, dirent.Name()))
		require.Nil(t, err)
		defer func() {
			require.Nil(t, file.Close())
		}()

		src, err := NewSource("pcap", file)
		require.Nil(t, err)

		// Setup a mock source
		mockSrc, err := afring.NewMockSource("mock",
			afring.CaptureLength(filter.CaptureLengthMinimalIPv4Transport),
		)
		require.Nil(t, err)
		errChan := mockSrc.Pipe(src, nil)

		for i := 0; i < pcapTestInputNPackets; i++ {
			p, err := mockSrc.NextPacket(nil)
			require.Nil(t, err)
			require.NotNil(t, p)
			require.Equal(t, capture.PacketUnknown, p.Type())
			require.NotZero(t, p.TotalLen())
		}
		mockSrc.ForceBlockRelease()

		// Block and check for any errors that may have happened while piping
		require.Nil(t, <-errChan)

		require.Nil(t, src.Close())
	}
}
