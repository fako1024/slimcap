package pcap

import (
	"bytes"
	"embed"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/afring"
	"github.com/fako1024/slimcap/link"
	"github.com/stretchr/testify/require"
)

const (
	pcapTestInputNPackets = 6
	testDataPath          = "testdata"
)

var testData []fs.DirEntry

func TestInvalidInput(t *testing.T) {

	t.Run("nil reader", func(t *testing.T) {
		src, err := NewSource("pcap", nil)
		require.EqualError(t, err, "nil io.Reader provided")
		require.Nil(t, src)
	})

	t.Run("nil data", func(t *testing.T) {
		src, err := NewSource("pcap", bytes.NewBuffer(nil))
		require.ErrorIs(t, err, io.EOF)
		require.Nil(t, src)
	})

	t.Run("empty data", func(t *testing.T) {
		src, err := NewSource("pcap", bytes.NewBuffer([]byte{}))
		require.ErrorIs(t, err, io.EOF)
		require.Nil(t, src)
	})

	t.Run("truncated data", func(t *testing.T) {
		invalidData := make([]byte, 23)
		src, err := NewSource("pcap", bytes.NewBuffer(invalidData))
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		require.Nil(t, src)
	})

	t.Run("invalid data", func(t *testing.T) {
		invalidData := make([]byte, 32)
		src, err := NewSource("pcap", bytes.NewBuffer(invalidData))
		require.EqualError(t, err, "invalid pcap header magic: 0")
		require.Nil(t, src)
	})
}

func TestReader(t *testing.T) {

	for _, dirent := range testData {
		file, err := os.Open(filepath.Join(testDataPath, dirent.Name()))
		require.Nil(t, err)
		defer func() {
			require.Nil(t, file.Close())
		}()

		src, err := NewSource("pcap", file)
		require.Nil(t, err)

		require.Equal(t, &link.Link{
			Type: link.TypeEthernet,
			Interface: &net.Interface{
				Name:  "pcap",
				Flags: net.FlagUp,
			},
		}, src.Link())

		for i := 0; i < pcapTestInputNPackets; i++ {
			pkt, err := src.NextPacket(nil)
			require.Nil(t, err)
			_ = pkt
		}

		// After all packets are read, we expect an EOF on all methods
		pkt, err := src.NextPacket(nil)
		require.ErrorIs(t, err, io.EOF)
		require.Nil(t, pkt)

		ipLayer, pktType, totalLen, err := src.NextIPPacket(nil)
		require.ErrorIs(t, err, io.EOF)
		require.Zero(t, totalLen)
		require.Equal(t, capture.PacketUnknown, pktType)
		require.Nil(t, ipLayer)

		err = src.NextPacketFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) error {
			require.Nil(t, payload)
			require.Zero(t, totalLen)
			require.Equal(t, capture.PacketUnknown, pktType)
			require.Equal(t, src.Link().Type.IpHeaderOffset(), ipLayerOffset)
			return nil
		})
		require.ErrorIs(t, err, io.EOF)

		stats, err := src.Stats()
		require.Nil(t, err)
		require.Equal(t, capture.Stats{PacketsReceived: pcapTestInputNPackets}, stats)

		require.Nil(t, src.Close())
		require.Nil(t, src.Free())
	}

}

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
			afring.CaptureLength(link.CaptureLengthMinimalIPv4Transport),
		)
		require.Nil(t, err)
		errChan := mockSrc.Pipe(src)

		for i := 0; i < pcapTestInputNPackets; i++ {
			p, err := mockSrc.NextPacket(nil)
			require.Nil(t, err)
			require.NotNil(t, p)
			require.Equal(t, capture.PacketUnknown, p.Type())
			require.NotZero(t, p.TotalLen())
		}

		// Block and check for any errors that may have happened while piping
		require.Nil(t, <-errChan)

		require.Nil(t, src.Close())
	}
}

func TestCaptureMethods(t *testing.T) {

	t.Run("NextPacket", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *Source) {
			p, err := src.NextPacket(nil)
			require.Nil(t, err)
			require.NotNil(t, p)
		})
	})

	t.Run("NextPacketInPlace", func(t *testing.T) {
		var p capture.Packet
		testCaptureMethods(t, func(t *testing.T, src *Source) {

			// Use NewPacket() method of source to instantiate a new reusable packet buffer
			if cap(p) == 0 {
				p = src.NewPacket()
			}

			_, err := src.NextPacket(p)
			require.Nil(t, err)
			require.NotNil(t, p)
		})
	})

	t.Run("NextPayload", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *Source) {
			p, pktType, totalLen, err := src.NextPayload(nil)
			require.Nil(t, err)
			require.NotNil(t, p)
			require.Equal(t, capture.PacketUnknown, pktType)
			require.NotZero(t, totalLen)
		})
	})

	t.Run("NextPayloadInPlace", func(t *testing.T) {
		var p capture.IPLayer
		testCaptureMethods(t, func(t *testing.T, src *Source) {

			// Use NewPacket() method of source to instantiate a new reusable packet buffer
			if cap(p) == 0 {
				pkt := src.NewPacket()
				p = pkt.Payload()
			}

			_, pktType, totalLen, err := src.NextPayload(p)
			require.Nil(t, err)
			require.NotNil(t, p)
			require.Equal(t, capture.PacketUnknown, pktType)
			require.NotZero(t, totalLen)
		})
	})

	t.Run("NextIPPacket", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *Source) {
			p, pktType, totalLen, err := src.NextIPPacket(nil)
			require.Nil(t, err)
			require.NotNil(t, p)
			require.Equal(t, capture.PacketUnknown, pktType)
			require.NotZero(t, totalLen)
		})
	})

	t.Run("NextIPPacketInPlace", func(t *testing.T) {
		var p capture.IPLayer
		testCaptureMethods(t, func(t *testing.T, src *Source) {

			// Use NewPacket() method of source to instantiate a new reusable packet buffer
			if cap(p) == 0 {
				pkt := src.NewPacket()
				p = pkt.IPLayer()
			}

			_, pktType, totalLen, err := src.NextIPPacket(p)
			require.Nil(t, err)
			require.NotNil(t, p)
			require.Equal(t, capture.PacketUnknown, pktType)
			require.NotZero(t, totalLen)
		})
	})

	t.Run("NextPacketFn", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *Source) {
			err := src.NextPacketFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) error {
				require.Equal(t, src.link.Type.IpHeaderOffset(), ipLayerOffset)
				require.NotNil(t, payload)
				require.Equal(t, capture.PacketUnknown, pktType)
				require.NotZero(t, totalLen)
				return nil
			})
			require.Nil(t, err)
		})
	})
}

func testCaptureMethods(t *testing.T, fn func(t *testing.T, src *Source)) {
	for _, dirent := range testData {
		file, err := os.Open(filepath.Join(testDataPath, dirent.Name()))
		require.Nil(t, err)
		defer func() {
			require.Nil(t, file.Close())
		}()

		src, err := NewSource("pcap", file)
		require.Nil(t, err)

		for i := 0; i < pcapTestInputNPackets; i++ {
			fn(t, src)
		}

		require.Nil(t, src.Close())
	}
}

//go:embed testdata/*
var pcaps embed.FS

func TestMain(m *testing.M) {

	var err error
	if testData, err = pcaps.ReadDir(testDataPath); err != nil {
		panic(err)
	}

	os.Exit(m.Run())
}
