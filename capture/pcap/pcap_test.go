package pcap

import (
	"bytes"
	"embed"
	"encoding/binary"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/fako1024/gotools/link"
	"github.com/fako1024/slimcap/capture"
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

	t.Run("invalid snaplen zero", func(t *testing.T) {
		src, err := NewSource("pcap", bytes.NewBuffer(buildTestPCAP(t, 0)))
		require.EqualError(t, err, "invalid pcap header snaplen: 0 (max 16777216)")
		require.Nil(t, src)
	})

	t.Run("invalid snaplen too large", func(t *testing.T) {
		src, err := NewSource("pcap", bytes.NewBuffer(buildTestPCAP(t, maxSnapLen+1)))
		require.EqualError(t, err, "invalid pcap header snaplen: 16777217 (max 16777216)")
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
			Name: "pcap",
			Type: link.TypeEthernet,
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
			require.Equal(t, src.Link().Type.IPHeaderOffset(), ipLayerOffset)
			return nil
		})
		require.ErrorIs(t, err, io.EOF)

		stats, err := src.Stats()
		require.Nil(t, err)
		require.Equal(t, capture.Stats{PacketsReceived: pcapTestInputNPackets}, stats)

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
				require.Equal(t, src.link.Type.IPHeaderOffset(), ipLayerOffset)
				require.NotNil(t, payload)
				require.Equal(t, capture.PacketUnknown, pktType)
				require.NotZero(t, totalLen)
				return nil
			})
			require.Nil(t, err)
		})
	})
}

func TestMalformedPacketCaptureLen(t *testing.T) {

	t.Run("negative capture length", func(t *testing.T) {
		src, err := NewSource("pcap", bytes.NewReader(buildTestPCAP(t, 64,
			testPacketRecord{captureLen: -1, originalLen: 64},
		)))
		require.Nil(t, err)
		require.NotNil(t, src)
		defer func() {
			require.Nil(t, src.Close())
		}()

		require.NotPanics(t, func() {
			payload, pktType, totalLen, err := src.NextPayload(nil)
			require.ErrorContains(t, err, "invalid packet capture length: -1")
			require.Nil(t, payload)
			require.Equal(t, capture.PacketUnknown, pktType)
			require.Zero(t, totalLen)
		})
	})

	t.Run("capture length exceeds snaplen", func(t *testing.T) {
		src, err := NewSource("pcap", bytes.NewReader(buildTestPCAP(t, 64,
			testPacketRecord{captureLen: 65, originalLen: 65},
		)))
		require.Nil(t, err)
		require.NotNil(t, src)
		defer func() {
			require.Nil(t, src.Close())
		}()

		require.NotPanics(t, func() {
			payload, pktType, totalLen, err := src.NextPayload(nil)
			require.ErrorContains(t, err, "invalid packet capture length: 65 exceeds snaplen 64")
			require.Nil(t, payload)
			require.Equal(t, capture.PacketUnknown, pktType)
			require.Zero(t, totalLen)
		})
	})
}

func TestPacketAddCallbackFnCalledOnReadSuccessOnly(t *testing.T) {

	src, err := NewSource("pcap", bytes.NewReader(buildTestPCAP(t, 64,
		testPacketRecord{captureLen: 4, originalLen: 4, payload: []byte{1, 2, 3, 4}},
		testPacketRecord{captureLen: -1, originalLen: 4},
	)))
	require.Nil(t, err)
	require.NotNil(t, src)
	defer func() {
		require.Nil(t, src.Close())
	}()

	callbackCount := 0
	var callbackPayload []byte
	src.PacketAddCallbackFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) {
		callbackCount++
		callbackPayload = append([]byte(nil), payload...)
	})

	payload, pktType, totalLen, err := src.NextPayload(nil)
	require.Nil(t, err)
	require.Equal(t, []byte{1, 2, 3, 4}, payload)
	require.Equal(t, capture.PacketUnknown, pktType)
	require.Equal(t, uint32(4), totalLen)
	require.Equal(t, 1, callbackCount)
	require.Equal(t, []byte{1, 2, 3, 4}, callbackPayload)

	payload, pktType, totalLen, err = src.NextPayload(nil)
	require.ErrorContains(t, err, "invalid packet capture length: -1")
	require.Nil(t, payload)
	require.Equal(t, capture.PacketUnknown, pktType)
	require.Zero(t, totalLen)
	require.Equal(t, 1, callbackCount)
	require.Equal(t, []byte{1, 2, 3, 4}, callbackPayload)
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

type testPacketRecord struct {
	captureLen  int32
	originalLen int32
	payload     []byte
}

func buildTestPCAP(t *testing.T, snapLen uint32, packets ...testPacketRecord) []byte {
	t.Helper()

	var out bytes.Buffer
	write := func(v interface{}) {
		require.Nil(t, binary.Write(&out, binary.LittleEndian, v))
	}

	write(uint32(MagicNativeEndianess))
	write(uint16(2))
	write(uint16(4))
	write(int32(0))
	write(uint32(0))
	write(snapLen)
	write(uint32(link.TypeEthernet))

	for _, packet := range packets {
		write(int32(0))
		write(int32(0))
		write(packet.captureLen)
		write(packet.originalLen)

		if packet.captureLen > 0 {
			captureLen := int(packet.captureLen)
			payload := packet.payload
			if len(payload) < captureLen {
				payload = make([]byte, captureLen)
				copy(payload, packet.payload)
			} else {
				payload = payload[:captureLen]
			}

			_, err := out.Write(payload)
			require.Nil(t, err)
		}
	}

	return out.Bytes()
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
