package afring

import (
	"fmt"
	"net"
	"testing"

	"github.com/fako1024/slimcap/capture"
	"github.com/stretchr/testify/require"
)

func TestBlockSizeAlignment(t *testing.T) {
	var (
		blockNr = 4
		snapLen = 64
	)
	for i := 0; i < 12; i++ {
		_, err := newTPacketRequestForBuffer((1 << i), blockNr, snapLen)
		require.EqualError(t, err, fmt.Sprintf("block size %d not aligned to page size", (1<<i)))
	}
	for i := 12; i < 28; i++ {
		req, err := newTPacketRequestForBuffer((1 << i), blockNr, snapLen)
		require.Nil(t, err)
		require.Equal(t, uint32(1<<i), req.blockSize)
		require.Equal(t, uint32(blockNr), req.blockNr)
		require.Equal(t, int(blockNr*(1<<i)), req.blockSizeNr())
	}
	for i := 0; i < 32; i++ {
		_, err := newTPacketRequestForBuffer((1<<i)+1, blockNr, snapLen)
		require.EqualError(t, err, fmt.Sprintf("block size %d not aligned to page size", (1<<i)+1))
	}
}

func TestOptions(t *testing.T) {

	t.Run("CaptureLength", func(t *testing.T) {
		for _, captureLen := range []int{
			1, 10, 64, 128, DefaultSnapLen, 2 * DefaultSnapLen,
		} {
			mockSrc, err := NewMockSource("mock",
				CaptureLength(captureLen),
			)
			require.Nil(t, err)
			require.Equal(t, captureLen, mockSrc.snapLen)

			frameSize, err := blockSizeTPacketAlign(tPacketHeaderLen+captureLen, tPacketDefaultBlockSize)
			require.Nil(t, err)

			require.Equal(t, uint32(frameSize), mockSrc.tpReq.frameSize)
		}
	})

	t.Run("Promiscuous", func(t *testing.T) {
		for _, isPromisc := range []bool{
			true, false,
		} {
			mockSrc, err := NewMockSource("mock",
				Promiscuous(isPromisc),
			)
			require.Nil(t, err)
			require.Equal(t, isPromisc, mockSrc.isPromisc)
		}
	})

	t.Run("BufferSize", func(t *testing.T) {
		for _, blockSize := range []int{
			4096 * 100, tPacketDefaultBlockSize, 2 * tPacketDefaultBlockSize,
		} {
			for _, nBlocks := range []int{
				1, 2, 4, 64,
			} {
				mockSrc, err := NewMockSource("mock",
					BufferSize(blockSize, nBlocks),
				)
				require.Nilf(t, err, "blockSize %d, nBlocks %d", blockSize, nBlocks)

				frameSize, err := blockSizeTPacketAlign(tPacketHeaderLen+mockSrc.snapLen, blockSize)
				require.Nil(t, err)
				require.Equal(t, uint32(frameSize), mockSrc.tpReq.frameSize)
				require.Equal(t, uint32(pageSizeAlign(blockSize)), mockSrc.tpReq.blockSize)
				require.Equal(t, uint32(nBlocks), mockSrc.tpReq.blockNr)
			}
		}
	})

}

func TestCaptureMethods(t *testing.T) {

	t.Run("NextPacket", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {
			p, err := src.NextPacket(nil)
			require.Nil(t, err)
			validatePacket(t, p, i, j)
		})
	})

	t.Run("NextPacketInPlace", func(t *testing.T) {
		var p capture.Packet
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {

			// Use NewPacket() method of source to instantiate a new reusable packet buffer
			if cap(p) == 0 {
				p = src.NewPacket()
			}

			_, err := src.NextPacket(p)
			require.Nil(t, err)
			validatePacket(t, p, i, j)
		})
	})

	t.Run("NextIPPacket", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {
			p, pktType, totalLen, err := src.NextIPPacket(nil)
			require.Nil(t, err)
			validateIPPacket(t, p, pktType, totalLen, i, j)
		})
	})

	t.Run("NextIPPacketInPlace", func(t *testing.T) {
		var p capture.IPLayer
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {

			// Use NewPacket() method of source to instantiate a new reusable packet buffer
			if cap(p) == 0 {
				pkt := src.NewPacket()
				p = pkt.IPLayer()
			}

			_, pktType, totalLen, err := src.NextIPPacket(p)
			require.Nil(t, err)
			validateIPPacket(t, p, pktType, totalLen, i, j)
		})
	})

	t.Run("NextPacketFn", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {
			err := src.NextPacketFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) error {
				require.Equal(t, src.link.Type.IpHeaderOffset(), ipLayerOffset)
				require.Equal(t, uint32(i+j), totalLen)
				require.Equal(t, byte(i+j)%5, pktType)
				require.Equal(t, fmt.Sprintf("10.0.0.%d:%d => 10.0.0.%d:%d (proto: %d)", i%254+1, i, j%254+1, j, 6), capture.IPLayer(payload[ipLayerOffset:]).String())
				return nil
			})
			require.Nil(t, err)
		})
	})
}

func testCaptureMethods(t *testing.T, fn func(t *testing.T, src *MockSource, i, j uint16)) {

	// Setup a mock source
	mockSrc, err := NewMockSource("mock",
		CaptureLength(64),
		Promiscuous(false),
		BufferSize(1024*1024, 5),
	)
	require.Nil(t, err)

	// Continuously populate the ring buffer in the background
	errChan := mockSrc.Run()
	var n = uint16(100)
	go func() {
		for i := uint16(1); i <= n; i++ {
			for j := uint16(1); j <= n; j++ {

				p, err := capture.BuildPacket(
					net.ParseIP(fmt.Sprintf("10.0.0.%d", i%254+1)),
					net.ParseIP(fmt.Sprintf("10.0.0.%d", j%254+1)),
					i,
					j,
					6, []byte{byte(i), byte(j)}, byte(i+j)%5, int(i+j))
				require.Nil(t, err)

				mockSrc.AddPacket(p)
			}
		}
		mockSrc.FinalizeBlock()
		mockSrc.Done()
	}()

	// Consume data from the source via the respective method
	for i := uint16(1); i <= n; i++ {
		for j := uint16(1); j <= n; j++ {
			fn(t, mockSrc, i, j)
		}
	}

	// Block and check for any errors that may have happened in the goroutine
	require.Nil(t, <-errChan)

	// Evaluate packet statistics
	stats, err := mockSrc.Stats()
	require.Nil(t, err)
	require.Equal(t, capture.Stats{PacketsReceived: int(n * n)}, stats)

	// Close the mock source
	require.Nil(t, mockSrc.Close())
}

func validatePacket(t *testing.T, p capture.Packet, i, j uint16) {
	validateIPPacket(t, p.IPLayer(), p.Type(), p.TotalLen(), i, j)
}

func validateIPPacket(t *testing.T, p capture.IPLayer, pktType capture.PacketType, totalLen uint32, i, j uint16) {
	require.Equal(t, uint32(i+j), totalLen)
	require.Equal(t, byte(i+j)%5, pktType)
	require.Equal(t, fmt.Sprintf("10.0.0.%d:%d => 10.0.0.%d:%d (proto: %d)", i%254+1, i, j%254+1, j, 6), p.String())
	c, err := capture.BuildPacket(
		net.ParseIP(fmt.Sprintf("10.0.0.%d", i%254+1)),
		net.ParseIP(fmt.Sprintf("10.0.0.%d", j%254+1)),
		i,
		j,
		6, []byte{byte(i), byte(j)}, byte(i+j)%5, int(i+j))
	require.Nil(t, err)
	require.Equalf(t, c.IPLayer(), p[:len(c.IPLayer())], "%v vs. %v", c.IPLayer(), p)
}
