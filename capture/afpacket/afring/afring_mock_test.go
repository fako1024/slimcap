//go:build !slimcap_nomock
// +build !slimcap_nomock

package afring

import (
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/link"
	"github.com/stretchr/testify/require"
)

func TestOptions(t *testing.T) {

	t.Run("CaptureLength", func(t *testing.T) {
		for _, captureLen := range []link.CaptureLengthStrategy{
			link.CaptureLengthFixed(1),
			link.CaptureLengthFixed(10),
			link.CaptureLengthFixed(64),
			link.CaptureLengthFixed(128),
			link.CaptureLengthFixed(DefaultSnapLen),
			link.CaptureLengthFixed(2 * DefaultSnapLen),
			link.CaptureLengthMinimalIPv4Header,
			link.CaptureLengthMinimalIPv4Transport,
			link.CaptureLengthMinimalIPv6Header,
			link.CaptureLengthMinimalIPv6Transport,
		} {
			mockSrc, err := NewMockSource("mock",
				CaptureLength(captureLen),
			)
			require.Nil(t, err)
			require.Equal(t, captureLen(mockSrc.link), mockSrc.snapLen)

			frameSize, err := blockSizeTPacketAlign(tPacketHeaderLen+captureLen(mockSrc.link), tPacketDefaultBlockSize)
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

func TestClosedSource(t *testing.T) {

	// Setup a mock source
	mockSrc, err := NewMockSource("mock",
		CaptureLength(link.CaptureLengthMinimalIPv4Transport),
		Promiscuous(false),
		BufferSize(1024*1024, 5),
	)
	require.Nil(t, err)

	// Close it right away
	require.Nil(t, mockSrc.Close())

	// Attempt to read from the source
	pkt, err := mockSrc.NextPacket(nil)
	require.Nil(t, pkt)
	require.ErrorIs(t, err, capture.ErrCaptureStopped)

	// Attempt to read from the source
	pkt, err = mockSrc.NextPacket(nil)
	require.Nil(t, pkt)
	require.ErrorIs(t, err, capture.ErrCaptureStopped)
}

func TestClosedSourceNoDrain(t *testing.T) {

	// Setup a mock source
	mockSrc, err := NewMockSourceNoDrain("mock",
		CaptureLength(link.CaptureLengthMinimalIPv4Transport),
		Promiscuous(false),
		BufferSize(1024*1024, 5),
	)
	require.Nil(t, err)

	// Initial attempt without data should fail
	errChan, err := mockSrc.Run(time.Millisecond)
	require.ErrorIs(t, err, ErrMockBufferNotPopulated)
	require.Nil(t, errChan)

	// In no drain mode the ring buffer has to be populated in
	// order to avoid weird behavior when trying to consume from it
	p, err := capture.BuildPacket(
		net.ParseIP("1.2.3.4"),
		net.ParseIP("5.6.7.8"),
		5555,
		80,
		6, []byte{}, capture.PacketOtherHost, 256)
	require.Nil(t, err)
	for mockSrc.CanAddPackets() {
		require.Nil(t, mockSrc.AddPacket(p))
	}
	errChan, err = mockSrc.Run(time.Millisecond)
	require.Nil(t, err)

	// Close it right away
	require.Nil(t, mockSrc.Close())

	// Attempt to read from the source
	pkt, err := mockSrc.NextPacket(nil)
	require.Nil(t, pkt)
	require.ErrorIs(t, err, capture.ErrCaptureStopped)
	require.Nil(t, <-errChan)

	// Attempt to read from the source
	pkt, err = mockSrc.NextPacket(nil)
	require.Nil(t, pkt)
	require.ErrorIs(t, err, capture.ErrCaptureStopped)
	require.Nil(t, <-errChan)
}

func TestFillRingBuffer(t *testing.T) {

	// Setup the original mock source
	mockSrc, err := NewMockSource("mock",
		CaptureLength(link.CaptureLengthMinimalIPv4Transport),
		Promiscuous(false),
		BufferSize(1024*1024, 5),
	)
	require.Nil(t, err)

	// Continuously populate the ring buffer until it's full
	var i, j uint16
	for {
		if !mockSrc.CanAddPackets() {
			mockSrc.FinalizeBlock(false)
			break
		}

		p, err := capture.BuildPacket(
			net.ParseIP(fmt.Sprintf("1.2.3.%d", i%254+1)),
			net.ParseIP(fmt.Sprintf("4.5.6.%d", j%254+1)),
			i,
			j,
			6, []byte{byte(i), byte(j)}, byte(i+j)%5, int(i+j))
		require.Nil(t, err)

		require.Nil(t, mockSrc.AddPacket(p))
		i++
		j++
	}

}

func TestUnblockOnClose(t *testing.T) {

	mockSrc, err := NewMockSource("mock",
		Promiscuous(false),
	)
	require.Nil(t, err)

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		_, err := mockSrc.NextPacket(nil)
		require.ErrorIs(t, capture.ErrCaptureStopped, err)

		wg.Done()
	}(wg)

	// Since there is no way to know if the goroutine is actually
	// already blocking we have to wait a sufficient amount of time
	time.Sleep(time.Second)
	require.Nil(t, mockSrc.Close())

	wg.Wait()
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
		var p capture.Packet = make(capture.Packet, DefaultSnapLen+6)
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {

			// Use NewPacket() method of source to instantiate a new reusable packet buffer
			if cap(p) == 0 {
				p = src.NewPacket()
			}

			p, err := src.NextPacket(p)
			require.Nil(t, err)
			validatePacket(t, p, i, j)
		})
	})

	t.Run("NextPayload", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {
			p, pktType, totalLen, err := src.NextPayload(nil)
			require.Nil(t, err)
			validateIPPacket(t, p[src.ipLayerOffset:], pktType, totalLen, i, j)
		})
	})

	t.Run("NextPayloadInPlace", func(t *testing.T) {
		var p = make([]byte, DefaultSnapLen)
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {

			// Use NewPacket() method of source to instantiate a new reusable packet buffer
			if cap(p) == 0 {
				pkt := src.NewPacket()
				p = pkt.Payload()
			}

			p, pktType, totalLen, err := src.NextPayload(p)
			require.Nil(t, err)
			validateIPPacket(t, p[src.ipLayerOffset:], pktType, totalLen, i, j)
		})
	})

	t.Run("NextPayloadZeroCopy", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {
			p, pktType, totalLen, err := src.NextPayloadZeroCopy()
			require.Nil(t, err)
			validateIPPacket(t, p[src.ipLayerOffset:], pktType, totalLen, i, j)
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
		var p capture.IPLayer = make(capture.IPLayer, DefaultSnapLen)
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {

			// Use NewPacket() method of source to instantiate a new reusable packet buffer
			if cap(p) == 0 {
				pkt := src.NewPacket()
				p = pkt.IPLayer()
			}

			p, pktType, totalLen, err := src.NextIPPacket(p)
			require.Nil(t, err)
			validateIPPacket(t, p, pktType, totalLen, i, j)
		})
	})

	t.Run("NextIPPacketZeroCopy", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {
			p, pktType, totalLen, err := src.NextIPPacketZeroCopy()
			require.Nil(t, err)
			validateIPPacket(t, p, pktType, totalLen, i, j)
		})
	})

	t.Run("NextPacketFn", func(t *testing.T) {
		testCaptureMethods(t, func(t *testing.T, src *MockSource, i, j uint16) {
			err := src.NextPacketFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) error {
				require.Equal(t, src.link.Type.IPHeaderOffset(), ipLayerOffset)
				require.Equal(t, int(i*1000+j), int(totalLen))
				require.Equal(t, byte(i+j)%5, pktType)
				require.Equal(t, fmt.Sprintf("1.2.3.%d:%d => 4.5.6.%d:%d (proto: %d)", i%254+1, i, j%254+1, j, 6), capture.IPLayer(payload[ipLayerOffset:]).String())
				return nil
			})
			require.Nil(t, err)
		})
	})
}

func TestPipe(t *testing.T) {

	// Setup the original mock source
	mockSrc, err := NewMockSource("mock",
		CaptureLength(link.CaptureLengthMinimalIPv6Transport),
		Promiscuous(false),
		BufferSize(1024*16, 8),
	)
	require.Nil(t, err)

	// Continuously populate the ring buffer in the background
	errChan := mockSrc.Run()
	var n = uint16(100)
	go func() {
		for i := uint16(1); i <= n; i++ {
			for j := uint16(1); j <= n; j++ {

				p, err := capture.BuildPacket(
					net.ParseIP(fmt.Sprintf("1.2.3.%d", i%254+1)),
					net.ParseIP(fmt.Sprintf("4.5.6.%d", j%254+1)),
					i,
					j,
					6, []byte{byte(i), byte(j)}, byte(i+j)%5, int(i*1000+j))
				require.Nil(t, err)

				require.Nil(t, mockSrc.AddPacket(p))
			}
		}

		mockSrc.FinalizeBlock(false)
		mockSrc.Done()

		require.Nil(t, <-errChan)
		stats, err := mockSrc.Stats()
		require.Nil(t, err)
		require.Equal(t, capture.Stats{PacketsReceived: uint64(n * n)}, stats)
		require.Nil(t, mockSrc.Close())
	}()

	// Setup the mock source used to pipe the first one
	mockSrc2, err := NewMockSource("mock2",
		CaptureLength(link.CaptureLengthMinimalIPv4Transport),
		Promiscuous(false),
	)
	require.Nil(t, err)

	readDoneChan := make(chan struct{}, 1)
	errChan2 := mockSrc2.Pipe(mockSrc, readDoneChan)

	// Consume data from the source via the respective method
	for i := uint16(1); i <= n; i++ {
		for j := uint16(1); j <= n; j++ {
			p, err := mockSrc2.NextPacket(nil)
			require.Nil(t, err)
			validatePacket(t, p, i, j)
		}
	}
	mockSrc2.ForceBlockRelease()

	<-readDoneChan

	require.Nil(t, <-errChan2)
	stats, err := mockSrc2.Stats()
	require.Nil(t, err)
	require.Equal(t, capture.Stats{PacketsReceived: uint64(n * n)}, stats)
	require.Nil(t, mockSrc2.Close())
}

func BenchmarkCaptureMethods(b *testing.B) {

	testPacket, err := capture.BuildPacket(
		net.ParseIP("1.2.3.4"),
		net.ParseIP("4.5.6.7"),
		1,
		2,
		6, []byte{1, 2}, 0, 128)
	require.Nil(b, err)

	for _, benchConfig := range []struct {
		blockSize   int
		nBlocks     int
		blockExpiry time.Duration
	}{
		{10 * 1024 * 1024, 4, time.Microsecond},
		{10 * 1024, 512, 10 * time.Nanosecond},
	} {

		// Setup a mock source
		mockSrc, err := NewMockSourceNoDrain("mock",
			CaptureLength(link.CaptureLengthMinimalIPv4Transport),
			BufferSize(benchConfig.blockSize, benchConfig.nBlocks),
			Promiscuous(false),
		)
		require.Nil(b, err)

		for mockSrc.CanAddPackets() {
			require.Nil(b, mockSrc.AddPacket(testPacket))
		}
		_, err = mockSrc.Run(benchConfig.blockExpiry)
		require.Nil(b, err)

		b.Run(fmt.Sprintf("NextPacket_%dkiBx%d", benchConfig.blockSize/1000, benchConfig.nBlocks), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				p, _ := mockSrc.NextPacket(nil)
				_ = p
			}
		})

		b.Run(fmt.Sprintf("NextPacketInPlace_%dkiBx%d", benchConfig.blockSize/1000, benchConfig.nBlocks), func(b *testing.B) {
			var p capture.Packet = mockSrc.NewPacket()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p, _ = mockSrc.NextPacket(p)
				_ = p
			}
		})

		b.Run(fmt.Sprintf("NextPayload_%dkiBx%d", benchConfig.blockSize/1000, benchConfig.nBlocks), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				p, pktType, totalLen, _ := mockSrc.NextPayload(nil)
				_ = p
				_ = pktType
				_ = totalLen
			}
		})

		b.Run(fmt.Sprintf("NextPayloadInPlace_%dkiBx%d", benchConfig.blockSize/1000, benchConfig.nBlocks), func(b *testing.B) {
			pkt := mockSrc.NewPacket()
			var p []byte = pkt.Payload()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p, pktType, totalLen, _ := mockSrc.NextPayload(p)
				_ = p
				_ = pktType
				_ = totalLen
			}
		})

		b.Run(fmt.Sprintf("NextPayloadZeroCopy_%dkiBx%d", benchConfig.blockSize/1000, benchConfig.nBlocks), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				p, pktType, totalLen, _ := mockSrc.NextPayloadZeroCopy()
				_ = p
				_ = pktType
				_ = totalLen
			}
		})

		b.Run(fmt.Sprintf("NextIPPacket_%dkiBx%d", benchConfig.blockSize/1000, benchConfig.nBlocks), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				p, pktType, totalLen, _ := mockSrc.NextIPPacket(nil)
				_ = p
				_ = pktType
				_ = totalLen
			}
		})

		b.Run(fmt.Sprintf("NextIPPacketInPlace_%dkiBx%d", benchConfig.blockSize/1000, benchConfig.nBlocks), func(b *testing.B) {
			pkt := mockSrc.NewPacket()
			var p capture.IPLayer = pkt.IPLayer()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				p, pktType, totalLen, _ := mockSrc.NextIPPacket(p)
				_ = p
				_ = pktType
				_ = totalLen
			}
		})

		b.Run(fmt.Sprintf("NextIPPacketZeroCopy_%dkiBx%d", benchConfig.blockSize/1000, benchConfig.nBlocks), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				p, pktType, totalLen, _ := mockSrc.NextIPPacketZeroCopy()
				_ = p
				_ = pktType
				_ = totalLen
			}
		})

		b.Run(fmt.Sprintf("NextPacketFn_%dkiBx%d", benchConfig.blockSize/1000, benchConfig.nBlocks), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = mockSrc.NextPacketFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) error {
					_ = payload
					_ = totalLen
					_ = pktType
					return nil
				})
			}
		})

		require.Nil(b, mockSrc.Close())
	}
}

func testCaptureMethods(t *testing.T, fn func(t *testing.T, _ *MockSource, _, _ uint16)) {

	// Setup a mock source
	mockSrc, err := NewMockSource("mock",
		CaptureLength(link.CaptureLengthMinimalIPv4Transport),
		Promiscuous(false),
		BufferSize(1024*16, 8),
	)
	require.Nil(t, err)

	// Continuously populate the ring buffer in the background
	errChan := mockSrc.Run()
	var n = uint16(100)
	go func() {
		for i := uint16(1); i <= n; i++ {
			for j := uint16(1); j <= n; j++ {

				p, err := capture.BuildPacket(
					net.ParseIP(fmt.Sprintf("1.2.3.%d", i%254+1)),
					net.ParseIP(fmt.Sprintf("4.5.6.%d", j%254+1)),
					i,
					j,
					6, []byte{byte(i), byte(j)}, byte(i+j)%5, int(i*1000+j))
				require.Nil(t, err)

				require.Nil(t, mockSrc.AddPacket(p))
			}
		}
		mockSrc.FinalizeBlock(false)
		mockSrc.Done()
	}()

	// Consume data from the source via the respective method
	for i := uint16(1); i <= n; i++ {
		for j := uint16(1); j <= n; j++ {
			fn(t, mockSrc, i, j)
		}
		_, err := mockSrc.MockFd.GetSocketStatsNoReset()
		require.Nil(t, err)
	}
	mockSrc.ForceBlockRelease()

	// Block and check for any errors that may have happened in the goroutine
	require.Nil(t, <-errChan)

	// Evaluate packet statistics
	stats, err := mockSrc.Stats()
	require.Nil(t, err)
	require.Equal(t, capture.Stats{PacketsReceived: uint64(n * n)}, stats)

	// Close the mock source
	require.Nil(t, mockSrc.Close())
}
