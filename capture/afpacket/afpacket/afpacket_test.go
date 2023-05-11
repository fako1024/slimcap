package afpacket

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
		var p capture.Packet
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
		var p []byte
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

			p, pktType, totalLen, err := src.NextIPPacket(p)
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
		CaptureLength(link.CaptureLengthMinimalIPv4Transport),
		Promiscuous(false),
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
					6, []byte{byte(i), byte(j)}, byte(i+j)%5, int(i+j))
				require.Nil(t, err)

				require.Nil(t, mockSrc.AddPacket(p))
			}
		}

		mockSrc.Done()

		require.Nil(t, <-errChan)
		stats, err := mockSrc.Stats()
		require.Nil(t, err)
		require.Equal(t, capture.Stats{PacketsReceived: int(n * n)}, stats)
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
	<-readDoneChan

	require.Nil(t, <-errChan2)
	stats, err := mockSrc2.Stats()
	require.Nil(t, err)
	require.Equal(t, capture.Stats{PacketsReceived: int(n * n)}, stats)
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

	// Setup a mock source
	mockSrc, err := NewMockSource("mock",
		CaptureLength(link.CaptureLengthMinimalIPv4Transport),
		Promiscuous(false),
	)
	require.Nil(b, err)

	for mockSrc.CanAddPackets() {
		mockSrc.AddPacket(testPacket)
	}
	mockSrc.RunNoDrain()

	b.Run("NextPacket", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p, _ := mockSrc.NextPacket(nil)
			_ = p
		}
	})

	b.Run("NextPacketInPlace", func(b *testing.B) {
		var p capture.Packet = mockSrc.NewPacket()
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			p, _ = mockSrc.NextPacket(p)
			_ = p
		}
	})

	b.Run("NextIPPacket", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			p, pktType, totalLen, _ := mockSrc.NextIPPacket(nil)
			_ = p
			_ = pktType
			_ = totalLen
		}
	})

	b.Run("NextIPPacketInPlace", func(b *testing.B) {
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

	b.Run("NextPacketFn", func(b *testing.B) {
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
}

func testCaptureMethods(t *testing.T, fn func(t *testing.T, src *MockSource, i, j uint16)) {

	// Setup a mock source
	mockSrc, err := NewMockSource("mock",
		CaptureLength(link.CaptureLengthMinimalIPv4Transport),
		Promiscuous(false),
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
					6, []byte{byte(i), byte(j)}, byte(i+j)%5, int(i+j))
				require.Nil(t, err)
				mockSrc.AddPacket(p)
			}
		}
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
	require.Equal(t, fmt.Sprintf("1.2.3.%d:%d => 4.5.6.%d:%d (proto: %d)", i%254+1, i, j%254+1, j, 6), p.String())
	c, err := capture.BuildPacket(
		net.ParseIP(fmt.Sprintf("1.2.3.%d", i%254+1)),
		net.ParseIP(fmt.Sprintf("4.5.6.%d", j%254+1)),
		i,
		j,
		6, []byte{byte(i), byte(j)}, byte(i+j)%5, int(i+j))
	require.Nil(t, err)
	require.Equalf(t, c.IPLayer(), p[:len(c.IPLayer())], "%v vs. %v", c.IPLayer(), p)
}
