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
		require.Equal(t, blockNr*(1<<i), req.blockSizeNr())
	}
	for i := 0; i < 32; i++ {
		_, err := newTPacketRequestForBuffer((1<<i)+1, blockNr, snapLen)
		require.EqualError(t, err, fmt.Sprintf("block size %d not aligned to page size", (1<<i)+1))
	}
}

func validatePacket(t *testing.T, p capture.Packet, i, j uint16) {
	validateIPPacket(t, p.IPLayer(), p.Type(), p.TotalLen(), i, j)
}

func validateIPPacket(t *testing.T, p capture.IPLayer, pktType capture.PacketType, totalLen uint32, i, j uint16) {
	require.Equalf(t, int(i*1000+j), int(totalLen), "i=%d, j=%d", i, j)
	require.Equalf(t, byte(i+j)%5, pktType, "i=%d, j=%d", i, j)
	require.Equalf(t, fmt.Sprintf("1.2.3.%d:%d => 4.5.6.%d:%d (proto: %d)", i%254+1, i, j%254+1, j, 6), p.String(), "i=%d, j=%d", i, j)
	c, err := capture.BuildPacket(
		net.ParseIP(fmt.Sprintf("1.2.3.%d", i%254+1)),
		net.ParseIP(fmt.Sprintf("4.5.6.%d", j%254+1)),
		i,
		j,
		6, []byte{byte(i), byte(j)}, byte(i+j)%5, int(i*1000+j))
	require.Nil(t, err)
	require.Equalf(t, c.IPLayer(), p[:len(c.IPLayer())], "%v vs. %v , i=%d, j=%d", c.IPLayer(), p, i, j)
}
