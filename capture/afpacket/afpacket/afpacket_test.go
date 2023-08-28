package afpacket

import (
	"fmt"
	"net"
	"testing"

	"github.com/fako1024/slimcap/capture"
	"github.com/stretchr/testify/require"
)

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
