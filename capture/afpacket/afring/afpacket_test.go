package afring

import (
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fako1024/slimcap/capture/afpacket/socket"
	"github.com/fako1024/slimcap/event"
	"github.com/fako1024/slimcap/link"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

type testCase struct {
	input []byte
}

func TestWeirdPacket(t *testing.T) {

	cases := []testCase{
		{
			input: []byte{0, 0, 48, 0, 0, 0, 0, 0, 0, 0, 242, 3, 0, 0},
		},
		{
			input: []byte{48, 0, 0, 0, 224, 24, 9, 0, 1, 0, 0, 0, 0, 0},
		},
		{
			input: []byte{0, 0, 244, 148, 244, 99, 189, 172, 42, 6, 0, 0, 0, 0},
		},
	}
	_ = cases

	data := []byte{0, 0, 0, 0, 216, 3, 0, 0, 244, 148, 244, 99, 149, 76, 122, 6, 128, 3, 0, 0, 170, 16, 0, 0, 9, 0, 0, 0, 82, 0, 96, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 17, 0, 8, 0, 2, 0, 0, 0, 1, 0, 0, 6, 0, 13, 185, 65, 65, 157, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 160, 206, 200, 221, 249, 17, 0, 13, 185, 65, 65, 157, 8, 0, 69, 0, 16, 156, 158, 102, 64, 0, 56, 6, 3, 19, 129, 143, 4, 238, 10, 0, 0, 102, 0, 80, 173, 126, 226, 237, 187, 74, 54, 20, 53, 87, 128, 16, 0, 85, 161, 113, 0, 0, 1, 1, 8, 10, 58, 133, 200, 6, 239, 243, 196, 46, 0, 0, 0, 0, 0}
	_ = data

	// pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Default)
	// fmt.Println(pkt.String())
	// fmt.Println(pkt.Data())

}

func TestBlockSizeAlignment(t *testing.T) {
	var (
		blockNr = 4
		snapLen = 64
	)
	for i := 0; i < 12; i++ {
		_, err := newTPacketRequestForBuffer((1 << i), blockNr, snapLen)
		require.EqualError(t, err, fmt.Sprintf("block size %d not aligned to page size", (1<<i)))
	}
	for i := 12; i < 30; i++ {
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

func TestCapture(t *testing.T) {

	testRingBlock, err := base64.StdEncoding.DecodeString(testRingBufferBlockA)
	require.Nil(t, err)

	var testRing []byte
	for i := 0; i < tPacketDefaultBlockNr; i++ {
		testRing = append(testRing, testRingBlock...)
	}

	fd, err := unix.Eventfd(0, unix.EFD_SEMAPHORE)
	require.Nil(t, err)

	evtFD, err := event.New()
	require.Nil(t, err)

	mockRingSource := &Source{
		snapLen:       64,
		blockSize:     (1 << 12),
		nBlocks:       tPacketDefaultBlockNr,
		ipLayerOffset: link.LinkType(1).IpHeaderOffset(),
		link: &link.Link{
			LinkType: 1,
			Interface: &net.Interface{
				Index:        1,
				MTU:          1500,
				Name:         "mock",
				HardwareAddr: []byte{},
				Flags:        net.FlagUp,
			},
		},
		Mutex: sync.Mutex{},
		ringBuffer: ringBuffer{
			ring: testRing,
		},
		socketFD: socket.FileDescriptor(fd),
		eventFD:  evtFD,
	}
	mockRingSource.ringBuffer.tpReq, err = newTPacketRequestForBuffer(mockRingSource.blockSize, mockRingSource.nBlocks, mockRingSource.snapLen)
	mockRingSource.ringBuffer.tpReq.retire_blk_tov = 1000
	require.Nil(t, err)

	go func(src *Source) {
		for {
			time.Sleep(10 * time.Millisecond)
			_, err := unix.Write(int(src.socketFD), []byte{1, 0, 0, 0, 0, 0, 0, 0})
			if err != nil {
				panic(err)
			}

			fd, err = unix.Eventfd(0, unix.EFD_SEMAPHORE)
			mockRingSource.socketFD = socket.FileDescriptor(fd)
		}
	}(mockRingSource)

	for i := 0; i < 26*tPacketDefaultBlockNr; i++ {
		p, err := mockRingSource.NextPacket(nil)
		require.Nil(t, err)

		fmt.Println(p.Len(), p.TotalLen(), p.IPLayer())
	}

}
