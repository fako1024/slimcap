package afpacket

import (
	"testing"
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