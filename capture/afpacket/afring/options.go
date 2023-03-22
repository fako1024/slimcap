//go:build linux
// +build linux

package afring

// Option denotes a functional option for the Source
type Option func(*Source)

// CaptureLength sets a snapLen / capture length (max. number of bytes captured per packet)
func CaptureLength(snapLen int) Option {
	return func(s *Source) {
		s.snapLen = snapLen
	}
}

// Promiscuous enables / disables promiscuous capture mode
func Promiscuous(enable bool) Option {
	return func(s *Source) {
		s.isPromisc = enable
	}
}

// BufferSize sets the block size / number of blocks for the ring buffer
func BufferSize(blockSize, nBlocks int) Option {
	return func(s *Source) {
		s.blockSize = pageSizeAlign(blockSize)
		s.nBlocks = nBlocks
	}
}
