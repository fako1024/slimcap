//go:build linux
// +build linux

package afring

type Option func(*Source)

func CaptureLength(snapLen int) Option {
	return func(s *Source) {
		s.snapLen = snapLen
	}
}

func Promiscuous(enable bool) Option {
	return func(s *Source) {
		s.isPromisc = enable
	}
}

func BufferSize(blockSize, nBlocks int) Option {
	return func(s *Source) {
		s.blockSize = pageSizeAlign(blockSize)
		s.nBlocks = nBlocks

	}
}
