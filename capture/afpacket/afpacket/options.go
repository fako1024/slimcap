//go:build linux
// +build linux

package afpacket

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
