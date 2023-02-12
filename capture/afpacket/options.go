package afpacket

import "github.com/fako1024/slimcap/capture"

// Option denotes a generic option applicable to all capture sources
type Option func(capture.Source)

// ZeroCopy enables / disables zero-copy mode when receiving packet data from the wire
func ZeroCopy(enable bool) Option {
	return func(s capture.Source) {
		if x, ok := s.(*Source); ok {
			x.isZeroCopy = enable
		} else if x, ok := s.(*RingBufSource); ok {
			x.isZeroCopy = enable
		} else {
			panic("option `ZeroCopy()` not supported")
		}
	}
}
