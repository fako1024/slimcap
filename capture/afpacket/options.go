package afpacket

import (
	"errors"

	"github.com/fako1024/slimcap/capture"
)

// Option denotes a generic option applicable to all capture sources
type Option func(capture.Source) error

// CaptureLen sets a custom capture length (a.k.a. snaplen)
func CaptureLength(snapLen int) Option {
	return func(s capture.Source) (err error) {
		if x, ok := s.(*Source); ok {
			x.snapLen = snapLen
		} else if x, ok := s.(*RingBufSource); ok {
			x.snapLen = snapLen
		} else {
			err = errors.New("option `CaptureLength()` not supported for this capture source")
		}
		return
	}
}

// BufferSize sets a custom overall buffer size
func BufferSize(blockSize, nBlocks int) Option {
	return func(s capture.Source) (err error) {
		if x, ok := s.(*RingBufSource); ok {
			x.blockSize = blockSize
			x.nBlocks = nBlocks
		} else {
			err = errors.New("option `BufferSize()` not supported for this capture source")
		}
		return
	}
}

// Promiscuous enables / disabled promiscuous mode
func Promiscuous(enable bool) Option {
	return func(s capture.Source) (err error) {
		if x, ok := s.(*Source); ok {
			x.isPromisc = enable
		} else if x, ok := s.(*RingBufSource); ok {
			x.isPromisc = enable
		} else {
			err = errors.New("option `Promiscuous()` not supported for this capture source")
		}
		return
	}
}
