//go:build linux
// +build linux

package afring

import (
	"github.com/fako1024/slimcap/link"
	"golang.org/x/net/bpf"
)

// Option denotes a functional option for the Source
type Option func(*Source)

// CaptureLength sets a snapLen / capture length (max. number of bytes captured per packet)
func CaptureLength(strategy link.CaptureLengthStrategy) Option {
	return func(s *Source) {
		s.snapLen = strategy(s.link)
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

// IgnoreVLANs causes the capture to drop / ignore all VLAN tagged packets on BPF level
func IgnoreVLANs(enable bool) Option {
	return func(s *Source) {
		s.ignoreVLANs = enable
	}
}

// ExtraBPFInstructions adds additional BPF instructions to the set of basic / existing ones
// used on the capture
func ExtraBPFInstructions(instr []bpf.RawInstruction) Option {
	return func(s *Source) {
		s.extraBPFInstr = instr
	}
}
