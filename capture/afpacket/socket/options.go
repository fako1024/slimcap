package socket

import "golang.org/x/net/bpf"

// SockerOptions denotes the available socket options
type SockerOptions struct {

	// Promiscuous mode
	Promiscuous bool

	// Ignore handling of VLANs
	IgnoreVLANs bool

	// Disable automatic BPF filter setup based on link type
	DisableAutoBPF bool

	// Extra BPF instructions to append to the auto-generated BPF filter
	ExtraBPFInstr []bpf.RawInstruction
}
