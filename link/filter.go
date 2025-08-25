package link

import (
	"golang.org/x/net/bpf"
)

const (
	defaultSnapLen = 262144

	opRET = 0x6
	opJEQ = 0x15
	opLDW = 0x20
	opLDH = 0x28
	opLDB = 0x30
	opAND = 0x54

	regVLanT     = 0xfffff02c
	regEtherType = 0xc
	regPPPType   = 0x14

	etherTypeIPv4  = 0x800
	etherTypeIPv6  = 0x86dd
	etherTypePPPOE = 0x8864
	ipTypeIPv4     = 0x40
	ipTypeIPv6     = 0x60
	pppTypeIPv4    = 0x21
	pppTypeIPv6    = 0x57
)

// BPFFn denotes a generic BPF wrapper function that is used to provide link type
// dependent filters
type BPFFn func(snapLen int, ignoreVLANs bool, extraInstr ...bpf.RawInstruction) []bpf.RawInstruction

// LinkTypeLoopback
// (ether proto 0x0800 || ether proto 0x86DD)
var bpfInstructionsLinkTypeLoopback = func(snapLen int, _ bool, extraInstr ...bpf.RawInstruction) (res []bpf.RawInstruction) {
	if snapLen == 0 {
		snapLen = defaultSnapLen
	}
	nExtra := uint8(len(extraInstr))

	res = append(res, []bpf.RawInstruction{
		{Op: opLDH, Jt: 0x0, Jf: 0x0, K: regEtherType},           // Load byte 12 from the packet (ethernet type)
		{Op: opJEQ, Jt: 0x1, Jf: 0x0, K: etherTypeIPv4},          // Compare against IPv4 header, continue further below if true
		{Op: opJEQ, Jt: 0x0, Jf: 0x1 + nExtra, K: etherTypeIPv6}, // Compare against IPv6 header, continue further below if true, return (no data) if false
	}...)

	if nExtra > 0 {
		res = append(res, extraInstr...) // Append any optional / extra instructions verbatim
	}

	res = append(res, []bpf.RawInstruction{
		{Op: opRET, Jt: 0x0, Jf: 0x0, K: uint32(snapLen)}, // Return up to snapLen bytes of the packet
		{Op: opRET, Jt: 0x0, Jf: 0x0, K: 0x0},             // Return (no data)
	}...)

	return
}

// LinkTypeEthernet
// ether proto 0x0800 || ether proto 0x86DD || (pppoes && (ether proto 0x0800 || ether proto 0x86DD))
// Note: The second occurrence of "(ether proto 0x0800 || ether proto 0x86DD)" is not duplicate, it pertains
// to the layers _after_ a PPPOE layer / header
var bpfInstructionsLinkTypeEther = func(snapLen int, ignoreVLANs bool, extraInstr ...bpf.RawInstruction) (res []bpf.RawInstruction) {
	if snapLen == 0 {
		snapLen = defaultSnapLen
	}
	nExtra := uint8(len(extraInstr))

	// Drop all VLAN-tagged packets if requested (prefix instructions)
	if ignoreVLANs {
		res = []bpf.RawInstruction{
			{Op: opLDW, Jt: 0x0, Jf: 0x0, K: regVLanT},     // Load VLAN ID register value
			{Op: opJEQ, Jt: 0x0, Jf: 0x8 + nExtra, K: 0x0}, // Compare against 0 (not a VLAN), continue if true, return if false
		}
	}

	res = append(res, []bpf.RawInstruction{
		{Op: opLDH, Jt: 0x0, Jf: 0x0, K: regEtherType},            // Load byte 12 from the packet (ethernet type)
		{Op: opJEQ, Jt: 0x5, Jf: 0x0, K: etherTypeIPv4},           // Compare against IPv4 header, continue further below if true
		{Op: opJEQ, Jt: 0x4, Jf: 0x0, K: etherTypeIPv6},           // Compare against IPv6 header, continue further below if true
		{Op: opJEQ, Jt: 0x0, Jf: 0x4 + nExtra, K: etherTypePPPOE}, // Compare against PPPOE header, continue if true, return (no data) if false
		{Op: opLDH, Jt: 0x0, Jf: 0x0, K: regPPPType},              // Load byte 20 from the packet (PPP protocol type)
		{Op: opJEQ, Jt: 0x1, Jf: 0x0, K: pppTypeIPv4},             // Compare against IPv4 PPP header, continue further below if true
		{Op: opJEQ, Jt: 0x0, Jf: 0x1 + nExtra, K: pppTypeIPv6},    // Compare against IPv6 PPP header, continue further below if true, return (no data) if false
	}...)

	if nExtra > 0 {
		res = append(res, extraInstr...) // Append any optional / extra instructions verbatim
	}

	res = append(res, []bpf.RawInstruction{
		{Op: opRET, Jt: 0x0, Jf: 0x0, K: uint32(snapLen)}, // Return up to snapLen bytes of the packet
		{Op: opRET, Jt: 0x0, Jf: 0x0, K: 0x0},             // Return (no data)
	}...)

	return
}

// LinkTypeSLIP
// ether proto 0x0800 || ether proto 0x86DD
var bpfInstructionsLinkTypeRaw = func(snapLen int, _ bool, extraInstr ...bpf.RawInstruction) (res []bpf.RawInstruction) {
	if snapLen == 0 {
		snapLen = defaultSnapLen
	}
	nExtra := uint8(len(extraInstr))

	res = append(res, []bpf.RawInstruction{
		{Op: opLDB, Jt: 0x0, Jf: 0x0, K: 0x0},                 // Load byte 0 from the packet (IP layer type)
		{Op: opAND, Jt: 0x0, Jf: 0x0, K: 0xf0},                // shifts the IP type only (this isn't an ether type, but part of the IP layer!!)
		{Op: opJEQ, Jt: 0x1, Jf: 0x0, K: ipTypeIPv4},          // Compare against IPv4 layer, continue further below if true
		{Op: opJEQ, Jt: 0x0, Jf: 0x1 + nExtra, K: ipTypeIPv6}, // Compare against IPv6 layer, continue further below if true, return (no data) if false
	}...)

	if nExtra > 0 {
		res = append(res, extraInstr...) // Append any optional / extra instructions verbatim
	}

	res = append(res, []bpf.RawInstruction{
		{Op: opRET, Jt: 0x0, Jf: 0x0, K: uint32(snapLen)}, // Return up to snapLen bytes of the packet
		{Op: opRET, Jt: 0x0, Jf: 0x0, K: 0x0},             // Return (no data)
	}...)

	return
}
