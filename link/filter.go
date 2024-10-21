package link

import (
	"fmt"

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
	regPktType   = 0xfffff004
	regEtherType = 0xc

	pktTypeOutbound = 0x4
	etherTypeIPv4   = 0x800
	etherTypeIPv6   = 0x86dd
)

// BPFFn denotes a generic BPF wrapper function that is used to provide link type
// dependent filters
type BPFFn func(snapLen int, noVlan bool, extraInstr ...bpf.RawInstruction) []bpf.RawInstruction

// LinkTypeLoopback
// not outbound && (ether proto 0x0800 || ether proto 0x86DD)
var bpfInstructionsLinkTypeLoopback = func(snapLen int, noVlan bool, extraInstr ...bpf.RawInstruction) (res []bpf.RawInstruction) {
	if snapLen == 0 {
		snapLen = defaultSnapLen
	}
	nExtra := uint8(len(extraInstr))

	res = append(res, []bpf.RawInstruction{
		{Op: opLDH, Jt: 0x0, Jf: 0x0, K: regPktType},               // Load pktType
		{Op: opJEQ, Jt: 0x4 + nExtra, Jf: 0x0, K: pktTypeOutbound}, // Compare against "OUTBOUND", return if true
		{Op: opLDH, Jt: 0x0, Jf: 0x0, K: regEtherType},             // Load byte 12 from the packet (ethernet type)
		{Op: opJEQ, Jt: 0x1 + nExtra, Jf: 0x0, K: etherTypeIPv4},   // Compare against IPv4, continue below if true
		{Op: opJEQ, Jt: 0x0, Jf: 0x1 + nExtra, K: etherTypeIPv6},   // Compare against IPv6, continue below if true
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
// the layers _after_ an PPPOEs packet
var bpfInstructionsLinkTypeEther = func(snapLen int, noVlan bool, extraInstr ...bpf.RawInstruction) (res []bpf.RawInstruction) {
	if snapLen == 0 {
		snapLen = defaultSnapLen
	}
	nExtra := uint8(len(extraInstr))

	fmt.Println("Setting up ethernet", noVlan, nExtra)

	// Drop all VLAN-tagged packets if requested (prefix instructions)
	if noVlan {
		res = []bpf.RawInstruction{
			{Op: opLDW, Jt: 0x0, Jf: 0x0, K: regVLanT},
			{Op: opJEQ, Jt: 0x0, Jf: 0x8 + nExtra, K: 0x0},
		}
	}

	res = append(res, []bpf.RawInstruction{
		{Op: opLDH, Jt: 0x0, Jf: 0x0, K: regEtherType},
		{Op: opJEQ, Jt: 0x5 + nExtra, Jf: 0x0, K: 0x800},
		{Op: opJEQ, Jt: 0x4 + nExtra, Jf: 0x0, K: 0x86dd},
		{Op: opJEQ, Jt: 0x0, Jf: 0x4 + nExtra, K: 0x8864},
		{Op: opLDH, Jt: 0x0, Jf: 0x0, K: 0x14},
		{Op: opJEQ, Jt: 0x1 + nExtra, Jf: 0x0, K: 0x21},
		{Op: opJEQ, Jt: 0x0, Jf: 0x1 + nExtra, K: 0x57},
	}...)

	if nExtra > 0 {
		res = append(res, extraInstr...)
	}

	res = append(res, []bpf.RawInstruction{
		{Op: opRET, Jt: 0x0, Jf: 0x0, K: uint32(snapLen)},
		{Op: opRET, Jt: 0x0, Jf: 0x0, K: 0x0},
	}...)

	fmt.Println(res)

	return
}

// LinkTypeSLIP
// ether proto 0x0800 || ether proto 0x86DD
var bpfInstructionsLinkTypeRaw = func(snapLen int, noVlan bool, extraInstr ...bpf.RawInstruction) (res []bpf.RawInstruction) {
	if snapLen == 0 {
		snapLen = defaultSnapLen
	}
	nExtra := uint8(len(extraInstr))

	res = append(res, []bpf.RawInstruction{
		{Op: opLDB, Jt: 0x0, Jf: 0x0, K: 0x0},
		{Op: opAND, Jt: 0x0, Jf: 0x0, K: 0xf0}, // shifts the IP type only (this isn't an ether type, but part of the IP layer!!)
		{Op: opJEQ, Jt: 0x3 + nExtra, Jf: 0x0, K: 0x40},
		{Op: opLDB, Jt: 0x0, Jf: 0x0, K: 0x0},
		{Op: opAND, Jt: 0x0, Jf: 0x0, K: 0xf0},
		{Op: opJEQ, Jt: 0x0, Jf: 0x1 + nExtra, K: 0x60},
	}...)

	if nExtra > 0 {
		res = append(res, extraInstr...)
	}

	res = append(res, []bpf.RawInstruction{
		{Op: opRET, Jt: 0x0, Jf: 0x0, K: uint32(snapLen)},
		{Op: opRET, Jt: 0x0, Jf: 0x0, K: 0x0},
	}...)

	return
}
