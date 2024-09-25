package link

import "golang.org/x/net/bpf"

const defaultSnapLen = 262144

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
		{Op: 0x28, Jt: 0x0, Jf: 0x0, K: 0xfffff004},
		{Op: 0x15, Jt: 0x4 + nExtra, Jf: 0x0, K: 0x4},
		{Op: 0x28, Jt: 0x0, Jf: 0x0, K: 0xc},
		{Op: 0x15, Jt: 0x1 + nExtra, Jf: 0x0, K: 0x800},
		{Op: 0x15, Jt: 0x0, Jf: 0x1 + nExtra, K: 0x86dd},
	}...)

	if nExtra > 0 {
		res = append(res, extraInstr...)
	}

	res = append(res, []bpf.RawInstruction{
		{Op: 0x6, Jt: 0x0, Jf: 0x0, K: uint32(snapLen)},
		{Op: 0x6, Jt: 0x0, Jf: 0x0, K: 0x0},
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

	// Drop all VLAN-tagged packets if requested (prefix instructions)
	if noVlan {
		res = []bpf.RawInstruction{
			{Op: 0x20, Jt: 0x0, Jf: 0x0, K: 0xfffff02c},
			{Op: 0x15, Jt: 0x0, Jf: 0x8 + nExtra, K: 0x0},
		}
	}

	res = append(res, []bpf.RawInstruction{
		{Op: 0x28, Jt: 0x0, Jf: 0x0, K: 0xc},
		{Op: 0x15, Jt: 0x5 + nExtra, Jf: 0x0, K: 0x800},
		{Op: 0x15, Jt: 0x4 + nExtra, Jf: 0x0, K: 0x86dd},
		{Op: 0x15, Jt: 0x0, Jf: 0x4 + nExtra, K: 0x8864},
		{Op: 0x28, Jt: 0x0, Jf: 0x0, K: 0x14},
		{Op: 0x15, Jt: 0x1 + nExtra, Jf: 0x0, K: 0x21},
		{Op: 0x15, Jt: 0x0, Jf: 0x1 + nExtra, K: 0x57},
	}...)

	if nExtra > 0 {
		res = append(res, extraInstr...)
	}

	res = append(res, []bpf.RawInstruction{
		{Op: 0x6, Jt: 0x0, Jf: 0x0, K: uint32(snapLen)},
		{Op: 0x6, Jt: 0x0, Jf: 0x0, K: 0x0},
	}...)

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
		{Op: 0x30, Jt: 0x0, Jf: 0x0, K: 0x0},
		{Op: 0x54, Jt: 0x0, Jf: 0x0, K: 0xf0},
		{Op: 0x15, Jt: 0x3 + nExtra, Jf: 0x0, K: 0x40},
		{Op: 0x30, Jt: 0x0, Jf: 0x0, K: 0x0},
		{Op: 0x54, Jt: 0x0, Jf: 0x0, K: 0xf0},
		{Op: 0x15, Jt: 0x0, Jf: 0x1 + nExtra, K: 0x60},
	}...)

	if nExtra > 0 {
		res = append(res, extraInstr...)
	}

	res = append(res, []bpf.RawInstruction{
		{Op: 0x6, Jt: 0x0, Jf: 0x0, K: uint32(snapLen)},
		{Op: 0x6, Jt: 0x0, Jf: 0x0, K: 0x0},
	}...)

	return
}
