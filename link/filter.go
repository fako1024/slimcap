package link

import "golang.org/x/net/bpf"

var bpfInstructionsLinkTypeEther = []bpf.RawInstruction{
	{Op: 40, Jt: 0, Jf: 0, K: 12},
	{Op: 21, Jt: 1, Jf: 0, K: 2048},
	{Op: 21, Jt: 0, Jf: 1, K: 34525},
	{Op: 6, Jt: 0, Jf: 0, K: 86},
	{Op: 6, Jt: 0, Jf: 0, K: 0},
}

var bpfInstructionsLinkTypeRaw = []bpf.RawInstruction{
	{Op: 48, Jt: 0, Jf: 0, K: 0},
	{Op: 84, Jt: 0, Jf: 0, K: 240},
	{Op: 21, Jt: 3, Jf: 0, K: 64},
	{Op: 48, Jt: 0, Jf: 0, K: 0},
	{Op: 84, Jt: 0, Jf: 0, K: 240},
	{Op: 21, Jt: 0, Jf: 1, K: 96},
	{Op: 6, Jt: 0, Jf: 0, K: 86},
	{Op: 6, Jt: 0, Jf: 0, K: 0},
}
