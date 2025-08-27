package filter

import (
	"testing"

	"github.com/fako1024/gotools/link"
	"github.com/stretchr/testify/assert"
	"golang.org/x/net/bpf"
)

func TestBPFFilter(t *testing.T) {
	snaplen := 4096
	tests := []struct {
		name     string
		linkType link.Type
	}{
		{"TypeEthernet", link.TypeEthernet},
		{"TypeLoopback", link.TypeLoopback},
		{"TypePPP", link.TypePPP},
		{"TypeGRE", link.TypeGRE},
		{"TypeNone", link.TypeNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := BPFFilter(tt.linkType)(snaplen, false)
			if filter == nil {
				t.Errorf("BPFFilter() returned nil filter")
			}
		})
	}
}

func TestLink_BPFFilter(t *testing.T) {
	tests := []struct {
		name     string
		l        link.Type
		wantFunc BPFFn
	}{
		{
			name: "Test Ethernet link BPF Filter Function",
			l:    link.TypeEthernet,
			wantFunc: func(snapLen int, _ bool, _ ...bpf.RawInstruction) []bpf.RawInstruction {
				return bpfInstructionsLinkTypeEther(snapLen, false)
			},
		},
		{
			name: "Test Loopback link BPF Filter Function",
			l:    link.TypeLoopback,
			wantFunc: func(snapLen int, _ bool, _ ...bpf.RawInstruction) []bpf.RawInstruction {
				return bpfInstructionsLinkTypeLoopback(snapLen, false)
			},
		},
		{
			name: "Test PPP link BPF Filter Function",
			l:    link.TypePPP,
			wantFunc: func(snapLen int, _ bool, _ ...bpf.RawInstruction) []bpf.RawInstruction {
				return bpfInstructionsLinkTypeRaw(snapLen, false)
			},
		},
		{
			name: "Test GRE link BPF Filter Function",
			l:    link.TypeGRE,
			wantFunc: func(snapLen int, _ bool, _ ...bpf.RawInstruction) []bpf.RawInstruction {
				return bpfInstructionsLinkTypeRaw(snapLen, false)
			},
		},
		{
			name: "Test None link BPF Filter Function",
			l:    link.TypeNone,
			wantFunc: func(snapLen int, _ bool, _ ...bpf.RawInstruction) []bpf.RawInstruction {
				return bpfInstructionsLinkTypeRaw(snapLen, false)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotFunc := BPFFilter(tt.l); !assert.ObjectsAreEqual(gotFunc(65536, false), tt.wantFunc(65536, false)) {
				t.Errorf("Link.BPFFilter() = %v, want %v", gotFunc(65536, false), tt.wantFunc(65536, false))
			}
		})
	}
}
