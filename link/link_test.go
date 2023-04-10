package link

import (
	"io/fs"
	"net"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/bpf"
)

func TestIsUp(t *testing.T) {
	link, _ := New("lo")

	want := true
	got := link.IsUp()

	if got != want {
		t.Errorf("IsUp() returned wrong value: got %v, want %v", got, want)
	}
}

func TestFindAllLinks(t *testing.T) {
	links, err := FindAllLinks()

	if err != nil {
		t.Errorf("FindAllLinks() returned error: %v", err)
	}

	for _, link := range links {
		if link == nil {
			t.Errorf("FindAllLinks() returned nil link")
		}
	}
}

func TestGetLinkType(t *testing.T) {
	want := TypeLoopback
	got, err := getLinkType("lo")

	if err != nil {
		t.Errorf("getLinkType() returned error: %v", err)
	}

	if got != want {
		t.Errorf("getLinkType() returned wrong value: got %v, want %v", got, want)
	}
}

func TestIpHeaderOffset(t *testing.T) {
	tests := []struct {
		name     string
		linkType Type
		want     byte
	}{
		{"TypeEthernet", TypeEthernet, IPLayerOffsetEthernet},
		{"TypeLoopback", TypeLoopback, IPLayerOffsetEthernet},
		{"TypePPP", TypePPP, 0},
		{"TypeGRE", TypeGRE, 0},
		{"TypeNone", TypeNone, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.linkType.IpHeaderOffset(); got != tt.want {
				t.Errorf("IpHeaderOffset() = %v, want %v for link type %v", got, tt.want, tt.linkType)
			}
		})
	}
}

func TestBPFFilter(t *testing.T) {
	snaplen := 4096
	tests := []struct {
		name     string
		linkType Type
	}{
		{"TypeEthernet", TypeEthernet},
		{"TypeLoopback", TypeLoopback},
		{"TypePPP", TypePPP},
		{"TypeGRE", TypeGRE},
		{"TypeNone", TypeNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := tt.linkType.BPFFilter()(snaplen)
			if filter == nil {
				t.Errorf("BPFFilter() returned nil filter")
			}
		})
	}
}

func TestLink_IpHeaderOffset(t *testing.T) {
	tests := []struct {
		name string
		l    Type
		want byte
	}{
		{
			name: "Test Ethernet link IP Header Offset",
			l:    TypeEthernet,
			want: IPLayerOffsetEthernet,
		},
		{
			name: "Test Loopback link IP Header Offset",
			l:    TypeLoopback,
			want: IPLayerOffsetEthernet,
		},
		{
			name: "Test PPP link IP Header Offset",
			l:    TypePPP,
			want: 0,
		},
		{
			name: "Test GRE link IP Header Offset",
			l:    TypeGRE,
			want: 0,
		},
		{
			name: "Test None link IP Header Offset",
			l:    TypeNone,
			want: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.l.IpHeaderOffset(); got != tt.want {
				t.Errorf("Link.IpHeaderOffset() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLink_BPFFilter(t *testing.T) {
	tests := []struct {
		name     string
		l        Type
		wantFunc func(snapLen int) []bpf.RawInstruction
	}{
		{
			name: "Test Ethernet link BPF Filter Function",
			l:    TypeEthernet,
			wantFunc: func(snapLen int) []bpf.RawInstruction {
				return bpfInstructionsLinkTypeEther(snapLen)
			},
		},
		{
			name: "Test Loopback link BPF Filter Function",
			l:    TypeLoopback,
			wantFunc: func(snapLen int) []bpf.RawInstruction {
				return bpfInstructionsLinkTypeEther(snapLen)
			},
		},
		{
			name: "Test PPP link BPF Filter Function",
			l:    TypePPP,
			wantFunc: func(snapLen int) []bpf.RawInstruction {
				return bpfInstructionsLinkTypeRaw(snapLen)
			},
		},
		{
			name: "Test GRE link BPF Filter Function",
			l:    TypeGRE,
			wantFunc: func(snapLen int) []bpf.RawInstruction {
				return bpfInstructionsLinkTypeRaw(snapLen)
			},
		},
		{
			name: "Test None link BPF Filter Function",
			l:    TypeNone,
			wantFunc: func(snapLen int) []bpf.RawInstruction {
				return bpfInstructionsLinkTypeRaw(snapLen)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotFunc := tt.l.BPFFilter(); !assert.ObjectsAreEqual(gotFunc(65536), tt.wantFunc(65536)) {
				t.Errorf("Link.BPFFilter() = %v, want %v", gotFunc(65536), tt.wantFunc(65536))
			}
		})
	}
}

func TestLink_FindAllLinks(t *testing.T) {
	tests := []struct {
		name    string
		mockFn  func() ([]net.Interface, error)
		wantErr error
	}{
		{
			name: "Test Find All Links Success",
			mockFn: func() ([]net.Interface, error) {
				return []net.Interface{
					{Name: "eth0", Flags: syscall.IFF_UP},
					{Name: "eth1", Flags: syscall.IFF_UP},
					{Name: "lo", Flags: syscall.IFF_UP},
				}, nil
			},
			wantErr: nil,
		},
		{
			name: "Test Find All Links Error",
			mockFn: func() ([]net.Interface, error) {
				return nil, fs.ErrNotExist
			},
			wantErr: &fs.PathError{
				Op:   "open",
				Path: "/sys/class/net/",
				Err:  fs.ErrNotExist,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			netInterfaces = &mockInterfaces{mockFn: tt.mockFn}
			got, err := FindAllLinks()
			if err != nil {
				if !assert.EqualError(t, err, tt.wantErr.Error()) {
					t.Errorf("Link_FindAllLinks() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}
			require.True(t, len(got) > 0)
			for _, l := range got {
				assert.NotNil(t, l)
			}
		})
	}
}

func TestNew(t *testing.T) {
	type args struct {
		ifName string
	}
	tests := []struct {
		name    string
		args    args
		mockFn  func(ifName string) (Type, error)
		want    *Link
		wantErr bool
	}{
		{
			name: "Test New Fail Interface not found",
			args: args{ifName: "eth2"},
			mockFn: func(ifName string) (Type, error) {
				return -1, fs.ErrNotExist
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Test New Fail Interface not up",
			args: args{ifName: "eth1"},
			mockFn: func(ifName string) (Type, error) {
				return TypeEthernet, nil
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "Test New Fail Invalid Link Type",
			args: args{ifName: "eth0"},
			mockFn: func(ifName string) (Type, error) {
				return TypeInvalid, nil
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			getLinkTypeF = tt.mockFn
			got, err := New(tt.args.ifName)
			if (err != nil) != tt.wantErr {
				t.Errorf("Link.New() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !assert.ObjectsAreEqual(got, tt.want) {
				t.Errorf("Link.New() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLink_IsUp(t *testing.T) {
	type fields struct {
		Type Type
		net.Interface
	}
	tests := []struct {
		name   string
		fields fields
		want   bool
	}{
		{
			name: "Test Up Interface",
			fields: fields{
				Type: TypeEthernet,
				Interface: net.Interface{
					Name:  "eth0",
					Flags: syscall.IFF_UP,
				},
			},
			want: true,
		},
		{
			name: "Test Down Interface",
			fields: fields{
				Type: TypeEthernet,
				Interface: net.Interface{
					Name:  "eth0",
					Flags: 0,
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := &Link{
				Type:      tt.fields.Type,
				Interface: &tt.fields.Interface,
			}
			if got := l.IsUp(); got != tt.want {
				t.Errorf("Link.IsUp() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockInterfaces struct {
	mockFn func() ([]net.Interface, error)
}

var netInterfaces = &mockInterfaces{
	mockFn: func() ([]net.Interface, error) {
		return nil, nil
	},
}

func (m *mockInterfaces) Interfaces() ([]net.Interface, error) {
	return m.mockFn()
}

var getLinkTypeF = func(ifName string) (Type, error) { return 1, nil }
