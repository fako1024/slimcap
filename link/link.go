package link

import (
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/net/bpf"
)

const (

	// IPLayerOffsetEthernet denotes the ethernet header offset
	IPLayerOffsetEthernet = 14

	// LayerOffsetPPPOE denotes the additional offset for PPPOE (session) packets
	LayerOffsetPPPOE = 8
)

var (

	// ErrNotExist denotes that the interface in question does not exist
	ErrNotExist = errors.New("interface does not exist or is unsupported")

	// ErrNotUp denotes that the interface in question is not up
	ErrNotUp = errors.New("interface is currently not up")
)

// EmptyEthernetLink provides a quick access to a plain / empty ethernet-type link
var EmptyEthernetLink = Link{
	Interface: Interface{
		Type: TypeEthernet,
	},
}

// Type denotes the linux interface type
type Type int

const (

	// TypeInvalid denotes an invalid link type
	TypeInvalid Type = iota

	// TypeEthernet denotes a link of type ARPHRD_LOOPBACK
	TypeEthernet Type = 1

	// TypeLoopback denotes a link of type ARPHRD_ETHER
	TypeLoopback Type = 772

	// TypePPP denotes a link of type ARPHRD_PPP
	TypePPP Type = 512

	// TypeGRE denotes a link of type ARPHRD_IPGRE
	TypeGRE Type = 778

	// TypeNone denotes a link of type ARPHRD_NONE:
	// Tunnel / anything else (confirmed: Wireguard, OpenVPN)
	TypeNone Type = 65534
)

// IpHeaderOffset returns the link / interface specific payload offset for the IP header
// c.f. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/if_arp.h
func (l Type) IPHeaderOffset() byte {
	switch l {
	case TypeEthernet,
		TypeLoopback:
		return IPLayerOffsetEthernet
	case TypePPP,
		TypeGRE,
		TypeNone:
		return 0
	}

	// Panic if unknown
	panic(fmt.Sprintf("LinkType %d not supported (yet)", l))
}

// BPFFilter returns the link / interface specific raw BPF instructions to filter for valid packets only
func (l Type) BPFFilter() func(snapLen int) []bpf.RawInstruction {
	switch l {
	case TypeEthernet,
		TypeLoopback:
		return bpfInstructionsLinkTypeEther
	case TypePPP,
		TypeGRE,
		TypeNone:
		return bpfInstructionsLinkTypeRaw
	}

	// Panic if unknown
	panic(fmt.Sprintf("LinkType %d not supported (yet)", l))
}

// Link denotes a link, i.e. an interface (wrapped) and its link type
type Link struct {
	Interface
}

// New instantiates a new link / interface
func New(ifName string) (link *Link, err error) {

	iface, lerr := NewInterface(ifName)
	if lerr != nil {
		if errors.Is(lerr, fs.ErrNotExist) {
			err = ErrNotExist
		} else {
			err = lerr
		}
		return
	}

	isUp, uerr := iface.IsUp()
	if uerr != nil {
		if errors.Is(uerr, fs.ErrNotExist) {
			err = ErrNotExist
		} else {
			err = uerr
		}
		return
	}

	if !isUp {
		err = ErrNotUp
		return
	}

	return &Link{
		Interface: iface,
	}, nil
}

// IsUp returns if a link / interface is up
func (l *Link) IsUp() (bool, error) {
	return l.Interface.IsUp()
}

// FindAllLinks retrieves all system network interfaces and their link type
func FindAllLinks() ([]*Link, error) {

	// Retrieve all network interfaces
	ifaces, err := Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve system network interfaces: %w", err)
	}

	// Determine link type for all interfaces
	var links []*Link
	for _, iface := range ifaces {
		links = append(links, &Link{
			Interface: iface,
		})
	}

	return links, err
}
