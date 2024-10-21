/*
Package link provides access to network interfaces and their parameters, such as link type and flags.
In addition, it provides the IP layer offset for each link type and implements default BPF filtering
to maximize throughput (by selecting only packets that subsequently can be processed / parsed by the
routines provided by slimcap).
*/
package link

import (
	"errors"
	"fmt"
	"io/fs"
)

const (

	// IPLayerOffsetEthernet denotes the ethernet header offset
	IPLayerOffsetEthernet = 14

	// IPLayerOffsetLinuxSLL2 denotes the Linux SLL2 header offset
	IPLayerOffsetLinuxSLL2 = 20

	// LayerOffsetPPPOE denotes the additional offset for PPPOE (session) packets
	LayerOffsetPPPOE = 8
)

var (

	// ErrNotExist denotes that the interface in question does not exist
	ErrNotExist = errors.New("interface does not exist")

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

	// TypeEthernet denotes a link of type ARPHRD_ETHER
	TypeEthernet Type = 1

	// TypeLoopback denotes a link of type ARPHRD_LOOPBACK
	TypeLoopback Type = 772

	// TypePPP denotes a link of type ARPHRD_PPP
	TypePPP Type = 512

	// TypeIP6IP6 denotes a link of type ARPHRD_TUNNEL6
	TypeIP6IP6 Type = 769

	// TypeGRE denotes a link of type ARPHRD_IPGRE
	TypeGRE Type = 778

	// TypeGRE6 denotes a link of type ARPHRD_IP6GRE
	TypeGRE6 Type = 823

	// TypeLinuxSLL2 denotes a link of type LINUX_SLL2
	TypeLinuxSLL2 Type = 276

	// TypeNone denotes a link of type ARPHRD_NONE:
	// Tunnel / anything else (confirmed: Wireguard, OpenVPN)
	TypeNone Type = 65534
)

// IPHeaderOffset returns the link / interface specific payload offset for the IP header
// c.f. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/if_arp.h
func (l Type) IPHeaderOffset() byte {
	switch l {
	case TypeEthernet,
		TypeLoopback:
		return IPLayerOffsetEthernet
	case TypePPP,
		TypeIP6IP6,
		TypeGRE,
		TypeGRE6,
		TypeNone:
		return 0
	case TypeLinuxSLL2:
		return IPLayerOffsetLinuxSLL2
	}

	// Panic if unknown
	panic(fmt.Sprintf("LinkType %d not supported by slimcap (yet), please open a GitHub issue", l))
}

// BPFFilter returns the link / interface specific raw BPF instructions to filter for valid packets only
func (l Type) BPFFilter() BPFFn {
	switch l {
	case TypeEthernet:
		return bpfInstructionsLinkTypeEther
	case TypeLoopback:
		return bpfInstructionsLinkTypeLoopback
	case TypePPP,
		TypeIP6IP6,
		TypeGRE,
		TypeGRE6,
		TypeLinuxSLL2,
		TypeNone:
		return bpfInstructionsLinkTypeRaw
	}

	// Panic if unknown
	panic(fmt.Sprintf("LinkType %d not supported by slimcap (yet), please open a GitHub issue", l))
}

// Link denotes a link, i.e. an interface (wrapped) and its link type
type Link struct {
	Interface
}

// New instantiates a new link / interface
func New(ifName string, opts ...func(*Link)) (link *Link, err error) {

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

	link = &Link{
		Interface: iface,
	}

	// Apply functional options, if any
	for _, opt := range opts {
		opt(link)
	}

	return
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
