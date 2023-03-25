package link

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/net/bpf"
)

const (

	// IPLayerOffsetEthernet denotes the ethernet header offset
	IPLayerOffsetEthernet = 14

	// LayerOffsetPPPOE denotes the additional offset for PPPOE (session) packets
	LayerOffsetPPPOE = 8
)

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
func (l Type) IpHeaderOffset() byte {
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
	panic(fmt.Sprintf("Link Type %d not supported (yet)", l))
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
	panic(fmt.Sprintf("Link Type %d not supported (yet)", l))
}

// Link denotes a link, i.e. an interface (wrapped) and its link type
type Link struct {
	Type Type

	*net.Interface
}

// New instantiates a new link / interface
func New(ifName string) (link *Link, err error) {

	iface, ierr := net.InterfaceByName(ifName)
	if ierr != nil {
		err = ierr
		return
	}

	if (iface.Flags & syscall.IFF_UP) == 0 {
		err = fmt.Errorf("interface `%s` is not up", ifName)
		return
	}

	linkType, lerr := getLinkType(ifName)
	if lerr != nil {
		if errors.Is(lerr, fs.ErrNotExist) {
			err = fmt.Errorf("interface `%s` does not exist or is unsupported", ifName)
		} else {
			err = lerr
		}
		return
	}

	return &Link{
		Type:      linkType,
		Interface: iface,
	}, nil
}

// IsUp returns if a link / interface is up
func (l *Link) IsUp() bool {
	return !(l.Flags&syscall.IFF_UP == 0)
}

// FindAllLinks retrieves all system network interfaces and their link type
func FindAllLinks() ([]*Link, error) {

	// Retrieve all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve system network interfaces: %w", err)
	}

	// Determine link type for all interfaces
	var links []*Link
	for i := 0; i < len(ifaces); i++ {

		linkType, err := getLinkType(ifaces[i].Name)
		if err != nil {
			return nil, fmt.Errorf("failed to determine link type for interface `%s`: %w", ifaces[i].Name, err)
		}

		links = append(links, &Link{
			Interface: &ifaces[i],
			Type:      linkType,
		})
	}

	return links, err
}

///////////////////////////

func getLinkType(ifName string) (Type, error) {

	sysPath := fmt.Sprintf("/sys/class/net/%s/type", ifName)
	data, err := os.ReadFile(sysPath)
	if err != nil {
		return -1, err
	}

	val, err := strconv.Atoi(strings.ReplaceAll(string(data), "\n", ""))
	if err != nil {
		return -1, err
	}

	if val < 0 || val > 65535 {
		return -1, fmt.Errorf("invalid link type read from `%s`: %d", sysPath, val)
	}

	return Type(val), nil
}
