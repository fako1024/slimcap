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

// LinkType denotes the linux interface type
type LinkType int

// IpHeaderOffset returns the link / interface specific payload offset for the IP header
// c.f. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/if_arp.h
func (l LinkType) IpHeaderOffset() byte {
	switch l {
	case 1, // ARPHRD_ETHER
		772: // ARPHRD_LOOPBACK
		return IPLayerOffsetEthernet
	case 512, // ARPHRD_PPP
		778,   // ARPHRD_IPGRE
		65534: // ARPHRD_NONE Tunnel / anything else (confirmed: Wireguard, OpenVPN)
		return 0
	}

	// Panic if unknown
	panic(fmt.Sprintf("Link Type %d not supported (yet)", l))
}

// BPFFilter returns the link / interface specific raw BPF instructions to filter for valid packets only
func (l LinkType) BPFFilter() func(snapLen int) []bpf.RawInstruction {
	switch l {
	case 1, // ARPHRD_ETHER
		772: // ARPHRD_LOOPBACK
		return bpfInstructionsLinkTypeEther
	case 512, // ARPHRD_PPP
		778,   // ARPHRD_IPGRE
		65534: // ARPHRD_NONE Tunnel / anything else (confirmed: Wireguard, OpenVPN)
		return bpfInstructionsLinkTypeRaw
	}

	// Panic if unknown
	panic(fmt.Sprintf("Link Type %d not supported (yet)", l))
}

// Link denotes a link, i.e. an interface (wrapped) and its link type
type Link struct {
	LinkType LinkType

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
		LinkType:  linkType,
		Interface: iface,
	}, nil
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
			LinkType:  linkType,
		})
	}

	return links, err
}

///////////////////////////

func getLinkType(ifName string) (LinkType, error) {

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

	return LinkType(val), nil
}
