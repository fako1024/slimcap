//go:build linux
// +build linux

package link

import (
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"strconv"
	"strings"
	"unsafe"

	"syscall"

	"golang.org/x/sys/unix"
)

const (
	netBasePath   = "/sys/class/net/"
	netUEventPath = "/uevent"
	netTypePath   = "/type"
	netFlagsPath  = "/flags"

	netUEventIfIndexPrefix    = "IFINDEX="
	netUEventDevTypePrefix    = "DEVTYPE="
	netUEventDevTypeVLAN      = "vlan"
	netUEventIfIndexPrefixLen = len(netUEventIfIndexPrefix)
	netUEventDevTypePrefixLen = len(netUEventDevTypePrefix)
)

var (
	// ErrIndexOutOfBounds denotes the (unlikely) case of an invalid index being outside the range of an int
	ErrIndexOutOfBounds = errors.New("interface index out of bounds")
)

// Interfaces returns all host interfaces
func Interfaces() ([]Interface, error) {

	linkDir, err := os.OpenFile(netBasePath, os.O_RDONLY, 0600)
	if err != nil {
		return nil, err
	}

	ifaceNames, err := linkDir.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	ifaces := make([]Interface, len(ifaceNames))
	for i, ifaceName := range ifaceNames {
		if ifaces[i], err = NewInterface(ifaceName); err != nil {
			return nil, err
		}
	}

	return ifaces, nil
}

// IsUp determines if an interface is currently up (at the time of the call)
func (i Interface) IsUp() (bool, error) {

	data, err := os.ReadFile(netBasePath + i.Name + netFlagsPath)
	if err != nil {
		return false, err
	}

	flags, err := strconv.ParseInt(
		strings.TrimSpace(string(data)), 0, 64)
	if err != nil {
		return false, err
	}

	return flags&unix.IFF_UP != 0, nil
}

// IPs retrieves all IPv4 and IPv6 addresses assigned to the interface using
// a minimal netlink RTM_GETADDR dump to avoid the higher-level net package.
// Mostly extracted from the net package internals (net.Interface.Addrs()).
func (i Interface) IPs() ([]net.IP, error) {
	tab, err := syscall.NetlinkRIB(syscall.RTM_GETADDR, syscall.AF_UNSPEC)
	if err != nil {
		return nil, os.NewSyscallError("netlinkrib", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, os.NewSyscallError("parsenetlinkmessage", err)
	}
	ifat, err := addrTable(&i, msgs)
	if err != nil {
		return nil, err
	}
	return ifat, nil
}

func (i Interface) getIndexVLAN() (int, bool, error) {

	data, err := os.ReadFile(netBasePath + i.Name + netUEventPath)
	if err != nil {
		return -1, false, err
	}

	return extractIndexVLAN(data)
}

func (i Interface) getLinkType() (Type, error) {

	data, err := os.ReadFile(netBasePath + i.Name + netTypePath)
	if err != nil {
		return -1, err
	}

	val, err := strconv.Atoi(
		strings.TrimSpace(string(data)))
	if err != nil {
		return -1, err
	}

	if val < 0 || val > 65535 {
		return -1, fmt.Errorf("invalid link type read from `%s`: %d", netBasePath+i.Name+netTypePath, val)
	}

	return Type(val), nil
}

////////////////////////////////////////////////////////////////////////////////

func extractIndexVLAN(data []byte) (int, bool, error) {
	var (
		index  int64
		isVLAN bool
		err    error
	)

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, netUEventIfIndexPrefix) {
			index, err = strconv.ParseInt(
				strings.TrimSpace(line[netUEventIfIndexPrefixLen:]), 0, 64)
			if err != nil {
				return -1, false, err
			}
			continue
		}

		if strings.HasPrefix(line, netUEventDevTypePrefix) {
			isVLAN = strings.EqualFold(strings.TrimSpace(line[netUEventDevTypePrefixLen:]),
				netUEventDevTypeVLAN)
		}
	}

	// Validate integer upper / lower bounds
	if index > 0 && index <= math.MaxInt {
		return int(index), isVLAN, nil
	}

	return -1, false, ErrIndexOutOfBounds
}

func addrTable(iface *Interface, msgs []syscall.NetlinkMessage) ([]net.IP, error) {
	var ifat []net.IP
loop:
	for _, m := range msgs {
		switch m.Header.Type {
		case syscall.NLMSG_DONE:
			break loop
		case syscall.RTM_NEWADDR:
			ifam := (*syscall.IfAddrmsg)(unsafe.Pointer(&m.Data[0])) // #nosec G103
			if iface.Index == int(ifam.Index) {
				attrs, err := syscall.ParseNetlinkRouteAttr(&m)
				if err != nil {
					return nil, os.NewSyscallError("parsenetlinkrouteattr", err)
				}
				ifa := newAddr(ifam, attrs)
				if ifa != nil {
					ifat = append(ifat, ifa)
				}
			}
		}
	}
	return ifat, nil
}

func newAddr(ifam *syscall.IfAddrmsg, attrs []syscall.NetlinkRouteAttr) net.IP {
	var ipPointToPoint bool
	// Seems like we need to make sure whether the IP interface
	// stack consists of IP point-to-point numbered or unnumbered
	// addressing.
	for _, a := range attrs {
		if a.Attr.Type == syscall.IFA_LOCAL {
			ipPointToPoint = true
			break
		}
	}
	for _, a := range attrs {
		if ipPointToPoint && a.Attr.Type == syscall.IFA_ADDRESS {
			continue
		}
		switch ifam.Family {
		case syscall.AF_INET:
			return net.IPv4(a.Value[0], a.Value[1], a.Value[2], a.Value[3])
		case syscall.AF_INET6:
			ip := make(net.IP, net.IPv6len)
			copy(ip, a.Value[:])
			return ip
		}
	}
	return nil
}
