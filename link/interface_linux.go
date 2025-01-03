//go:build linux
// +build linux

package link

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

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
