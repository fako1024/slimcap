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
	"syscall"
)

const (
	netBasePath  = "/sys/class/net/"
	netIndexPath = "/ifindex"
	netTypePath  = "/type"
	netFlagsPath = "/flags"
)

// ErrIndexOutOfBounds denotes the (unlikely) case of an invalid index being outside the range of an int
var ErrIndexOutOfBounds = errors.New("interface index out of bounds")

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

	return flags&syscall.IFF_UP != 0, nil
}

////////////////////////////////////////////////////////////////////////////////

func (i Interface) getIndex() (int, error) {

	data, err := os.ReadFile(netBasePath + i.Name + netIndexPath)
	if err != nil {
		return -1, err
	}

	index, err := strconv.ParseInt(
		strings.TrimSpace(string(data)), 0, 64)
	if err != nil {
		return -1, err
	}

	// Validate integer upper / lower bounds
	if index > 0 && index <= math.MaxInt {
		return int(index), nil
	}

	return -1, ErrIndexOutOfBounds
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
