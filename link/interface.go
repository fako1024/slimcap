package link

import "path/filepath"

// Interface is the low-level representation of a network interface
type Interface struct {
	Name   string
	Index  int
	isVLAN bool
	Type   Type
}

// NewInterface instantiates a new network interface and obtains its basic parameters
func NewInterface(name string) (iface Interface, err error) {
	iface = Interface{
		Name: filepath.Clean(name),
	}

	if iface.Index, iface.isVLAN, err = iface.getIndexVLAN(); err != nil {
		return
	}
	if iface.Type, err = iface.getLinkType(); err != nil {
		return
	}

	return
}

// String returns the name of the network interface (Stringer interface)
func (i Interface) String() string {
	return i.Name
}
