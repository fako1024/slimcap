package link

// Interface is the low-level representation of a network interface
type Interface struct {
	Name  string
	Index int
	Type  Type
}

// NewInterface instantiates a new network interface and obtains its basic parameters
func NewInterface(name string) (iface Interface, err error) {
	iface = Interface{
		Name: name,
	}

	if iface.Index, err = getIndex(name); err != nil {
		return
	}
	if iface.Type, err = getLinkType(name); err != nil {
		return
	}

	return
}

// String returns the name of the network interface (Stringer interface)
func (i Interface) String() string {
	return i.Name
}
