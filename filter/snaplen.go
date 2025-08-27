package filter

import (
	"github.com/fako1024/gotools/link"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// CaptureLengthStrategy denotes a strategy to calculate an optimal snaplen
// for a link (type) depending on the use case
type CaptureLengthStrategy = func(l *link.Link) int

var (

	// CaptureLengthFixed denotes a simple fixed snaplen strategy
	CaptureLengthFixed = func(snaplen int) CaptureLengthStrategy {
		return func(*link.Link) int {
			return snaplen
		}
	}

	// CaptureLengthMinimalIPv4Header indicates that the minimal necessary length to
	// facilitate IPv4 layer analysis should be chosen
	CaptureLengthMinimalIPv4Header = func(l *link.Link) int {
		return int(l.Type.IPHeaderOffset()) + ipv4.HeaderLen // include full IPv4 header
	}

	// CaptureLengthMinimalIPv6Header indicates that the minimal necessary length to
	// facilitate IPv6 layer analysis should be chosen
	CaptureLengthMinimalIPv6Header = func(l *link.Link) int {
		return int(l.Type.IPHeaderOffset()) + ipv6.HeaderLen // include full IPv6 header
	}

	// CaptureLengthMinimalIPv4Transport indicates that the minimal necessary length to
	// facilitate IPv4 transport layer analysis should be chosen
	CaptureLengthMinimalIPv4Transport = func(l *link.Link) int {
		return int(l.Type.IPHeaderOffset()) + ipv4.HeaderLen + 14 // include IPv4 transport layer up to TCP flag position
	}

	// CaptureLengthMinimalIPv6Transport indicates that the minimal necessary length to
	// facilitate IPv6 transport layer analysis should be chosen
	CaptureLengthMinimalIPv6Transport = func(l *link.Link) int {
		return int(l.Type.IPHeaderOffset()) + ipv6.HeaderLen + 14 // include IPv4 transport layer up to TCP flag position
	}
)
