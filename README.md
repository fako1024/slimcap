# A high-performance network packet capture library

[![Github Release](https://img.shields.io/github/release/fako1024/slimcap.svg)](https://github.com/fako1024/slimcap/releases)
[![GoDoc](https://godoc.org/github.com/fako1024/slimcap?status.svg)](https://godoc.org/github.com/fako1024/slimcap/)
[![Go Report Card](https://goreportcard.com/badge/github.com/fako1024/slimcap)](https://goreportcard.com/report/github.com/fako1024/slimcap)
[![Build/Test Status](https://github.com/fako1024/slimcap/workflows/Go/badge.svg)](https://github.com/fako1024/slimcap/actions?query=workflow%3AGo)
[![CodeQL](https://github.com/fako1024/slimcap/actions/workflows/codeql.yml/badge.svg)](https://github.com/fako1024/slimcap/actions/workflows/codeql.yml)

This package provides a simple yet powerful interface to perform network packet capture / sniffing. It is focused on high performance / traffic throughput.

## Features
- Support for raw payload / IP layer packet capture via AF_PACKET (Linux) directly from network socket or using a ring buffer
- Minimal CPU usage and memory (allocation) footprint, support for zero-copy operations
- Virtual / mock capture sources including traffic replay from PCAP files (or even "chaining" multiple sources)
- Inherent support for packet type / direction detection
- Written in native Go (no `CGO` dependency)

> [!WARNING]
> **This package does *not* perform any payload / network layer decoding**\
> `slimcap` is aimed at doing the heavy lifting of extracting up to the IP layer of network packets with the utmost performance possible. All further parsing / processing must
> be done by the caller.

## Installation
```bash
go get -u github.com/fako1024/slimcap
```

## Usage
Perform simple capture of a few packets on a network interface using the various options of the `capture.Source` interface, using a fixed capture length (i.e. snaplen) of 64 bytes:
```go
listener, err := afpacket.NewSource("enp1s0",
	afpacket.CaptureLength(link.CaptureLengthFixed(64)),
)
if err != nil {
	// Error handling
}

// Capture a packet from the wire (allocate & copy)
p, err := listener.NextPacket(nil)
if err != nil {
	// Error handling
}
fmt.Printf("Received packet on enp1s0 (total len %d): %v (inbound: %v)\n",
	p.TotalLen(), p.Payload(), p.IsInbound())

// Capture a packet from the wire (copy to existing / reusable buffer packet)
pBuf := listener.NewPacket()
p, err := listener.NextPacket(pBuf)
if err != nil {
	// Error handling
}
fmt.Printf("Received packet on enp1s0 (total len %d): %v (inbound: %v)\n",
	p.TotalLen(), p.Payload(), p.IsInbound())

// Capture a packet from the wire (function execution)
if err := listener.NextPacketFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) (err error) {
	fmt.Printf("Received packet on enp1s0 (total len %d): %v (inbound: %v)\n",
		totalLen, payload, pktType != capture.PacketOutgoing)
	return
}); err != nil {
	// Error handling
}

// Close the listener / the capture
if err := listener.Close(); err != nil {
	// Error handling
}
```
Perform zero-copy capture of a few packets on a network interface using the various options of the `capture.SourceZeroCopy` interface, using an optimal capture length (i.e. snaplen) to ensure any transport layer can be accessed for IPv4 & IPv6 packets and setting custom ring buffer size / number of blocks:
```go
listener, err := afring.NewSource("enp1s0",
	afring.CaptureLength(link.CaptureLengthMinimalIPv6Transport),
	afring.BufferSize((1<<20), 4),
	afring.Promiscuous(false),
)
if err != nil {
	// Error handling
}

// Capture a raw packet (full payload) from the wire (zero-copy, no heap allocation)
payload, pktType, totalLen, err := listener.NextPayloadZeroCopy()
if err != nil {
	// Error handling
}
fmt.Printf("Received payload on enp1s0 (total len %d): %v (inbound: %v)\n",
	totalLen, payload, pktType != capture.PacketOutgoing)

// Capture a packet (IP layer only) from the wire (zero-copy, no heap allocation)
ipLayer, pktType, totalLen, err := listener.NextIPPacketZeroCopy()
if err != nil {
	// Error handling
}
fmt.Printf("Received IP layer on enp1s0 (total len %d): %v (inbound: %v)\n",
	totalLen, ipLayer, pktType != capture.PacketOutgoing)

// Close the listener / the capture
if err := listener.Close(); err != nil {
	// Error handling
}
```

> [!WARNING]
> In zero-copy mode, andy and all interactions with the payload / ipLayer must be concluded prior to the next invocation of `Next...ZeroCopy()` since the calls provide direct access to the memory areas allocated by AF_PACKET (which may be overwritten by the next call)!

For further examples, please refer to the implementations in [examples](./examples). A production-level project that uses `slimcap` and showcases all its capabilities (including end-to-end testing using mock sources) is [goProbe](https://github.com/els0r/goProbe).

## Performance
The following benchmarks (c.f. [afring_mock_test.go](./capture/afpacket/afring/afring_mock_test.go)) show the relative difference in
general performance and memory allocation footprint of a single packet retrieval (obtained on a commodity Laptop using mock capture sources). For obvious reasons, zero-copy mode performs best and hence should be chosen in high-throughput scenarios:
```
goarch: amd64
pkg: github.com/fako1024/slimcap/capture/afpacket/afring
cpu: Intel(R) Core(TM) i7-10510U CPU @ 1.80GHz
BenchmarkCaptureMethods
BenchmarkCaptureMethods/NextPacket         		226401712	  74.60 ns/op	64 B/op	  1 allocs/op
BenchmarkCaptureMethods/NextPacketInPlace  		353661006	  32.17 ns/op	 0 B/op	  0 allocs/op
BenchmarkCaptureMethods/NextPayload        		176332635	  63.81 ns/op	48 B/op	  1 allocs/op
BenchmarkCaptureMethods/NextPayloadInPlace 		516911223	  21.65 ns/op	 0 B/op	  0 allocs/op
BenchmarkCaptureMethods/NextPayloadZeroCopy     535092314	  19.67 ns/op	 0 B/op	  0 allocs/op
BenchmarkCaptureMethods/NextIPPacket            179753388	  64.18 ns/op	48 B/op	  1 allocs/op
BenchmarkCaptureMethods/NextIPPacketInPlace     381187490	  28.33 ns/op	 0 B/op	  0 allocs/op
BenchmarkCaptureMethods/NextIPPacketZeroCopy    567278034	  19.67 ns/op	 0 B/op	  0 allocs/op
BenchmarkCaptureMethods/NextPacketFn            559334258	  20.44 ns/op	 0 B/op	  0 allocs/op
```

## Capture Mocks / Testing
In order to support extensive testing up to end-to-end level without having to rely on _actual_ network interface capture, both plain AF_PACKET and ring buffer captures are provided with mock-level sources implementing / wrapping their actual implementations. Hence, it is possible to simply exchange any invocation of an `afpacket` or `afring` source with their respective mock counterpart, e.g. by changing:
```go
listener, err := afring.NewSource("enp1s0",
	// Options
)
```
to
```go
listener, err := afring.NewMockSource("enp1s0",
	// Options
)
```
By either generating synthetic packet data or piping previously captured packets from a PCAP file these mock sources can then be used just like actual capture sources, e.g. for testing purposes. Some good examples on how to perform test using mocks can be found in [afpacket_mock_test.go](./capture/afpacket/afpacket/afpacket_mock_test.go) and [afring_mock_test.go](./capture/afpacket/afring/afring_mock_test.go), respectively.
Since the mock implementations incur a minor, yet siginificant performance overhead (even if not used), `slimcap` supports a build tag that allows disabling mocks completely (which in turn will also remove the aforementioned overhead):
```bash
go build -tags slimcap_nomock
```
Using this build tag for high performance production environments is recommended.

## Bug Reports & Feature Requests
Please use the [issue tracker](https://github.com/fako1024/slimcap/issues) for bugs and feature requests (or any other matter).

## License
See the [LICENSE](./LICENSE) file for usage conditions.
