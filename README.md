# A lightweight and high-performance network packet capture library

[![Github Release](https://img.shields.io/github/release/fako1024/slimcap.svg)](https://github.com/fako1024/slimcap/releases)
[![GoDoc](https://godoc.org/github.com/fako1024/slimcap?status.svg)](https://godoc.org/github.com/fako1024/slimcap/)
[![Go Report Card](https://goreportcard.com/badge/github.com/fako1024/slimcap)](https://goreportcard.com/report/github.com/fako1024/slimcap)
[![Build/Test Status](https://github.com/fako1024/slimcap/workflows/Go/badge.svg)](https://github.com/fako1024/slimcap/actions?query=workflow%3AGo)
[![CodeQL](https://github.com/fako1024/slimcap/actions/workflows/codeql.yml/badge.svg)](https://github.com/fako1024/slimcap/actions/workflows/codeql.yml)

This package provides a simple interface to network packet capture / sniffing. It is focused on high performance and does *not* perform any payload / network layer decoding.

**Note:** This is currently considered WIP. The interface and / or features are not stable and can change at any point in time !

## Features
- Support for network packet capture via AF_PACKET (Linux) directly from network socket or via ring buffer
- Minimal memory and CPU usage footprint, support for zero-copy operations

## Installation
```bash
go get -u github.com/fako1024/slimcap
```

## Examples
#### Perform simple capture of a few packets on a network interface (c.f. `examples/dump`)
```go
package main

import (
	"flag"
	"log"

	"github.com/fako1024/slimcap/capture/afpacket"
)

func main() {

	var (
		devName string
		maxPkts int
	)

	flag.StringVar(&devName, "d", "", "device / interface to capture on")
	flag.IntVar(&maxPkts, "n", 10, "maximum number of packets to capture")
	flag.Parse()
	if devName == "" {
		log.Fatal("no interface specified (-d)")
	}

	listener, err := afpacket.NewRingBufSource(devName,
		afpacket.CaptureLength(64),
		afpacket.BufferSize((1<<20), 4),
		afpacket.Promiscuous(false),
	)
	if err != nil {
		log.Fatalf("failed to start listener or `%s`: %s", devName, err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			log.Fatalf("failed to close listener or `%s`: %s", devName, err)
		}
	}()
	log.Printf("Listening on interface `%s`: %+v", listener.Link().Name, listener.Link().Interface)

	log.Printf("Reading %d packets from wire (copy operation)...", maxPkts)
	for i := 0; i < maxPkts; i++ {
		p, err := listener.NextPacket(nil)
		if err != nil {
			log.Fatalf("error during capture (copy operation) on `%s`: %s", devName, err)
		}
		log.Printf("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, p.TotalLen(), p.Payload(), p.Type() == 0)
	}

	log.Printf("Reading %d packets from wire (read into existing buffer)...", maxPkts)
	p := listener.NewPacket()
	for i := 0; i < maxPkts; i++ {
		if p, err = listener.NextPacket(p); err != nil {
			log.Fatalf("error during capture (read into existing buffer) on `%s`: %s", devName, err)
		}
		log.Printf("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, p.TotalLen(), p.Payload(), p.Type() == 0)
	}

	log.Printf("Reading %d packets from wire (zero-copy function call)...", maxPkts)
	for i := 0; i < maxPkts; i++ {
		if err := listener.NextPacketFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) (err error) {
			log.Printf("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, totalLen, payload, pktType == 0)
			return
		}); err != nil {
			log.Fatalf("error during capture (zero-copy function call) on `%s`: %s", devName, err)
		}
	}
}

```
