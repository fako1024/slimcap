package main

import (
	"log"

	"github.com/fako1024/slimcap/capture/afpacket"
	"github.com/fako1024/slimcap/link"
)

func main() {

	var (
		devName = "eth0"
		maxPkts = 10
	)

	link, err := link.New(devName)
	if err != nil {
		log.Fatalf("failed to set up link `%s`: %s", devName, err)
	}

	listener, err := afpacket.NewRingBufSource(link,
		afpacket.CaptureLength(64),
		afpacket.BufferSize(1*1024*1024),
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

	for i := 0; i < maxPkts; i++ {
		if err := listener.NextIPPacketFn(func(payload []byte, pktType byte) error {
			log.Printf("Received packet with IP layer on `%s`: %v (inbound: %v)", devName, payload, pktType == 0)
			return nil
		}); err != nil {
			log.Fatalf("error during capture on `%s`: %s", devName, err)
		}
	}
}
