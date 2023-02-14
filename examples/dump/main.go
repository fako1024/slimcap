package main

import (
	"log"

	"github.com/fako1024/slimcap/capture/afpacket"
	"github.com/fako1024/slimcap/link"
)

func main() {

	var (
		devName = "enp45s0u1u1"
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

	log.Printf("Reading %d packets from wire (copy operation)...", maxPkts)
	for i := 0; i < maxPkts; i++ {
		p, err := listener.NextPacket()
		if err != nil {
			log.Fatalf("error during capture (copy operation) on `%s`: %s", devName, err)
		}
		log.Printf("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, p.TotalLen(), p.Payload(), p.Type() == 0)
	}

	log.Printf("Reading %d packets from wire (read into existing buffer)...", maxPkts)
	p := make(afpacket.Packet, 64)
	for i := 0; i < maxPkts; i++ {
		if err := listener.NextPacketInto(&p); err != nil {
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
