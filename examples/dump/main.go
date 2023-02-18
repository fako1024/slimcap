package main

import (
	"flag"
	"log"

	"github.com/fako1024/slimcap/capture/afpacket"
	"github.com/fako1024/slimcap/link"
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

	link, err := link.New(devName)
	if err != nil {
		log.Fatalf("failed to set up link `%s`: %s", devName, err)
	}
	log.Printf("Listening on interface `%s`: %+v", link.Name, *link.Interface)

	listener, err := afpacket.NewRingBufSource(link,
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
