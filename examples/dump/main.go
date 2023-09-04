package main

import (
	"flag"

	"github.com/fako1024/slimcap/capture/afpacket/afring"
	"github.com/fako1024/slimcap/examples/log"
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

	listener, err := afring.NewSource(devName,
		afring.CaptureLength(link.CaptureLengthFixed(64)),
		afring.BufferSize((1<<20), 4),
		afring.Promiscuous(false),
	)
	if err != nil {
		log.Fatal("failed to start listener on `%s`: %s", devName, err)
	}
	log.Info("Listening on interface `%s`: %+v", listener.Link().Name, listener.Link().Interface)

	log.Info("Reading %d packets from wire (copy operation)...", maxPkts)
	for i := 0; i < maxPkts; i++ {
		p, err := listener.NextPacket(nil)
		if err != nil {
			log.Fatal("error during capture (copy operation) on `%s`: %s", devName, err)
		}
		log.Info("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, p.TotalLen(), p.Payload(), p.IsInbound())
	}

	log.Info("Reading %d packets from wire (read into existing buffer)...", maxPkts)
	p := listener.NewPacket()
	for i := 0; i < maxPkts; i++ {
		if p, err = listener.NextPacket(p); err != nil {
			log.Fatal("error during capture (read into existing buffer) on `%s`: %s", devName, err)
		}
		log.Info("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, p.TotalLen(), p.Payload(), p.IsInbound())
	}

	log.Info("Reading %d packets from wire (zero-copy function call)...", maxPkts)
	for i := 0; i < maxPkts; i++ {
		if err := listener.NextPacketFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) (err error) {
			log.Info("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, totalLen, payload, p.IsInbound())
			return
		}); err != nil {
			log.Fatal("error during capture (zero-copy function call) on `%s`: %s", devName, err)
		}
	}

	if err := listener.Close(); err != nil {
		log.Fatal("failed to close listener on `%s`: %s", devName, err)
	}
}
