package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/els0r/telemetry/logging"
	"github.com/fako1024/slimcap/capture/afpacket/afring"
	"github.com/fako1024/slimcap/link"
)

func main() {

	var (
		devName string
		maxPkts int
	)

	logger, logErr := logging.New(logging.LevelInfo, logging.EncodingPlain)
	if logErr != nil {
		fmt.Fprintf(os.Stderr, "failed to instantiate CLI logger: %v\n", logErr)
		os.Exit(1)
	}

	flag.StringVar(&devName, "d", "", "device / interface to capture on")
	flag.IntVar(&maxPkts, "n", 10, "maximum number of packets to capture")
	flag.Parse()
	if devName == "" {
		logger.Fatal("no interface specified (-d)")
	}

	listener, err := afring.NewSource(devName,
		afring.CaptureLength(link.CaptureLengthFixed(64)),
		afring.BufferSize((1<<20), 4),
		afring.Promiscuous(false),
	)
	if err != nil {
		logger.Fatalf("failed to start listener on `%s`: %s", devName, err)
	}
	logger.Infof("Listening on interface `%s`: %+v", listener.Link().Name, listener.Link().Interface)

	logger.Infof("Reading %d packets from wire (copy operation)...", maxPkts)
	for i := 0; i < maxPkts; i++ {
		p, err := listener.NextPacket(nil)
		if err != nil {
			logger.Fatalf("error during capture (copy operation) on `%s`: %s", devName, err)
		}
		logger.Infof("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, p.TotalLen(), p.Payload(), p.IsInbound())
	}

	logger.Infof("Reading %d packets from wire (read into existing buffer)...", maxPkts)
	p := listener.NewPacket()
	for i := 0; i < maxPkts; i++ {
		if p, err = listener.NextPacket(p); err != nil {
			logger.Fatalf("error during capture (read into existing buffer) on `%s`: %s", devName, err)
		}
		logger.Infof("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, p.TotalLen(), p.Payload(), p.IsInbound())
	}

	logger.Infof("Reading %d packets from wire (zero-copy function call)...", maxPkts)
	for i := 0; i < maxPkts; i++ {
		if err := listener.NextPacketFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) (err error) {
			logger.Infof("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, totalLen, payload, p.IsInbound())
			return
		}); err != nil {
			logger.Fatalf("error during capture (zero-copy function call) on `%s`: %s", devName, err)
		}
	}

	if err := listener.Close(); err != nil {
		logger.Fatalf("failed to close listener on `%s`: %s", devName, err)
	}
}
