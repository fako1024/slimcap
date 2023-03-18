package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/fako1024/slimcap/capture/afpacket"
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func main() {

	zapLogger, err := zap.NewDevelopment()
	if err != nil {
		fmt.Printf("failed to instantiate logger: %s\n", err)
		os.Exit(1)
	}
	defer zapLogger.Sync()
	logger = zapLogger.Sugar()

	var (
		devName string
		maxPkts int
	)

	flag.StringVar(&devName, "d", "", "device / interface to capture on")
	flag.IntVar(&maxPkts, "n", 10, "maximum number of packets to capture")
	flag.Parse()
	if devName == "" {
		logger.Fatal("no interface specified (-d)")
	}

	listener, err := afpacket.NewRingBufSource(devName,
		afpacket.CaptureLength(64),
		afpacket.BufferSize((1<<20), 4),
		afpacket.Promiscuous(false),
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
		logger.Infof("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, p.TotalLen(), p.Payload(), p.Type() == 0)
	}

	logger.Infof("Reading %d packets from wire (read into existing buffer)...", maxPkts)
	p := listener.NewPacket()
	for i := 0; i < maxPkts; i++ {
		if p, err = listener.NextPacket(p); err != nil {
			logger.Fatalf("error during capture (read into existing buffer) on `%s`: %s", devName, err)
		}
		logger.Infof("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, p.TotalLen(), p.Payload(), p.Type() == 0)
	}

	logger.Infof("Reading %d packets from wire (zero-copy function call)...", maxPkts)
	for i := 0; i < maxPkts; i++ {
		if err := listener.NextPacketFn(func(payload []byte, totalLen uint32, pktType, ipLayerOffset byte) (err error) {
			logger.Infof("Received packet with Payload on `%s` (total len %d): %v (inbound: %v)", devName, totalLen, payload, pktType == 0)
			return
		}); err != nil {
			logger.Fatalf("error during capture (zero-copy function call) on `%s`: %s", devName, err)
		}
	}

	if err := listener.Close(); err != nil {
		logger.Fatalf("failed to close listener on `%s`: %s", devName, err)
	}
	time.Sleep(time.Second)
	if err := listener.Free(); err != nil {
		logger.Fatalf("failed to free listener resources on `%s`: %s", devName, err)
	}

	return
}
