package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/els0r/telemetry/logging"
	"github.com/fako1024/slimcap/capture/pcap"
)

func main() {

	var (
		fileName string
		maxPkts  int
		raw      bool
	)

	logger, logErr := logging.New(logging.LevelInfo, logging.EncodingPlain)
	if logErr != nil {
		fmt.Fprintf(os.Stderr, "failed to instantiate CLI logger: %v\n", logErr)
		os.Exit(1)
	}

	flag.StringVar(&fileName, "f", "", "pcap file to read from")
	flag.IntVar(&maxPkts, "n", 10, "maximum number of packets to process")
	flag.BoolVar(&raw, "r", false, "output raw packet information")
	flag.Parse()
	if fileName == "" {
		logger.Fatalf("no input file specified (-f)")
	}

	listener, err := pcap.NewSourceFromFile(fileName)
	if err != nil {
		logger.Fatalf("failed to start pcap reader for `%s`: %s", fileName, err)
	}

	defer func() {
		if err := listener.Close(); err != nil {
			logger.Fatalf("failed to close listener on `%s`: %s", fileName, err)
		}
	}()

	logger.Infof("Reading up to %d packets from `%s` (link type: %d)...", maxPkts, fileName, listener.Link().Type)
	for i := 0; i < maxPkts; i++ {
		p, err := listener.NextPacket(nil)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			logger.Fatalf("error during packet reading (copy operation) on `%s`: %s", fileName, err)
		}
		if raw {
			logger.Infof("Read packet with Payload (total len %d): %v", p.TotalLen(), p.Payload())
		} else {
			logger.Infof("Read packet (total len %d): %v", p.TotalLen(), p.IPLayer().String())
		}
	}
}
