/*
Package pcap provides a simple packet dump tool that will simply consume up to a certain number
of previously captured network packets from the provided pcap file, optionally log them and then exit.
*/
package main

import (
	"errors"
	"flag"
	"io"

	"github.com/els0r/telemetry/logging"
	"github.com/fako1024/slimcap/capture/pcap"
)

func main() {

	var (
		fileName string
		maxPkts  int
		raw      bool
	)

	flag.StringVar(&fileName, "f", "", "pcap file to read from")
	flag.IntVar(&maxPkts, "n", 10, "maximum number of packets to process")
	flag.BoolVar(&raw, "r", false, "output raw packet information")
	flag.Parse()
	if fileName == "" {
		logging.Logger().Fatalf("no input file specified (-f)")
	}

	listener, err := pcap.NewSourceFromFile(fileName)
	if err != nil {
		logging.Logger().Fatalf("failed to start pcap reader for `%s`: %s", fileName, err)
	}

	defer func() {
		if err := listener.Close(); err != nil {
			logging.Logger().Fatalf("failed to close listener on `%s`: %s", fileName, err)
		}
	}()

	logging.Logger().Infof("Reading up to %d packets from `%s` (link type: %d)...", maxPkts, fileName, listener.Link().Type)
	for i := 0; i < maxPkts; i++ {
		p, err := listener.NextPacket(nil)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			logging.Logger().Fatalf("error during packet reading (copy operation) on `%s`: %s", fileName, err)
		}
		if raw {
			logging.Logger().Infof("Read packet with Payload (total len %d): %v", p.TotalLen(), p.Payload())
		} else {
			logging.Logger().Infof("Read packet (total len %d): %v", p.TotalLen(), p.IPLayer().String())
		}
	}
}
