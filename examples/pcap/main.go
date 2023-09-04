package main

import (
	"errors"
	"flag"
	"io"

	"github.com/fako1024/slimcap/capture/pcap"
	"github.com/fako1024/slimcap/examples/log"
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
		log.Fatal("no input file specified (-f)")
	}

	listener, err := pcap.NewSourceFromFile(fileName)
	if err != nil {
		log.Fatal("failed to start pcap reader for `%s`: %s", fileName, err)
	}

	defer func() {
		if err := listener.Close(); err != nil {
			log.Fatal("failed to close listener on `%s`: %s", fileName, err)
		}
	}()

	log.Info("Reading up to %d packets from `%s` (link type: %d)...", maxPkts, fileName, listener.Link().Type)
	for i := 0; i < maxPkts; i++ {
		p, err := listener.NextPacket(nil)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return
			}
			log.Fatal("error during packet reading (copy operation) on `%s`: %s", fileName, err)
		}
		if raw {
			log.Info("Read packet with Payload (total len %d): %v", p.TotalLen(), p.Payload())
		} else {
			log.Info("Read packet (total len %d): %v", p.TotalLen(), p.IPLayer().String())
		}
	}
}
