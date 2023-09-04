package main

import (
	"flag"
	"strings"

	"github.com/fako1024/slimcap/examples/log"
)

const (
	Ifaces             = "ifaces"
	LogLevel           = "log-level"
	MaxIfaceErrors     = "max-iface-errors"
	CPUProfilingOutput = "cpu-profiling-output"
	MemProfilingOutput = "mem-profiling-output"
	SkipIfaces         = "skip-ifaces"
	UseRingBuffer      = "use-ring-buffer"
	UseZeroCopy        = "use-zero-copy"
	LogPacketPayload   = "log-packets"
)

const (
	DefaultLogLevel       = "info"
	DefaultMaxIfaceErrors = 10
)

type Config struct {
	Ifaces           []string
	SkipIfaces       []string
	LogLevel         string
	MaxIfaceErrors   int
	UseRingBuffer    bool
	UseZeroCopy      bool
	LogPacketPayload bool

	CPUProfileOutput string
	MemProfileOutput string
}

func ParseConfig() (cfg Config) {

	var rawIfaces, rawSkipIfaces string

	flag.StringVar(&cfg.LogLevel, LogLevel, DefaultLogLevel, "log level")
	flag.IntVar(&cfg.MaxIfaceErrors, MaxIfaceErrors, DefaultMaxIfaceErrors, "maximum interface errors encountered before they are logged")
	flag.StringVar(&rawIfaces, Ifaces, "", "comma/space-separated list of interfaces to capture on")
	flag.StringVar(&rawSkipIfaces, SkipIfaces, "", "comma/space-separated list of interfaces to skip capturing on")

	flag.BoolVar(&cfg.UseRingBuffer, UseRingBuffer, true, "use ring buffer for capturing")
	flag.BoolVar(&cfg.UseZeroCopy, UseZeroCopy, true, "use zero-copy operations for capturing")
	flag.BoolVar(&cfg.LogPacketPayload, LogPacketPayload, false, "log first bytes of packet payload to console (INFO level)")

	flag.StringVar(&cfg.CPUProfileOutput, CPUProfilingOutput, "", "pprof CPU profile output file")
	flag.StringVar(&cfg.MemProfileOutput, MemProfilingOutput, "", "pprof MEM profile output file")

	flag.Parse()
	cfg.Ifaces = parseList(rawIfaces)
	cfg.SkipIfaces = parseList(rawSkipIfaces)

	log.SetLevel(cfg.LogLevel)

	return
}

func parseList(list string) []string {
	return strings.Fields(strings.Replace(list, ",", " ", -1))
}
