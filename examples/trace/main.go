/*
Package trace provides a comprehensive tool that supports various common use cases when
interacting with the `slimcap` module, including plain and ring-buffer AF_PACKET capture
on multiple interfaces, zero-copy mode (if requested) and optional logging and profiling.
*/
package main

import (
	"github.com/els0r/telemetry/logging"
)

var logger *logging.L

func main() {

	cfg := ParseConfig()

	c := &Capture{}
	if err := c.OnIfaces(cfg.Ifaces).
		SkipIfaces(cfg.SkipIfaces).
		MaxIfaceErrors(cfg.MaxIfaceErrors).
		UseRingBuffer(cfg.UseRingBuffer).
		UseZeroCopy(cfg.UseZeroCopy).
		LogPacketPayload(cfg.LogPacketPayload).
		WithCPUProfiling(cfg.CPUProfileOutput).
		WithMemProfiling(cfg.MemProfileOutput).
		Run(); err != nil {
		logger.Fatalf("critical error during capture: %s", err)
	}
}
