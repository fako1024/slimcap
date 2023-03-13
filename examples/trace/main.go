package main

import (
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func main() {

	cfg := ParseConfig()
	defer logger.Sync()

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
