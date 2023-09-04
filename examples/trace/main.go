package main

import "github.com/fako1024/slimcap/examples/log"

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
		log.Fatal("critical error during capture: %s", err)
	}
}
