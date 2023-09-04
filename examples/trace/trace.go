package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"syscall"

	"github.com/fako1024/slimcap/capture"
	"github.com/fako1024/slimcap/capture/afpacket/afpacket"
	"github.com/fako1024/slimcap/capture/afpacket/afring"
	"github.com/fako1024/slimcap/examples/log"
	"github.com/fako1024/slimcap/link"
)

// Capture denotes a simple capturing structure / manager
type Capture struct {
	ifaces, skipIfaces []string
	maxIfaceErrors     int
	useRingBuffer      bool
	useZeroCopy        bool
	logPacketPayload   bool

	cpuProfilePath string
	memProfilePath string
}

// OnIfaces sets the interfaces to capture / process on
func (c *Capture) OnIfaces(ifaces []string) *Capture {
	c.ifaces = ifaces
	return c
}

// SkipIfaces sets an optional list of interfaces to skip
func (c *Capture) SkipIfaces(ifaces []string) *Capture {
	c.skipIfaces = ifaces
	return c
}

// MaxIfaceErrors sets the maximum number of errors allowed to occur before capture is terminated
func (c *Capture) MaxIfaceErrors(max int) *Capture {
	c.maxIfaceErrors = max
	return c
}

// UseRingBuffer enables / disables the use of the AF_PACKET ring buffer
func (c *Capture) UseRingBuffer(b bool) *Capture {
	c.useRingBuffer = b
	return c
}

// UseZeroCopy enables / disables processing via zero-copy methods
func (c *Capture) UseZeroCopy(b bool) *Capture {
	c.useZeroCopy = b
	return c
}

// LogPacketPayload enables / disables verbose logging of the packet payload
func (c *Capture) LogPacketPayload(b bool) *Capture {
	c.logPacketPayload = b
	return c
}

// WithCPUProfiling enables CPU profiling and stores it at the provided destination / path
func (c *Capture) WithCPUProfiling(profilePath string) *Capture {
	c.cpuProfilePath = profilePath
	return c
}

// WithMemProfiling enables memory profiling and stores it at the provided destination / path
func (c *Capture) WithMemProfiling(profilePath string) *Capture {
	c.memProfilePath = profilePath
	return c
}

// Run starts the capture
func (c *Capture) Run() (err error) {

	if c.cpuProfilePath != "" {
		f, err := os.Create(c.cpuProfilePath)
		if err != nil {
			return err
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			return err
		}
		defer pprof.StopCPUProfile()
	}
	if c.memProfilePath != "" {
		defer func() {
			f, perr := os.Create(c.memProfilePath)
			if err != nil {
				err = perr
				return
			}
			if perr := pprof.Lookup("allocs").WriteTo(f, 0); perr != nil {
				err = perr
			}
		}()
	}

	// Read and log all interfaces
	links, err := link.FindAllLinks()
	if err != nil {
		return err
	}
	for _, iface := range links {
		log.Info("Found interface `%s` (idx %d), link type %d", iface.Name, iface.Index, iface.Type)
	}

	// construct list of skipped interfaces
	auxMapAvailableLinks := make(map[string]struct{}, len(links))
	for _, link := range links {
		auxMapAvailableLinks[strings.ToLower(link.Interface.Name)] = struct{}{}
	}

	auxMapIfaces := make(map[string]struct{}, len(c.ifaces))
	if len(c.ifaces) > 0 {
		for _, iface := range c.ifaces {
			iStr := strings.ToLower(iface)

			_, exists := auxMapAvailableLinks[iStr]
			if !exists {
				return fmt.Errorf("interface %q not found on host", iface)
			}
			auxMapIfaces[iStr] = struct{}{}
		}
	} else {
		auxMapIfaces = auxMapAvailableLinks
	}

	for _, iface := range c.skipIfaces {
		iStr := strings.ToLower(iface)
		_, exists := auxMapIfaces[iStr]
		if exists {
			delete(auxMapIfaces, iStr)
		}
	}

	var capturing, skipped []string
	for _, link := range links {
		_, exists := auxMapIfaces[strings.ToLower(link.Interface.Name)]
		if !exists {
			skipped = append(skipped, link.Interface.Name)
		} else {
			capturing = append(capturing, link.Interface.Name)
		}
	}
	sort.Slice(skipped, func(i, j int) bool {
		return skipped[i] < skipped[j]
	})
	if len(skipped) > 0 {
		log.Warn("skipping capture on interfaces [%s]", strings.Join(skipped, ","))
	}

	sort.Slice(capturing, func(i, j int) bool {
		return capturing[i] < capturing[j]
	})
	log.Info("attempting capture on interfaces [%s]", strings.Join(capturing, ","))

	sigExitChan := make(chan os.Signal, 1)
	signal.Notify(sigExitChan, syscall.SIGTERM, os.Interrupt)

	var listeners []capture.Source
	// Fork a goroutine for each interface
	wg := sync.WaitGroup{}
	for _, iface := range links {
		wg.Add(1)
		go func(l *link.Link) {
			defer wg.Done()

			for _, skipLink := range skipped {
				if l.Name == skipLink {
					return
				}
			}

			if isUp, err := l.IsUp(); err != nil || !isUp {
				log.Warn("skipping listener on non-up interface `%s`", l.Name)
				return
			}

			var listener capture.Source
			if c.useRingBuffer {
				listener, err = afring.NewSourceFromLink(l, afring.CaptureLength(link.CaptureLengthMinimalIPv6Transport))
				if err != nil {
					log.Error("error starting listener (with ring buffer) on `%s`: %s", l.Name, err)
				}
			} else {
				listener, err = afpacket.NewSourceFromLink(l)
				if err != nil {
					log.Error("error starting listener (no ring buffer) on `%s`: %s", l.Name, err)
				}
			}
			listeners = append(listeners, listener)

			var nErr int
			if c.useZeroCopy {
				for {
					if err := listener.NextPacketFn(func(payload []byte, totalLen uint32, pktType byte, ipLayerOffset byte) error {
						if c.logPacketPayload {
							log.Info("[%s] Got %v / %d", l.Name, payload[ipLayerOffset:ipLayerOffset+16], pktType)
						}
						return nil
					}); err != nil {
						if errors.Is(err, capture.ErrCaptureStopped) {
							log.Info("gracefully stopped capture on `%s`", l.Name)
							return
						}
						nErr++
						if nErr >= c.maxIfaceErrors {
							log.Error("too many errors (%d) on `%s`, stopping capture", nErr, l.Name)
						}
					}
				}
			} else {
				for {
					pkt, err := listener.NextPacket(nil)
					if err != nil {
						if errors.Is(err, capture.ErrCaptureStopped) {
							log.Info("gracefully stopped capture on `%s`", l.Name)
							return
						}
						nErr++
						if nErr >= c.maxIfaceErrors {
							log.Error("too many errors (%d) on `%s`, stopping capture", nErr, l.Name)
						}
					}

					if c.logPacketPayload {
						log.Info("[%s] Got IP layer %v / %d", l.Name, pkt.IPLayer()[:16], pkt.Type())
					}
				}
			}

		}(iface)
	}

	go func() {
		// Wait for signal to exit
		<-sigExitChan

		for _, listener := range listeners {
			stats, err := listener.Stats()
			if err != nil {
				log.Error("failed to retrieve socket stats: %s", err)
			}
			log.Info("Packet stats: %#v", stats)

			if err := listener.Close(); err != nil {
				log.Error("failed to gracefully stop capture: %s", err)
			}
		}
	}()

	wg.Wait()
	return nil
}
