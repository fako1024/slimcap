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
	"github.com/fako1024/slimcap/capture/afpacket"
	"github.com/fako1024/slimcap/link"
	"github.com/sirupsen/logrus"
)

var log = logrus.StandardLogger()

type Capture struct {
	ifaces, skipIfaces []string
	maxIfaceErrors     int
	useRingBuffer      bool
	useZeroCopy        bool
	logPacketPayload   bool

	cpuProfilePath string
	memProfilePath string
}

func (c *Capture) OnIfaces(ifaces []string) *Capture {
	c.ifaces = ifaces
	return c
}

func (c *Capture) SkipIfaces(ifaces []string) *Capture {
	c.skipIfaces = ifaces
	return c
}

func (c *Capture) MaxIfaceErrors(max int) *Capture {
	c.maxIfaceErrors = max
	return c
}

func (c *Capture) UseRingBuffer(b bool) *Capture {
	c.useRingBuffer = b
	return c
}

func (c *Capture) UseZeroCopy(b bool) *Capture {
	c.useZeroCopy = b
	return c
}

func (c *Capture) LogPacketPayload(b bool) *Capture {
	c.logPacketPayload = b
	return c
}

func (c *Capture) WithCPUProfiling(profilePath string) *Capture {
	c.cpuProfilePath = profilePath
	return c
}

func (c *Capture) WithMemProfiling(profilePath string) *Capture {
	c.memProfilePath = profilePath
	return c
}

func (c *Capture) Run() (err error) {

	if c.cpuProfilePath != "" {
		f, err := os.Create(c.cpuProfilePath)
		if err != nil {
			return err
		}
		pprof.StartCPUProfile(f)
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
			return
		}()
	}

	// Read and log all interfaces
	links, err := link.FindAllLinks()
	if err != nil {
		return err
	}
	for _, iface := range links {
		log.Infof("Found interface `%s` (idx %d), link type %d, HWAddr `%s`, flags `%s`", iface.Name, iface.Index, iface.LinkType, iface.HardwareAddr, iface.Flags)
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
		log.Warnf("skipping capture on interfaces [%s]", strings.Join(skipped, ","))
	}

	sort.Slice(capturing, func(i, j int) bool {
		return capturing[i] < capturing[j]
	})
	log.Infof("attempting capture on interfaces [%s]", strings.Join(capturing, ","))

	sigExitChan := make(chan os.Signal, 1)
	signal.Notify(sigExitChan, syscall.SIGTERM, os.Interrupt)

	var listeners []capture.Source
	// Fork a goroutine for each interface
	wg := sync.WaitGroup{}
	for _, iface := range links {
		wg.Add(1)
		go func(l link.Link) {
			defer wg.Done()

			for _, skipLink := range skipped {
				if l.Name == skipLink {
					return
				}
			}

			if (l.Interface.Flags & syscall.IFF_UP) == 0 {
				log.Warnf("skipping listener on non-up interface `%s`", l.Name)
				return
			}

			var listener capture.Source
			if c.useRingBuffer {
				listener, err = afpacket.NewRingBufSource(l)
				if err != nil {
					log.Errorf("error starting listener (with ring buffer) on `%s`: %s", l.Name, err)
				}
			} else {
				listener, err = afpacket.NewSource(l)
				if err != nil {
					log.Errorf("error starting listener (no ring buffer) on `%s`: %s", l.Name, err)
				}
			}
			listeners = append(listeners, listener)

			var nErr int
			if c.useZeroCopy {
				for {
					if err := listener.NextIPPacketFn(func(payload []byte, pktType byte) error {
						if c.logPacketPayload {
							log.Infof("[%s] Got %v / %d", l.Name, payload[:16], pktType)
						}
						return nil
					}); err != nil {
						if errors.Is(err, capture.ErrCaptureStopped) {
							log.Infof("gracefully stopped capture on `%s`", l.Name)
							return
						}
						nErr++
						if nErr >= c.maxIfaceErrors {
							log.Errorf("too many errors (%d) on `%s`, stopping capture", nErr, l.Name)
						}
					}
				}
			} else {
				for {
					pkt, pktType, err := listener.NextIPPacket()
					if err != nil {
						if errors.Is(err, capture.ErrCaptureStopped) {
							log.Infof("gracefully stopped capture on `%s`", l.Name)
							return
						}
						nErr++
						if nErr >= c.maxIfaceErrors {
							log.Errorf("too many errors (%d) on `%s`, stopping capture", nErr, l.Name)
						}
					}

					if c.logPacketPayload {
						log.Infof("[%s] Got %v / %d", l.Name, pkt[:16], pktType)
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
				log.Errorf("failed to retrieve socket stats: %s", err)
			}
			log.Infof("Packet stats: %#v", stats)

			if err := listener.Close(); err != nil {
				log.Errorf("failed to gracefully stop capture: %s", err)
			}
		}
	}()

	wg.Wait()
	return nil
}
