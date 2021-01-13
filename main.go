package main

import (
	"fmt"
	"log"

	"github.com/jreisinger/checkip/check"
)

// Version is the default version of checkip.
var Version = "dev"

func main() {
	log.SetFlags(0) // no timestamp in error messages
	ipaddr, verbose := handleFlags()

	ch := make(chan string)
	checks := []check.Check{
		&check.AS{},
		&check.DNS{},
		&check.ThreatCrowd{},
		&check.AbuseIPDB{},
		&check.Geo{},
		&check.VirusTotal{},
	}
	for _, chk := range checks {
		go check.Run(chk, ipaddr, ch, verbose)
	}
	for range checks {
		fmt.Print(<-ch)
	}
}
