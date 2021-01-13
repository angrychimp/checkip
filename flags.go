package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
)

func handleFlags() (net.IP, bool) {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s [flags] <ipaddr>\n", os.Args[0])
		flag.PrintDefaults()
	}

	version := flag.Bool("version", false, "version")
	verbose := flag.Bool("v", false, "verbose")

	flag.Parse()

	if *version {
		fmt.Println(Version)
		os.Exit(0)
	}

	if len(flag.Args()) != 1 {
		log.Fatalf("missing IP address to check")
	}

	ipaddr := net.ParseIP(flag.Args()[0])
	if ipaddr == nil {
		log.Fatalf("invalid IP address: %v\n", os.Args[1])
	}

	return ipaddr, *verbose
}
