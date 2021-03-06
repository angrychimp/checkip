package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/jreisinger/checkip/check"
)

// Flags are all the available CLI flags (options). I use a struct instead of
// separate variables to keep all flags in one place.
type Flags struct {
	Version     bool
	ChecksToRun checksToRun
	IPaddr      net.IP
}

// ParseFlags validates the flags and parses them into Flags.
func ParseFlags() (Flags, error) {
	f := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)

	Version := f.Bool("version", false, "print version")
	var ChecksToRun checksToRun
	f.Var(&ChecksToRun, "check", "run only selected check(s): `check[,...]`")

	f.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "%s [flags] <ipaddr>\n", os.Args[0])
		f.PrintDefaults()
	}

	err := f.Parse(os.Args[1:])
	if err != nil {
		return Flags{}, err
	}

	if len(f.Args()) == 0 {
		return Flags{}, fmt.Errorf("missing IP address to check")
	}

	IPaddr := net.ParseIP(f.Args()[0])
	if IPaddr == nil {
		return Flags{}, fmt.Errorf("invalid IP address: %v", f.Args()[0])
	}

	flags := Flags{
		Version:     boolValue(Version),
		ChecksToRun: ChecksToRun,
		IPaddr:      IPaddr,
	}

	return flags, err
}

// checksToRun can be used multiple times and can take multiple values separated
// by a comma. It contains the checks to run selected via -check.
type checksToRun []check.Check

func (a *checksToRun) String() string {
	return fmt.Sprintf("%s", *a)
}

func (a *checksToRun) Set(value string) error {
	requestedCheckNames := strings.Split(value, ",")
	for _, reqChkName := range requestedCheckNames {
		chk, ok := isAvailable(reqChkName)
		if !ok {
			log.Fatalf("unknown check: %s\n", reqChkName)
		}
		*a = append(*a, chk)
	}
	return nil
}

func isAvailable(checkName string) (check.Check, bool) {
	checkName = strings.TrimSpace(checkName)
	checkName = strings.ToLower(checkName)

	for _, chk := range availableChecks {
		if strings.HasPrefix(strings.ToLower(chk.Name()), checkName) {
			return chk, true
		}
	}

	return nil, false
}

func boolValue(v *bool) bool {
	if !*v {
		return false
	}
	return *v
}
