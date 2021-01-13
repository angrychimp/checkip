package check

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"text/template"

	"github.com/jreisinger/checkip/util"
)

// AS holds information about an Autonomous System.
type AS struct {
	Source      string
	FirstIP     net.IP
	LastIP      net.IP
	CountryCode string
	Number      int
	Description string
}

// Do fills in AS data for a given IP address. The data is taken from a TSV
// file ip2asn-combined downloaded from iptoasn.com.
func (a *AS) Do(ipaddr net.IP) (bool, error) {
	file := "/var/tmp/ip2asn-combined.tsv"
	a.Source = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

	if err := util.Update(file, a.Source, "gz"); err != nil {
		return false, fmt.Errorf("can't update %s from %s: %v", file, a.Source, err)
	}

	if err := a.search(ipaddr, file); err != nil {
		return false, fmt.Errorf("searching %s in %s: %v", ipaddr, file, err)
	}

	return true, nil
}

// Name returns the name of the check.
func (a *AS) Name() string {
	return fmt.Sprint("AS")
}

// Result returns the result of the check.
func (a *AS) Result(verbose bool) string {
	funcMap := template.FuncMap{}
	const tmpl = `
		Country:  {{.CountryCode}}
		ASN:      {{.Number}}
		first IP: {{.FirstIP}}
		last IP:  {{.LastIP}}
		source:   {{.Source}}`
	result := fmt.Sprintf("%s", a.Description)
	if verbose {
		result += util.TemplateToString(tmpl, funcMap, a)
	}
	return result
}

// search searches the ippadrr in tsvFile and if found fills in AS data.
func (a *AS) search(ipaddr net.IP, tsvFile string) error {
	tsv, err := os.Open(tsvFile)
	if err != nil {
		return err
	}

	s := bufio.NewScanner(tsv)
	for s.Scan() {
		line := s.Text()
		fields := strings.Split(line, "\t")
		a.FirstIP = net.ParseIP(fields[0])
		a.LastIP = net.ParseIP(fields[1])
		if isBetween(ipaddr, a.FirstIP, a.LastIP) {
			a.Number, err = strconv.Atoi(fields[2])
			if err != nil {
				return fmt.Errorf("converting string to int: %v", err)
			}
			a.CountryCode = fields[3]
			a.Description = fields[4]
			return nil
		}
	}
	if s.Err() != nil {
		return err
	}

	return nil
}

func isBetween(ipAddr, firstIPAddr, lastIPAddr net.IP) bool {
	if bytes.Compare(ipAddr, firstIPAddr) >= 0 && bytes.Compare(ipAddr, lastIPAddr) <= 0 {
		return true
	}
	return false
}
