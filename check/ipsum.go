package check

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/jreisinger/checkip/util"
)

// IPsum counts on how many blacklists the IP address was found according to
// https://github.com/stamparm/ipsum.
type IPsum struct {
	NumOfBlackists int
}

// Do fills in the date into IPsum. If the IP address is found on at least 3
// blacklists it returns false.
func (ip *IPsum) Do(ipaddr net.IP) (bool, error) {
	file := "/var/tmp/ipsum.txt"
	url := "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

	if err := util.Update(file, url, ""); err != nil {
		return false, fmt.Errorf("can't update %s from %s: %v", file, url, err)
	}

	if err := ip.search(ipaddr, file); err != nil {
		return false, fmt.Errorf("searching %s in %s: %v", ipaddr, file, err)
	}

	if ip.NumOfBlackists > 2 {
		return false, nil
	}

	return true, nil
}

// search searches the ippadrr in tsvFile and if found fills in IPsum data.
func (ip *IPsum) search(ipaddr net.IP, tsvFile string) error {
	tsv, err := os.Open(tsvFile)
	if err != nil {
		return err
	}

	s := bufio.NewScanner(tsv)
	for s.Scan() {
		line := s.Text()
		if strings.HasPrefix(line, "#") { // skip comments
			continue
		}
		fields := strings.Fields(line)
		if ipaddr.Equal(net.ParseIP(fields[0])) { // IP address found
			ip.NumOfBlackists, err = strconv.Atoi(fields[1])
			if err != nil {
				return err
			}
			break
		}
	}
	if s.Err() != nil {
		return err
	}

	return nil
}

// Name returns the name of the check.
func (ip *IPsum) Name() string {
	return fmt.Sprint("IPsum")
}

// String returns the result of the check.
func (ip *IPsum) String() string {
	format := "found on %d blacklist"
	if ip.NumOfBlackists != 1 {
		format += "s"
	}
	return fmt.Sprintf(format, ip.NumOfBlackists)
}
