// Package check allows you to run various IP address checks.
package check

import (
	"fmt"
	"net"

	. "github.com/logrusorgru/aurora"
)

// Check represents an IP address checker.
type Check interface {
	Do(addr net.IP) (bool, error)
	Name() string
	Result(verbose bool) string
}

// Run runs a check of an IP address and returns the result over a channel.
func Run(chk Check, ipaddr net.IP, ch chan string, verbose bool) {
	format := "%-16s%s\n"
	ok, err := chk.Do(ipaddr)
	if err != nil {
		ch <- fmt.Sprintf(format, Gray(11, chk.Name()), err)
		return
	}
	if ok {
		ch <- fmt.Sprintf(format, chk.Name(), chk.Result(verbose))
	} else {
		ch <- fmt.Sprintf(format, Magenta(chk.Name()), chk.Result(verbose))
	}
}
