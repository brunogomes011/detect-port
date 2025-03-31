package detect

import (
	"fmt"
	"net"
	"time"
)

type PortState struct {
	Port     int
	Open     state
	Protocol string
}

type state bool

// String converts the boolean value of state to a human readable string
func (s state) String() string {
	if s {
		return "open"
	}
	return "closed"
}

// detectPort performs a port scan on a single TCP port
func detectPort(host string, port int, proto string) PortState {
	p := PortState{
		Port:     port,
		Protocol: proto,
	}
	address := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	fmt.Println(address)
	detectConn, err := net.DialTimeout(proto, address, 1*time.Second)
	if err != nil {
		return p
	}
	detectConn.Close()
	p.Open = true
	return p
}

// Results represents the scan results for a single host
type Results struct {
	Host       string
	NotFound   bool
	PortStates []PortState
}

// Run performs a port scan on the hosts list
func Run(hl *HostsList, ports []int, proto string) []Results {
	res := make([]Results, 0, len(hl.Hosts))
	for _, h := range hl.Hosts {
		r := Results{
			Host: h,
		}

		if _, err := net.LookupHost(h); err != nil {
			r.NotFound = true
			res = append(res, r)
			continue
		}
		for _, p := range ports {
			r.PortStates = append(r.PortStates, detectPort(h, p, proto))
		}
		res = append(res, r)
	}
	return res
}
