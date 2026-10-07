// Run only as an operator bootstrap step, never on workload input.
// The emitted snapshot must be reviewed; runtime DNS changes outside it deny.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run hack/registry-policy.go registry-host")
		os.Exit(1)
	}
	host := os.Args[1]
	ips, err := net.LookupIP(host)
	if err != nil {
		panic(err)
	}
	var cidrs []string
	for _, ip := range ips {
		a, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		a = a.Unmap()
		if !a.IsGlobalUnicast() || a.IsLoopback() || a.IsLinkLocalUnicast() {
			panic("bootstrap resolved a forbidden address")
		}
		bits := 128
		if a.Is4() {
			bits = 32
		}
		cidrs = append(cidrs, netip.PrefixFrom(a, bits).String())
	}
	if len(cidrs) == 0 {
		panic("no registry addresses")
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"registries": []any{map[string]any{"host": host, "endpoints": []any{map[string]any{"host": host, "cidrs": cidrs}}}}})
}
