// Command nftdump prints the kill-switch descriptors compiled
// from command-line flags. It exists for scripts and tests
// (scripts/killswitch-check.sh consumes its output) and for
// reviewing generated rules without a running client.
//
// Usage:
//
//	go run ./killswitch/nftdump -mode when-connected \
//	    -endpoint 203.0.113.7:443 -lan=false -platform nft
//
// -platform: nft (default) | iptables | windows | android.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"

	"openproxy/core/killswitch"
)

type endpointsFlag []killswitch.Endpoint

func (f *endpointsFlag) String() string { return fmt.Sprint(*f) }

func (f *endpointsFlag) Set(v string) error {
	// SplitHostPort handles both 203.0.113.7:443 and
	// [2001:db8::7]:8443.
	addr, portStr, err := net.SplitHostPort(v)
	if err != nil {
		return fmt.Errorf("endpoint %q: want addr:port (bracket IPv6 literals): %w", v, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("endpoint %q: bad port: %w", v, err)
	}
	*f = append(*f, killswitch.Endpoint{Address: addr, Port: port})
	return nil
}

func main() {
	mode := flag.String("mode", string(killswitch.ModeWhenConnected), "off | when-connected | always-on")
	lan := flag.Bool("lan", false, "allow LAN egress")
	tunif := flag.String("tun-if", "", "tunnel interface name (default "+killswitch.DefaultTunnelInterface+")")
	platform := flag.String("platform", "nft", "nft | iptables | windows | android")
	var eps endpointsFlag
	flag.Var(&eps, "endpoint", "tunnel endpoint exception addr:port (repeatable)")
	flag.Parse()

	d, err := killswitch.Compile(killswitch.Config{
		Mode:            killswitch.Mode(*mode),
		Endpoints:       eps,
		AllowLAN:        *lan,
		TunnelInterface: *tunif,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "nftdump:", err)
		os.Exit(1)
	}
	switch *platform {
	case "nft":
		fmt.Print(d.LinuxNFT)
	case "iptables":
		for _, c := range d.LinuxIPTables {
			fmt.Println(c)
		}
	case "windows":
		enc, _ := json.MarshalIndent(d.Windows, "", "  ")
		fmt.Println(string(enc))
	case "android":
		enc, _ := json.MarshalIndent(d.Android, "", "  ")
		fmt.Println(string(enc))
	default:
		fmt.Fprintln(os.Stderr, "nftdump: unknown -platform", *platform)
		os.Exit(1)
	}
}
