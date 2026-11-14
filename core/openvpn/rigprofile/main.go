// Command rigprofile renders the OpenVPN 3 session profile
// for the OpenVPN 3 loopback handshake rig
// (android/openvpn3/rig) through the exact production intake
// path a VPN Gate pool node takes on a device:
//
//	VPN Gate CSV -> core/parsers.ParseVPNGateCSV
//	-> node document (JSON) -> core/specnode.Parse
//	-> core/openvpn.RenderProfile
//
// It exists so the rig's client profile is produced by the
// production code end to end — never by a test-side copy of
// the rendering logic — while the rig itself (a JVM process)
// cannot call Go. Input is a VPN Gate CSV file (the rig
// synthesises a one-row CSV whose embedded config is a
// SoftEther-export-shaped profile repointed at loopback);
// output is the rendered profile text, byte for byte what
// the Android bridge hands to the OpenVPN 3 core.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"openproxy/core/openvpn"
	"openproxy/core/parsers"
	"openproxy/core/specnode"
)

func main() {
	csvPath := flag.String("csv", "", "path to a VPN Gate CSV file")
	outPath := flag.String("out", "", "where to write the rendered profile")
	flag.Parse()
	if *csvPath == "" || *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: rigprofile -csv <vpngate.csv> -out <profile.ovpn>")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*csvPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rigprofile: read csv:", err)
		os.Exit(1)
	}
	res := parsers.ParseVPNGateCSV(string(raw), parsers.Options{})
	var doc []byte
	for _, it := range res.Items {
		if it.Err == nil && it.Node != nil {
			doc, err = json.Marshal(it.Node)
			if err != nil {
				fmt.Fprintln(os.Stderr, "rigprofile: marshal node document:", err)
				os.Exit(1)
			}
			break
		}
	}
	if doc == nil {
		fmt.Fprintln(os.Stderr, "rigprofile: CSV produced no usable node")
		os.Exit(1)
	}
	node, err := specnode.Parse(doc)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rigprofile: specnode.Parse:", err)
		os.Exit(1)
	}
	rp, err := openvpn.RenderProfile(node)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rigprofile: RenderProfile:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*outPath, []byte(rp.Text), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "rigprofile: write profile:", err)
		os.Exit(1)
	}
	fmt.Printf("rigprofile: node=%s server=%s:%d proto=%s rewritten=%v\n",
		node.Name, node.Server, node.Port, rp.Proto, rp.Rewritten)
}
