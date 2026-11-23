// Command xcheck is the independent second source for the
// BLAKE3-based vectors (KDF-05 family): it recomputes the
// Shadowsocks 2022 session subkeys in ../vectors.json with
// lukechampine.com/blake3 - a different BLAKE3 implementation
// than the zeebo/blake3 the generator uses - and fails if any
// expectation disagrees. Two implementations agreeing is the
// dual-source evidence for these vectors (checklist rule F.1).
//
// Run from this directory:
//
//	go run . [../vectors.json]
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"lukechampine.com/blake3"
)

type vector struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Inputs   map[string]any `json:"inputs"`
	Expected map[string]any `json:"expected"`
}

type vectorFile struct {
	Vectors []vector `json:"vectors"`
}

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	path := "../vectors.json"
	if len(os.Args) > 1 {
		path = os.Args[1]
	}
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		panic(err)
	}
	checked := 0
	for _, v := range vf.Vectors {
		if v.Category != "kdf" {
			continue
		}
		pskHex, ok := v.Inputs["psk"].(string)
		if !ok {
			continue // not a BLAKE3 vector
		}
		if _, ok := v.Expected["subkey"]; !ok {
			continue // e.g. KDF-06 separate-header vectors: no subkey
		}
		if _, ok := v.Inputs["salt"]; !ok {
			continue
		}
		salt := unhex(v.Inputs["salt"].(string))
		keyLen := int(v.Inputs["keyLen"].(float64))
		material := append(unhex(pskHex), salt...)
		out := make([]byte, keyLen)
		blake3.DeriveKey(out, "shadowsocks 2022 session subkey", material)
		got := hex.EncodeToString(out)
		want := v.Expected["subkey"].(string)
		if got != want {
			fmt.Printf("MISMATCH %s: lukechampine=%s vectors.json=%s\n", v.ID, got, want)
			os.Exit(1)
		}
		fmt.Printf("OK %s (lukechampine/blake3 agrees)\n", v.ID)
		checked++
	}
	if checked == 0 {
		fmt.Println("no BLAKE3 KDF vectors found - nothing checked")
		os.Exit(1)
	}
	fmt.Printf("xcheck: %d BLAKE3 vectors verified\n", checked)
}
