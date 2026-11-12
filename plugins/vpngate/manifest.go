// Package vpngate is the VPN Gate source plugin: the project's
// only official public source in phase 1 (proposal book 7.3).
//
// The plugin fetches the official VPN Gate server-list CSV
// (published by the University of Tsukuba explicitly for
// third-party client integration), maps it onto the unified node
// model by reusing the Step 8 format parser, groups nodes by
// country/region, and gates activation behind the mandatory
// risk-disclosure consent of book 7.3.
//
// Plugin discipline (book 7.2): the plugin only fetches, parses
// and probes. It executes no arbitrary code, uploads no user
// data and contains no telemetry. Disabling the plugin revokes
// the risk consent and purges the fetch cache.
package vpngate

import (
	_ "embed"
	"encoding/json"
	"fmt"
)

//go:embed manifest.json
var manifestBytes []byte

// Manifest is the plugin's source registration as data
// (book 7.2: name, operator, authorization basis, terms URL,
// data format, update frequency, permission declaration).
type Manifest struct {
	ID                    string   `json:"id"`
	Name                  string   `json:"name"`
	Operator              string   `json:"operator"`
	Version               string   `json:"version"`
	DataFormat            string   `json:"dataFormat"`
	UpdateIntervalMinutes int      `json:"updateIntervalMinutes"`
	Homepage              string   `json:"homepage"`
	Endpoints             []string `json:"endpoints"`
	Authorization         struct {
		Status   string `json:"status"`
		Basis    string `json:"basis"`
		TermsURL string `json:"termsUrl"`
	} `json:"authorization"`
	Permissions struct {
		NetworkHosts          []string `json:"networkHosts"`
		ExecutesArbitraryCode bool     `json:"executesArbitraryCode"`
		UploadsUserData       bool     `json:"uploadsUserData"`
		Telemetry             bool     `json:"telemetry"`
	} `json:"permissions"`
	RiskText struct {
		Version       string `json:"version"`
		I18nKeyPrefix string `json:"i18nKeyPrefix"`
	} `json:"riskText"`
}

// LoadManifest parses and validates the embedded manifest.
// A manifest that violates the book 7.1/7.2 registration rules
// (an official plugin must be grade A) is rejected outright.
func LoadManifest() (*Manifest, error) {
	var m Manifest
	if err := json.Unmarshal(manifestBytes, &m); err != nil {
		return nil, fmt.Errorf("vpngate: manifest parse: %w", err)
	}
	if m.ID != "vpngate" || m.Name == "" || m.Operator == "" {
		return nil, fmt.Errorf("vpngate: manifest missing id/name/operator")
	}
	if m.Authorization.Status != "A" {
		return nil, fmt.Errorf("vpngate: manifest authorization.status must be A for an official plugin, got %q", m.Authorization.Status)
	}
	if m.Authorization.Basis == "" || m.Authorization.TermsURL == "" {
		return nil, fmt.Errorf("vpngate: manifest authorization basis/termsUrl required (book 7.2)")
	}
	if m.DataFormat != "csv" || len(m.Endpoints) == 0 {
		return nil, fmt.Errorf("vpngate: manifest dataFormat/endpoints invalid")
	}
	if m.Permissions.ExecutesArbitraryCode || m.Permissions.UploadsUserData || m.Permissions.Telemetry {
		return nil, fmt.Errorf("vpngate: manifest permission declaration violates book 7.2 (fetch/parse/probe only)")
	}
	if m.RiskText.Version == "" || m.RiskText.I18nKeyPrefix == "" {
		return nil, fmt.Errorf("vpngate: manifest riskText declaration required")
	}
	return &m, nil
}
