// Package locales carries the built-in language packs of the
// Relavia desktop client. Packs live in locales/<lang>/messages.json
// (one JSON key/value file per language, mirroring the _locales
// layout the proposal book 8.1 prescribes) and are embedded into
// the binary; the directory layout stays the single source of
// truth so packs can also be shipped or hot-updated as plain files
// later without code changes.
//
// Pack discipline (book 3.6, multilingual-native):
//   - zh-Hans is the source language; every key is authored there
//     first, then translated. Keys are added to the source pack
//     before they are referenced from UI code.
//   - zh-Hant and en are complete translations, including every
//     risk-disclosure string (risk.*), which must never ship
//     machine-translated.
//   - Key-set equality and non-empty values across all packs are
//     enforced by tests and by tools/i18ncheck in CI.
package locales

import "embed"

// FS holds every built-in pack: <lang>/messages.json.
//
//go:embed */messages.json
var FS embed.FS

// Supported lists the built-in languages in UI preference order.
var Supported = []string{"zh-Hans", "zh-Hant", "en"}

// Source is the source language every other pack is checked
// against.
const Source = "zh-Hans"

// Fallback is the language used when a key is missing in the
// active pack (book 3.6: missing translations fall back to
// English).
const Fallback = "en"
