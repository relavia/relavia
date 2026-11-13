//go:build tools

// Package tools pins build-time-only module requirements so that
// `go mod tidy` does not prune them.
//
// gomobile's gobind generates code that imports
// github.com/sagernet/gomobile/bind inside this module's context
// during the Android AAR build (scripts/build-android.sh bind).
// Nothing in the app imports that package, so without this anchor
// tidy drops the gomobile requirement and gobind fails with
// "no Go package in github.com/sagernet/gomobile/bind" — this
// regressed once already (fixed by a bare `go get` in be4bd62,
// pruned again by the next tidy in fbf2730). Keep this file.
package tools

import (
	_ "github.com/sagernet/gomobile/bind"
)
