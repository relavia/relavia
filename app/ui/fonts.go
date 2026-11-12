package ui

import (
	"os"
	"path/filepath"
	"runtime"

	"gioui.org/font"
	"gioui.org/font/gofont"
	"gioui.org/font/opentype"
)

// Font strategy: Gio ships no system-font discovery, and the Go
// fonts have no CJK glyphs — a Chinese UI rendered with them
// alone would show tofu boxes. The client therefore loads a
// platform CJK font at startup when one is present (Windows
// YaHei / JhengHei ship with the OS; Noto Sans CJK on Linux;
// PingFang on macOS) and falls back to the Go fonts otherwise.
//
// STATUS: the loading paths are the standard OS font locations,
// but glyph rendering on a real Windows machine is part of the
// Step 9 real-machine checklist (the sandbox has no display).
// If no CJK font is found, Latin text still renders correctly
// and the log records the miss (see cmd/relavia).
func FontCollection() []font.FontFace {
	faces := gofont.Collection()
	for _, path := range cjkFontCandidates() {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if parsed, err := opentype.ParseCollection(data); err == nil && len(parsed) > 0 {
			faces = append(faces, parsed...)
			continue
		}
		if face, err := opentype.Parse(data); err == nil {
			faces = append(faces, font.FontFace{Font: face.Font(), Face: face})
		}
	}
	return faces
}

// FoundCJK reports whether at least one CJK-capable font file was
// found on this machine (used for a startup log line).
func FoundCJK() bool {
	for _, path := range cjkFontCandidates() {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}

func cjkFontCandidates() []string {
	switch runtime.GOOS {
	case "windows":
		root := os.Getenv("WINDIR")
		if root == "" {
			root = `C:\Windows`
		}
		fonts := filepath.Join(root, "Fonts")
		return []string{
			filepath.Join(fonts, "msyh.ttc"), // Microsoft YaHei (Simplified)
			filepath.Join(fonts, "msjh.ttc"), // Microsoft JhengHei (Traditional)
			filepath.Join(fonts, "msgothic.ttc"),
			filepath.Join(fonts, "malgun.ttf"),
		}
	case "darwin":
		return []string{
			"/System/Library/Fonts/PingFang.ttc",
			"/System/Library/Fonts/STHeiti Medium.ttc",
			"/Library/Fonts/Arial Unicode.ttf",
		}
	default: // linux and others
		return []string{
			"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
			"/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc",
			"/usr/share/fonts/noto-cjk/NotoSansCJK-Regular.ttc",
			"/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
			"/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
		}
	}
}
