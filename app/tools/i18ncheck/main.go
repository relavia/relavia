// Command i18ncheck is the automated multilingual gate of
// proposal book Step 9 (it runs in CI on every push):
//
//  1. Pack integrity: every shipped pack's key set must equal
//     the source pack's (zh-Hans), with no empty values
//     (i18n.CheckPacks).
//  2. Hardcoded-string scan: the rendering layer (app/ui and
//     app/cmd) must not contain user-visible string literals.
//     A literal is FLAGGED when it contains CJK characters or a
//     run of 3+ Latin letters (a "word"), UNLESS it is
//     - a known language-pack key (a reference, not text),
//     - path-like (contains '/' or '\\': imports, file paths,
//     URLs — never display text in this codebase),
//     - listed in whitelist.txt with a written justification.
//     Struct tags, import paths, and the placeholder-name keys of
//     T(key, args) calls are ignored (names of {placeholder} slots,
//     not text). Test files are ignored (they may contain sample
//     display strings).
//     Scope note: the platform package is not scanned — its
//     user-visible surface is labels passed in from the rendering
//     layer, and its Detail() strings are diagnostics that only
//     ever reach the log view; user-facing capability state is
//     rendered from cap.* keys driven by Available() booleans.
//
// Community packs (Step 18): -extra lang,lang additionally
// checks in-progress packs found under -locales against the
// source pack and reports their completeness percent; an extra
// pack fails the run only with -strict-extra (CI gates shipped
// packs unconditionally; a community pack must reach 100% —
// no missing, empty or [UNTRANSLATED] values — before it is
// promoted into locales.Supported).
//
// Usage: i18ncheck [-locales dir] [-scan dir,dir] [-whitelist file]
//
//	[-extra lang,lang] [-strict-extra]
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"openproxy/app/i18n"
	"openproxy/app/locales"
)

func main() {
	localesDir := flag.String("locales", "locales", "language pack directory")
	scanDirs := flag.String("scan", "ui,cmd", "comma-separated directories to scan for hardcoded strings")
	whitelistPath := flag.String("whitelist", "tools/i18ncheck/whitelist.txt", "hardcoded-scan whitelist file")
	extraLangs := flag.String("extra", "", "comma-separated in-progress community packs to also check against the source pack")
	strictExtra := flag.Bool("strict-extra", false, "fail the run when an -extra pack is incomplete")
	flag.Parse()

	failed := false

	// --- 1. pack integrity -------------------------------------
	reports, err := i18n.CheckPacks(os.DirFS(*localesDir), locales.Supported, locales.Source)
	if err != nil {
		fmt.Println("i18ncheck: pack check error:", err)
		os.Exit(1)
	}
	sourceKeys := map[string]bool{}
	if src, err := i18n.LoadPack(os.DirFS(*localesDir), locales.Source); err == nil {
		for k := range src.Messages {
			sourceKeys[k] = true
		}
	}
	printReport := func(rep i18n.PackReport) {
		fmt.Printf("pack %-8s keys=%d missing=%d extra=%d empty=%d untranslated=%d completeness=%.1f%%\n",
			rep.Lang, rep.Keys, len(rep.MissingKeys), len(rep.ExtraKeys), len(rep.EmptyKeys),
			len(rep.UntranslatedKey), rep.Completeness(len(sourceKeys)))
		for _, k := range rep.MissingKeys {
			fmt.Printf("  MISSING      %s: %s\n", rep.Lang, k)
		}
		for _, k := range rep.ExtraKeys {
			fmt.Printf("  EXTRA        %s: %s\n", rep.Lang, k)
		}
		for _, k := range rep.EmptyKeys {
			fmt.Printf("  EMPTY        %s: %s\n", rep.Lang, k)
		}
		for _, k := range rep.UntranslatedKey {
			fmt.Printf("  UNTRANSLATED %s: %s\n", rep.Lang, k)
		}
	}
	for _, rep := range reports {
		printReport(rep)
		if !rep.OK() {
			failed = true
		}
	}
	if *extraLangs != "" {
		var extras []string
		for _, l := range strings.Split(*extraLangs, ",") {
			if l = strings.TrimSpace(l); l != "" {
				extras = append(extras, l)
			}
		}
		extraReports, err := i18n.CheckPacks(os.DirFS(*localesDir), extras, locales.Source)
		if err != nil {
			fmt.Println("i18ncheck: extra pack check error:", err)
			os.Exit(1)
		}
		for _, rep := range extraReports {
			printReport(rep)
			if !rep.OK() && *strictExtra {
				failed = true
			}
		}
		reports = append(reports, extraReports...)
	}

	// --- 2. hardcoded scan --------------------------------------
	whitelist, err := loadWhitelist(*whitelistPath)
	if err != nil {
		fmt.Println("i18ncheck: whitelist error:", err)
		os.Exit(1)
	}
	var violations []string
	for _, dir := range strings.Split(*scanDirs, ",") {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			vs, err := scanFile(path, sourceKeys, whitelist)
			if err != nil {
				return err
			}
			violations = append(violations, vs...)
			return nil
		})
		if err != nil {
			fmt.Println("i18ncheck: scan error:", err)
			os.Exit(1)
		}
	}
	sort.Strings(violations)
	for _, v := range violations {
		fmt.Println("HARDCODED", v)
	}
	if len(violations) > 0 {
		failed = true
	}

	fmt.Printf("i18ncheck: packs=%d scan_violations=%d\n", len(reports), len(violations))
	if failed {
		os.Exit(1)
	}
	fmt.Println("i18ncheck: OK")
}

// loadWhitelist reads exact literal contents, one per line.
// Lines starting with '#' are justification comments and are
// REQUIRED above every entry (enforced loosely: an entry with no
// preceding comment is itself an error).
func loadWhitelist(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	out := map[string]bool{}
	sawComment := false
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			sawComment = true
			continue
		}
		if !sawComment {
			return nil, fmt.Errorf("%s:%d: whitelist entry without a justification comment", path, i+1)
		}
		out[line] = true
		sawComment = false
	}
	return out, nil
}

func scanFile(path string, packKeys, whitelist map[string]bool) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	// Collect literals that are never display text:
	//   - struct tags;
	//   - import paths (incl. single-segment ones like "fmt");
	//   - placeholder-name keys inside T(key, map[string]string{...})
	//     calls — they name the {placeholder} slots of pack strings.
	tags := map[*ast.BasicLit]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.Field:
			if node.Tag != nil {
				tags[node.Tag] = true
			}
		case *ast.ImportSpec:
			if node.Path != nil {
				tags[node.Path] = true
			}
		case *ast.CallExpr:
			if sel, ok := node.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "T" && len(node.Args) >= 2 {
				ast.Inspect(node.Args[1], func(inner ast.Node) bool {
					if lit, ok := inner.(*ast.BasicLit); ok {
						tags[lit] = true
					}
					return true
				})
			}
		}
		return true
	})
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING || tags[lit] {
			return true
		}
		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		if !isFlagged(s, packKeys, whitelist) {
			return true
		}
		pos := fset.Position(lit.Pos())
		out = append(out, fmt.Sprintf("%s:%d: %q", path, pos.Line, s))
		return true
	})
	return out, nil
}

func isFlagged(s string, packKeys, whitelist map[string]bool) bool {
	if s == "" || whitelist[s] || packKeys[s] {
		return false
	}
	if strings.ContainsAny(s, "/\\") {
		return false // path-like: import, file path, URL
	}
	wordRun := 0
	for _, r := range s {
		switch {
		case unicode.Is(unicode.Han, r), unicode.Is(unicode.Hiragana, r),
			unicode.Is(unicode.Katakana, r), unicode.Is(unicode.Hangul, r):
			return true
		case r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
			wordRun++
			if wordRun >= 3 {
				return true
			}
		default:
			wordRun = 0
		}
	}
	return false
}
