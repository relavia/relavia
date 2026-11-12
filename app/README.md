# Relavia client (app module)

The desktop client: platform-independent application service
layer + Gio shell, per proposal book 5.1. Delivered in Step 9
(Windows client MVP); Step 10 reuses `service/` unchanged for
Android.

## Layout

| Path | What |
|---|---|
| `service/` | Application service layer: node/group store, import (Step 8 parsers), handshake scheduling, connection control, auto-select with the weak-encryption ruling, log buffer. Platform-independent. |
| `i18n/` | Runtime localization engine (fallback chain, runtime switching, pack integrity checks). |
| `locales/<lang>/` | Language packs (JSON key/value). zh-Hans is the source language; zh-Hant and en are complete translations. |
| `platform/` | OS facilities behind honest capability interfaces: system proxy, TUN detection, system tray. Windows implementations are compile-verified only in Step 9 (see the Step 9 report's real-machine checklist). |
| `ui/` | Gio shell: node list/groups, connect, import, log view, settings (language + kernel capability display). No hardcoded display strings. |
| `cmd/relavia/` | Desktop entry point. |
| `tools/i18ncheck/` | The CI multilingual gate: pack key-set integrity + hardcoded-string scan of the rendering layer. |

## Build

```sh
# Linux development build (needs Gio's system headers:
# vulkan, x11, xkbcommon, wayland, egl — see CI for the apt list)
go build ./...
go test ./...
go run ./tools/i18ncheck

# Windows release build (CGO-free cross-compile, official
# kernel build tags from Step 7)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 \
  go build -tags "with_quic with_utls with_wireguard with_gvisor" \
  -o dist/relavia.exe ./cmd/relavia
```

## Known interim states (Step 9)

- The node store is plain JSON (0600, user config dir). Step 13
  replaces it with encrypted storage at `service.Store`.
- The kernel runs in manual mode (local mixed listener). The
  adapter honestly reports TUN / system-proxy / kill-switch as
  unavailable in-process; Steps 11–12 land the platform network
  layer. The UI displays this instead of offering dead switches.
