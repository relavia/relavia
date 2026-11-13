# Language packs — contributor guide

Relavia is multilingual from the first line of code (proposal
book §3.6, locked 2026-11-12). All user-visible text lives in
these packs; the UI contains no hardcoded strings (enforced by
`tools/i18ncheck` in CI).

**Shipped languages (100% complete, selectable in the app):**
简体中文 `zh-Hans` (source language), 繁體中文 `zh-Hant`,
English `en`.

**Community languages:** anyone may contribute a new pack or
improve an in-progress one by following this guide. Candidate
batch from the book (§8.1): ja, ko, es, ru, pt, fr, de, ar,
fa, tr, vi, id — other languages are equally welcome.

简要说明（中文）：新增语言请复制 `_template/messages.json`
到 `locales/<语言代码>/messages.json`，逐条翻译并去掉
`[UNTRANSLATED]` 标记，用下方命令校验到 100% 后提 PR；
风险类文案（`risk.*`、`security.*`、`update.err_*`）必须
人工翻译、禁止机翻上岗，且须经母语者复核。术语以术语表
为准。

## Starting a new language

1. Copy `_template/messages.json` to
   `locales/<lang>/messages.json`, where `<lang>` is the
   BCP 47 tag (`ja`, `ko`, `pt-BR`, …). The template holds
   every key with the English text prefixed by
   `[UNTRANSLATED]`.
2. Translate value by value. Remove the `[UNTRANSLATED]`
   prefix only from strings you have actually translated.
   Set `lang.name` to the language's own name in its own
   script (e.g. `日本語`).
3. Keep every `{placeholder}` exactly as in the source
   (`{node}`, `{ok}`, `{ms}`, …) — the app substitutes them
   at runtime; a renamed or dropped placeholder is a bug.
4. Validate from the `app/` directory:

   ```
   go run ./tools/i18ncheck -extra <lang> -strict-extra
   ```

   Done means: `missing=0 extra=0 empty=0 untranslated=0
   completeness=100.0%` and exit code 0.

## Translation discipline

- **Translate from the English pack**, and consult the
  zh-Hans source pack when a phrase is ambiguous. Never edit
  zh-Hans/en/zh-Hant in a language PR.
- **Risk strings are safety text, not prose.** The groups
  `risk.*`, `security.*` and `update.err_*` (plus
  `android.vpn_permission_*`) must be translated by a human
  who understands them — machine translation output may be
  used as a private drafting aid but must never be committed
  unreviewed, and these groups additionally require the
  native-speaker review below before merge.
- **Follow the glossary.** Core terms have one approved
  rendering per language; do not improvise synonyms. If the
  glossary lacks your language's rendering, propose it in
  the PR — the merged PR becomes the glossary entry.
- Match the register of the shipped packs: concise,
  factual, no marketing language, no exclamation marks.
- Numbers, units (`ms`, `TUN`, protocol names, file
  extensions) and brand names (`Relavia`, `VPN Gate`,
  `WireGuard`) are never translated.

## Glossary (core terms)

Source (zh-Hans) → zh-Hant → English. New languages add
their column via PR review.

| zh-Hans | zh-Hant | English | Notes |
|---|---|---|---|
| 节点 | 節點 | node | a proxy server entry |
| 分组 | 分組 | group | |
| 订阅 | 訂閱 | subscription | |
| 导入 | 匯入 | import | |
| 连接 | 連線 | connect / connection | zh-Hant uses 連線 |
| 断开 | 中斷連線 | disconnect | |
| 测活 | 測活 | test (connectivity test) | real-handshake liveness check |
| 弱加密 | 弱加密 | weak encryption | legacy non-AEAD ciphers |
| 断网保护 | 斷網保護 | kill switch | |
| 系统代理 | 系統代理 | system proxy | |
| 分流（路由） | 分流（路由） | routing / split routing | reserved; no UI strings yet |
| 口令 | 密碼 | passphrase | regional convention differs per pack — keep each pack's own |
| 内核 | 核心 | kernel | zh-Hant uses 核心 |
| 日志 | 日誌 | log | |
| 凭据 | 憑證 | credentials | |
| 校验 | 校驗 | verification | signature/hash checks |
| 流量 | 流量 | traffic | |
| 更新渠道 | 更新渠道 | update channel | stable / beta |

## Review and promotion

1. Open a PR containing only the new/changed pack under
   `locales/<lang>/`. Do **not** add the language to
   `locales.Supported` yourself.
2. CI must pass, and the `-strict-extra` check above must
   report 100.0%.
3. A native speaker who did not write the translation
   reviews it — for risk strings this is mandatory, for the
   rest of the pack a reviewer confirms overall quality.
   Review happens in the PR thread; the reviewer is recorded
   there.
4. On merge, a maintainer promotes the pack: adds `<lang>`
   to `locales.Supported` and to the embed list in
   `locales.go`. Only then does the language become
   selectable in the app (**maturity rule: below 100% a pack
   is never loadable** — partial packs stay in PRs, where
   the checker reports their honest completeness).

## Right-to-left languages

The runtime already reports each language's direction
(`i18n.DirectionOf`; ar/fa/he/ur resolve to RTL) and views
never hardcode layout direction. An RTL pack can therefore
be translated with the process above; the remaining
layout-flip verification on a real device is tracked in
docs/step18-本地化与无障碍基线.md and is a maintainer task
at promotion time, not a translator blocker.
