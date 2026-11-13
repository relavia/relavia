# Language pack template — NOT a language

This directory is scaffolding for community translators. It is
deliberately **not** listed in `locales.Supported` and **not**
embedded into the binary, so it can never be loaded by the app.

`messages.json` here contains every key of the English pack,
each value prefixed with `[UNTRANSLATED]`. To start a new
language:

1. Create `locales/<lang>/messages.json` (BCP 47 tag, e.g.
   `ja`, `pt-BR`) as a copy of this file.
2. Replace each value with your translation and remove the
   `[UNTRANSLATED]` prefix. Set `lang.name` to the language's
   own name in its own script.
3. Validate (from the `app/` directory):

   ```
   go run ./tools/i18ncheck -extra <lang> -strict-extra
   ```

   The pack is done when the report shows `missing=0 extra=0
   empty=0 untranslated=0 completeness=100.0%` and the run
   passes.

Full rules — translation discipline, the mandatory glossary,
native-speaker review, and the promotion process — live in
[../README.md](../README.md).
