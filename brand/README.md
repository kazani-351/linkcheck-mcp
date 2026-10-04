# Brand assets

- `logo.svg`: app tile (favicon, MCP icon). `mark.svg`: the bare mark, used inline on the landing page.
- `logo-square.svg`: full-bleed tile used to render the PNG icons (platforms round the corners themselves).
- PNGs are rendered in Safari: open `og.html` (1200x630 preview card) and `icons.html` (180 and 256 icons), screenshot, crop to exact size.
- After changing anything here, run `python3 brand/build.py` to regenerate `src/brand-assets.ts`.

Colors match kazani.pages.dev: canvas `#0a0c0b`, card `#0f1413`, accent `#5cc8a8`.
