# CertForge design system

All values live as tokens at the top of `src/styles.css`. Components never use raw colours, radii, easing curves or durations.

## Colour meanings

| Token | Meaning | Never used for |
| --- | --- | --- |
| `--accent` (blue #1F5EFF / #5B8CFF dark) | The one action colour: primary buttons, selection, the leaf certificate, links | Status |
| `--ok` | A check passed / something matches | Decoration |
| `--warn` | Needs attention, but not blocking | Decoration |
| `--bad` | Blocking problem (wrong key, expired, broken chain) | Decoration |
| `--ink`, `--ink-2`, `--ink-3` | Primary, secondary, quiet text | — |
| `--surface`, `--surface-2`, `--surface-3` | Panels, wells, tracks | — |

There is one accent. Green, amber and red appear only when they report a check result.

## Type roles

- **UI:** the system font stack (`--font`). The file is offline, so it loads no web fonts.
- **Mono** (`--mono`): file names, fingerprints, config snippets, file extensions.
- **Sizes:** `--fs-xs` 11.5 · `--fs-sm` 12.5 · `--fs-md` 13.5 · `--fs-lg` 15 · `--fs-xl` fluid 20–24 (Inspector title) · `--fs-hero` fluid 32–46 (first-run headline).

## Shape and motion

- **Radius:** `--r-sm` 7 · `--r-md` 11 · `--r-lg` 16 (panels) · `--r-xl` 22 (drop zone) · `--r-pill`.
- **Easing:** `--ease-out` for entrances and state changes · `--ease-in-out` for the progress bar.
- **Duration:** `--dur-fast` 120 ms (hover, toggles) · `--dur-mid` 220 ms (fades) · `--dur-slow` 380 ms (drawer).
- All motion is switched off under `prefers-reduced-motion`.

## Layout

The layout has three zones, left to right:
1. **Your files** (intake, 310 px)
2. **Inspector** (fluid)
3. **Where is this going?** (output, 360 px)

Below 1,280 px the output panel drops under the other two. Below 1,000 px everything stacks into one column with a step bar.

## Rules

- No component library, no custom cursor, plain system cursor.
- Light and dark follow the system; the header button cycles auto → light → dark (not remembered — the app saves nothing).
- Every interactive element is a real button or input with a visible focus ring.
