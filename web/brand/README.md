# receive.link brand

The mark is a "landing point": concentric rings with a single node at the center. The idea is that every file someone sends you comes to rest at one safe place. Calm and reassuring, not alarmist.

## Color

| Token | Hex | Use |
|-------|-----|-----|
| Green | `#23A267` | the rings, and the period in the wordmark |
| Ink | `#0E0E16` | the wordmark, the center node on light, the app-icon tile |
| Grey (dark bg) | `#8E8CA6` | the muted `link` on dark |
| Grey (light bg) | `#9A98A8` | the muted `link` on light |
| Paper | `#F4F3F7` | light surface |

Two colors carry the brand: green and ink. Grey is only ever the muted `link`. The center node is always neutral (ink on light, white on dark) and never green, so it stays legible at any size.

## Type

The wordmark is Inter, weight 600, lowercase, letter-spacing `-1`. `receive` leads, the period is green, and `link` drops to weight 400 in grey. The app bundles Inter at `web/fonts/inter.woff2`. For fixed external placements, outline the text so it renders identically without the font installed.

## Files

- `mark.svg`: primary mark with the ripple ring, for light backgrounds.
- `mark-dark.svg`: same mark with a white center, for dark backgrounds.
- `app-icon.svg`: self-contained ink tile plus a bold mark. Use for PWA, home screen, and avatars.
- `favicon.svg`: the bold cut (no ripple), transparent, with a center that adapts to the browser light or dark theme. Wired into `web/index.html`.
- `lockup-light.svg` / `lockup-dark.svg`: the mark plus the wordmark.

## Rules

- Clear space: keep at least one node-diameter of empty space around the mark.
- Minimum size: below about 24px use the bold favicon cut, since the thin ripple ring disappears. The favicon cut holds down to 16px.
- Do not recolor the rings anything but green, do not fill the center green, do not add gradients or shadows, and do not stretch the mark.

## Still on the old branding (separate from these files)

- `web/og.png` (the social share card) and the in-app header logo still carry older FileKey-era branding. Updating those is a follow-up, not part of this asset set.
- For an Apple touch icon, export `app-icon.svg` to a 180x180 PNG, since Safari ignores SVG for `apple-touch-icon`.
