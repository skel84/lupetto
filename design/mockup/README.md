# Lupetto dashboard mockup

A clickable static mockup of the redesigned `lupetto-explorer` dashboard, for review before the real UI is rebuilt
(see [the redesign decision](../../docs/decisions.md#dashboard-redesign-and-local-inventory-user-approved-2026-10-01)).
It is **not** the product UI and all data is **sample data**: package names, versions, and advisory IDs come from
the real signed Wolfi index and security feed (2026-10-01); severities, digests, dates, and build history are invented.

## How to view

```sh
python3 -m http.server -d design/mockup 8099
```

Open <http://localhost:8099/>. The striped bar at the top switches the visual direction (`?theme=a|b`) and color
mode (`?mode=auto|light|dark`); the choice is remembered while you click around. **All screens ▾** lists every screen
and state. No build step, no external requests; every page carries `Content-Security-Policy: default-src 'self'`.

## Visual directions

**A · Tana** (“the den”). Calm and editorial: warm paper and terracotta, serif headings, roomy cards, a top bar.
Each product is a card you can read like a short status report; verdicts are soft pills and severity uses distinct
shapes (octagon, triangle, diamond, circle, “?”). It favours explanation over density, for occasional operators who
want to know “what should I do?” at a glance.

**B · Pista** (“the trail”). An instrument panel: cool graphite with a teal signal colour, monospace for versions and
digests, a left rail, one dense ledger of products, square corners and hairlines. Severity is a 4-segment meter plus
text. It favours scanning many images quickly, for operators who live in terminals.

Both share markup and only differ in CSS, have light and dark palettes (`light-dark()`), carry text labels next to
every colour cue, and show a visible focus ring.

## Implementation notes for the real UI

- Tabs, filters, version pickers, and compare are links or GET forms; the mockup's JavaScript only emulates
  server-side filtering, opens the “Track a product” form as a `<dialog>` (the link still works without JS), and
  remembers the mockup's direction/mode. Raw logs and the data note are `<details>`.
- Build/track buttons are links here; in the product they are POST forms with the CSRF token.
- `_src/generate.py` regenerates the HTML from the sample data (`python3 design/mockup/_src/generate.py`, Python 3.12+); it is not
  needed to view the mockup.
- Only the postgresql family page exists in the catalog; other catalog links point to it.
