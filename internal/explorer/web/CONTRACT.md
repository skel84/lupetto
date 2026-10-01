# Explorer UI contract

This is the contract between the Explorer Go server (`internal/explorer`) and the dashboard UI: the templates in `web/templates/` and the assets in `web/static/`. It describes the current source. The Go types it names are in [`models.go`](../models.go) and [`dashboard_models.go`](../dashboard_models.go); those are the only Go files a UI author needs to read.

Explorer supervises the standalone `lupetto` CLI and gets every fact from `lupetto … --json`. The UI only presents CLI documents and Explorer job state. It must not compute security conclusions, choose or rank versions, or invent outcomes. Display strings that carry a judgement (verdicts, action labels) come from Go.

The UI is visual direction **B · Pista** from the approved mockup (`design/mockup/`, `?theme=b`): graphite/teal, monospace versions and digests, a left side rail, one dense product ledger, square corners, a 4-segment severity meter plus text. Light and dark palettes follow the OS (`prefers-color-scheme`); there is no theme switcher.

## Files and template names

- Templates are every `web/templates/*.html` file (top level only). All are parsed into one `html/template` set at startup. The server runs templates **by defined name, not by file name**:

| Template | Routes | Model (root `.`) | File |
| --- | --- | --- | --- |
| `images` | `GET /`, `GET /images` | `ImagesView` | `images.html` |
| `image` | `GET /images/{package}/{selector}`, alias `GET /tracks/{package}/{selector}` | `ImageView` | `image.html` |
| `packages` | `GET /catalog`, alias `GET /packages` | `PackagesView` | `catalog.html` |
| `package` | `GET /catalog/{name}`, alias `GET /packages/{name}` | `PackageView` | `catalog.html` |
| `jobs` | `GET /builds`, alias `GET /jobs` | `JobsView` | `builds.html` |
| `job` | `GET /builds/{id}`, alias `GET /jobs/{id}` | `JobDetailView` | `builds.html` |
| `tracking` | `GET /products/track` | `TrackingView` | `tracking.html` |

- Shared names: `layout.html` (page shell: `head`, `rail-images`/`rail-catalog`/`rail-builds`, `page-end`, `doc-end`), `partials.html` (severity, verdicts, stages, data note, track dialog, …), `icons.html` (`icon`, `icon-lg`, `icon-xl`, `icon-paths`, `logo`). Every `define` name is global: a duplicate silently replaces the other.
- No custom template functions are registered. Use built-ins (`len`, `index`, `slice`, `eq` — which accepts several right-hand values —, `ne`, `lt`, `gt`, `and`, `or`, `not`, `printf`, `urlquery`) and methods such as `.Format`/`.IsZero` on `time.Time`. Templates cannot do arithmetic, so every count the UI shows is a Go field.
- A sub-template call resets `$` to its argument. Anything needing `$.CSRFToken`, `$.BuildsEnabled` or `$.Shell` inside a `range` must be inline in the page template or receive those values as its root.
- Output is buffered. A missing template or an execution error returns a plain-text `500` with the error and no partial HTML. With no `.html` files, every HTML page returns `500` `Explorer template "<name>" is missing; dashboard UI is not installed`; `?format=json` still works.
- Static assets are embedded and served at `GET /static/<path>` (`/static/app.css`, `/static/app.js`). `CONTRACT.md` and `.gitkeep` are not templates.

## Security constraints for UI authors

Every response carries:

```
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cache-Control: no-store
```

- **The CSP blocks inline code.** No inline `<script>`, `on*=` attributes, `javascript:` URLs, `<style>` elements or `style="…"` attributes. Everything lives in `/static/`.
- No third-party origins (fonts, CDNs, analytics, images) and no `data:` URLs. Icons are inline SVG markup in templates. `fetch` is same-origin only.
- Every string can come from the CLI, a registry or a package index: treat it as untrusted. Rely on `html/template` escaping and never bypass it (the server never provides `template.HTML`). JavaScript inserts server text with `textContent`/text nodes only, never `innerHTML`.
- **Every POST form contains `<input type="hidden" name="csrfToken" value="{{.CSRFToken}}">`** (or `$.CSRFToken` inside `range`/`with`). The template test enforces this.
- **Host allowlist on every request.** Before any route, token or Origin check, the request `Host` must match an `--allowed-host` rule; otherwise the server returns a plain-text `403` (`Host is not allowed; configure --allowed-host for the intended external hostname`) with no model data and no CSRF token. This applies on every listener address, including `0.0.0.0`.
  - With no `--allowed-host` flags, the defaults are exactly `localhost`, `127.0.0.1` and `[::1]`, each at any valid port.
  - The flag is repeatable and explicit values **replace** the defaults. A hostname without a port allows any port; `host:port` requires that exact port, and a `Host` with no port does not match it. IPv6 literals are bracketed (`[2001:db8::1]:9443`). DNS names compare case-insensitively with a trailing dot ignored; IP addresses are normalized.
  - An ingress deployment must list its external hostname. Only `Host` is checked; forwarded headers are never consulted. The allowlist is a DNS-rebinding guard, not authentication. Explorer has no login; access control is the network boundary.

## Common model: `BaseView` and `ShellView`

Every page model embeds `BaseView`, so its fields are at the root (`{{.CSRFToken}}`, `{{.Shell.Registry}}`). Inside `range`/`with`, use `$.…`.

| Field | Meaning |
| --- | --- |
| `CSRFToken string` | Random per process; the hidden field `csrfToken` in every POST form. A page loaded before a restart gets `403`. |
| `BuildsEnabled bool` | `false` unless started with `--enable-builds`. When false, render build buttons disabled (never as POST forms) and say why; the server rejects builds with `403` anyway. Tracking products is **not** gated by this flag. |
| `Shell ShellView` | Side rail, footer and build-guard data, on every page. |

```
ShellView { Registry, RegistryState, DockerState, DockerReason string; RunningBuild *BuildItem;
            StatusComputedAt time.Time; StatusRefreshing bool; IndexSHA256, FeedSHA256, Architecture string }
```

- `Registry` is the configured `host/repository` ("" = not configured). `RegistryState` is the result of the last status comparison, not a separate health check: `ready` (comparison without errors), `error` (`Status.LastError` or any track error), or `unknown`/`""` (not compared yet). `DockerState` is `available`, `unavailable` (show `DockerReason`), or `""` (not known yet).
- `RunningBuild` is non-nil while a build runs. Only one build runs at a time: render every build control disabled with "Another build is running", show the nav count and a link to the running build.
- `StatusComputedAt` can be zero (no successful check yet). The footer offers `POST /status/refresh` ("Check now").

## Read-only JSON (`?format=json`)

Adding `?format=json` to any GET page route returns its model as `application/json` (JSON names from the Go tags). There are no JSON write endpoints. Missing slices can be `null` in JSON. The JS uses: `/?format=json` → `status.refreshing`; `/catalog?format=json` → `refreshing`; `/builds?format=json` → `running`, `shell.runningBuild.detailURL`; `/builds/{id}?format=json` → `item.state`, `item.stages[].name|status`.

## Time values

- Pointers can be nil (`JobView.EndedAt`, `JobView.ExitCode`, `InventoryBuild.BuildTime`, `InspectDocument.Created`); guard them with `with`. `{{with .ExitCode}}` tests the pointer, so exit code `0` still renders. `ExitCode` can be `-1` when the process never started.
- Non-pointer times can be zero; check `.IsZero`. All times are UTC; the UI renders `2006-01-02` in dense cells (full time in `title`) and `2006-01-02 15:04 UTC` elsewhere, inside `<time datetime>`.

## Shared enumerations

| Value | Where | Values → UI |
| --- | --- | --- |
| `ProductRow.VerdictKind` | verdict chip colour/icon | `ok` (green check), `update` (amber up-arrow), `rebuild` (amber cycle), `notbuilt` (blue dashed plus), `local` (blue upload), `error` (red triangle); anything else renders muted. The text is always `ProductRow.Verdict` (Go display string, e.g. "Up to date", "Update available", "Fixes available", "Not in registry", "Unable to compare"); optional sub-line `VerdictDetail`. |
| `PrimaryAction.Kind` | row/page primary action | `build` → POST `/builds` form with `package`, `selector`, `mode`, label `Label`; `tracking` → link to `URL` (or `/products/track?package=`); `""` → "Details" link. |
| `PrimaryAction.Mode`, form `mode` | builds | `publish`: `--no-load`, inherits registry/signing settings. `local`: loads into local Docker; publication and signing are suppressed. |
| severity | `MissingFix.MaxSeverity`, `Advisory.Severity` | `critical`, `high`, `medium`, `low`; anything else (including `""`) is shown as `unknown`. Meter segments filled: 4/3/2/1/0. Text label always present. |
| `BuildItem.State` | builds | `running`, `succeeded`, `failed`, `canceled` (Explorer jobs and records); `unsupported`, `invalid`, `unreadable` (history records that could not be used; show `Error`). |
| `BuildStage.Name` | 7-stage progress, always all seven in order | `resolve`, `build`, `validate`, `load`, `publish`, `sign`, `attest` → "Resolve", "Build", "Validate SBOM", "Load into Docker", "Publish", "Sign", "Attest SBOM". |
| `BuildStage.Status` | stage cells | record values `completed`, `loaded`, `published`, `signed`, `attested` (done), `failed`, `skipped` ("Skipped · not requested"), `not-attempted` ("Not attempted · earlier stage failed"); live jobs also `running` ("In progress") and `pending` ("Waiting") for stages not yet reached. No percentages. |
| `PackageSet.Source` | packages/compare | `registry`, `local`. |
| `PackageChange.Kind` | compare | `added`, `removed`, `changed`. Explorer does not order versions, so a change is never labelled an upgrade or downgrade. |

## Pages

### `images`: `ImagesView`

```
ImagesView   { BaseView; Status StatusView; Inventory InventoryView; Products []ProductRow; Groups []ProductGroup;
               Summary ImagesSummary; Notice ImagesNotice; Query, Filter string; TotalMatches int }
ProductGroup { Package, DetailURL string; Rows []ProductRow }
ImagesSummary{ All, NeedsAction, Current, NotInRegistry, MissingCritical int }
ImagesNotice { Tracked, Untracked string }
ProductRow   { Package, Selector string; Track Track; DetailURL string; Versions []VersionRow;
               Verdict, VerdictKind, VerdictDetail string; UnreachableCount int; NeedsAction bool;
               Severity SeverityCounts; Action PrimaryAction }
VersionRow   { Identity PackageIdentity; Key string; Registry []Image; LocalImages []DockerImage; Builds []BuildItem; Latest bool }
SeverityCounts { Critical, High, Medium, Low, Unknown, Total int }
StatusView   { Document *StatusDocument; LastError string; Refreshing bool }
InventoryView{ Document *ImagesDocument; Error string }
```

- Query string: `q` (≤ 256 bytes, else `400`) and `filter` = `all` | `needs-action` | `current` | `not-in-registry` (tracks in state `not-built`; an error track is not evidence of absence) | `critical` (tracks with any critical advisory) (aliases `action`, `notbuilt`); anything else is `400`. The toolbar is a GET form (no CSRF). Filtering happens in Go; `Groups` holds only matching rows, `Summary` counts all tracks.
- The ledger renders one `ProductGroup` per product (`product-head` + one `tracks` row per selector). Columns: Version (`Selector`, `Track.Latest.Name`), Registry (`Track.Newest`, `len Track.Images`), Local (first `VersionRow` with `LocalImages`, else first with `Builds`, else "None"; "Docker unavailable" when `Shell.DockerState` is `unavailable`), Latest in Wolfi (`Track.Latest.Version`), Missing fixes (`Severity` meter + "`UnreachableCount` need another version"; "No registry image" without `Track.Newest`; "Unknown (track error)" when `Track.State` is `error`), Verdict, Action.
- `Severity` counts unique advisory IDs over all missing and unevaluated fixes of the newest registry image. `UnreachableCount` counts fixes that need a version outside the selector.
- `Notice.Tracked`/`Untracked` come from `?tracked=`/`?untracked=` after a products POST and render a confirmation banner.
- States: `Status.Document == nil && Status.Refreshing` → "Checking your images…" (polls `status.refreshing`, reloads); `Status.LastError` → error banner (with stale data if `Document` is set, showing `ComputedAt`); no tracks and no filter → "No products tracked yet" empty state; filter/query with no rows → "No images match"; `!BuildsEnabled` → read-only banner; `Shell.RunningBuild` → building banner; Docker unavailable / `Inventory.Error` → warning banners.
- The page carries the track dialog (see [Tracking](#tracking-trackingview)) and the single [security-data note](#security-evidence-required-wording).

### `image`: `ImageView` (one tracked version)

```
ImageView { BaseView; Status StatusView; Inventory InventoryView; Product ProductRow; Tab string;
            Versions []PackageSet; Packages PackageSet; Compare CompareView;
            FixedByRebuilding, NeedsAnotherVersion []MissingFix; Builds []BuildItem; Siblings []ImageSibling }
ImageSibling { Selector, URL string; Current bool }
PackageSet   { Key, Label, Source string; Packages []PackageIdentity; SPDXURL, Error string }
CompareView  { From, To string; Before, After PackageSet; Changes []PackageChange; Added, Removed, Changed, Unchanged int; Error string }
PackageChange{ Name, Architecture, Before, After, Kind string }
MissingFix   { Name, Architecture, InstalledVersion, FixedVersion, AvailableVersion string; IDs []string; ReachableByTrack bool;
               Advisories []Advisory; MaxSeverity string }
Advisory     { ID, Severity, SeveritySource string }
```

- `?tab=` `overview` (default) | `vulnerabilities` | `packages` | `compare` | `builds`; anything else is `400`. Packages: `?version=<PackageSet.Key>`. Compare: `?from=<Key>&to=<Key>`. Keys are registry digests or build IDs. A track missing from the cached status is a plain-text `404`.
- Tab links are `{{.Product.DetailURL}}?tab=…`; the version switcher uses `Siblings[].URL` and keeps the tab.
- **Overview:** verdict block, Registry (`Track.Images`, newest first; `UnidentifiedCount`/`ArtifactCount` are counts, not errors), Local Docker (`Versions[].LocalImages`), Recent builds (first three `Builds`), and a version strip from `Product.Versions` (index latest first, then registry newest-first, then local-only identities — not an APK ordering). `Track.State == "error"` shows `Track.Error` and never a clean result.
- **Vulnerabilities:** scope line (newest registry image; local images are not checked), banner, severity tiles (`Product.Severity`), "Fixed by rebuilding" (`FixedByRebuilding`) and "Needs another version" (`NeedsAnotherVersion`) tables, then `Track.UnevaluatedFixes` as an explicit "Couldn't be evaluated" table. One row per fix; each advisory ID links to NVD/GitHub/pkg.go.dev by prefix with its own severity and `SeveritySource`. "No missing fixes found" only appears when all three lists are empty and the track is not in error, and always links to the data note.
- **Packages:** source switcher over `Versions`; local builds with `SPDXURL` get a "Download SPDX (JSON)" link (`download` attribute, served by `GET /builds/{id}/sbom`); registry sets say SBOM download from attestations comes later. "Newer in Wolfi"/"Missing fixes" columns appear only for the newest registry image (they come from `Track.Outdated`/`Track.MissingFixes`). `PackageSet.Error` is shown verbatim.
- **Compare:** GET form with `tab=compare`, `from`, `to` selects over `Versions`; summary pills from the counts; table of `Changes` (unchanged hidden). Fewer than two `Versions` → "Nothing to compare yet".
- **Builds:** the shared builds table over `Builds` (records and live jobs for every version of this package, not only this selector).

### `packages`: `PackagesView` (catalog)

```
PackagesView { BaseView; Query string; Packages []PackageItem; TotalMatches, Limit int; Document *DiscoverDocument; LastError string; Refreshing bool }
PackageItem  { DiscoveredPackage; DetailURL string; Tracked bool }   // DiscoveredPackage { Name, Version, Description string }
```

- GET form with `q` (≤ 256 bytes). Case-insensitive substring match on name or description; empty `q` lists everything up to `Limit` (200). When `TotalMatches > Limit`, say the list is truncated.
- `Document` is metadata only (`Architecture`, `IndexSHA256`). `Document == nil && Refreshing` means "not loaded yet" (poll `refreshing`), not "no matches". `LastError` is the last discovery failure.
- Row actions: tracked → "Open" (`/?q=<name>`); otherwise "Track" (`/products/track?package=<name>`, opens the dialog with the package prefilled); "Versions…" → `DetailURL`.

### `package`: `PackageView` (one package's exact versions)

```
PackageView { BaseView; Name string; Document *DiscoverDocument; Error string }
```

- Runs `lupetto discover --json <name>` synchronously (25 s limit, at most four concurrent; otherwise `503 package discovery is busy; retry shortly`). Invalid names are `400`. `Error` is shown verbatim; `Document` is then nil.
- Each exact version has two POST `/builds` forms with `package` = the requested `Name` (preserves providers such as `cmd:curl`), `apkVersion` = the entry's `Version`, and `mode` = `publish` ("Build & publish") or `local` ("Build locally"). "Track versions" opens the dialog prefilled with `Name`.

### `jobs`: `JobsView` (builds list)

```
JobsView  { BaseView; Items []BuildItem; Inventory InventoryView; Jobs []JobView; Running bool; HistoryLimit int }
BuildItem { ID, DetailURL, Package, Version, State string; StartedAt time.Time; Record *BuildRecord; Error string;
            Stages []BuildStage; Live bool; SPDXURL string }
BuildStage{ Name, Status string }
```

- `Items` is newest first and merges retained build records (`lupetto images --json`, including CLI builds) with Explorer's in-memory jobs (`Live` true). Explorer keeps the last `HistoryLimit` (50) live jobs in memory only; records persist in the cache directory. `?package=` filters by package.
- `Shell.RunningBuild` renders a "Running now" card with live stages, View and Cancel (POST `/builds/{id}/cancel`).
- The result column is derived only from stage statuses (e.g. "published; failed at Sign"), never from log text.

### `job`: `JobDetailView` (build detail)

```
JobDetailView { BaseView; Item BuildItem; HasLog bool; Job JobView; Log LogChunk }
JobView  { ID string; Request BuildRequest; State string; StartedAt time.Time; EndedAt *time.Time; ExitCode *int; Record *BuildRecord; Error string; CancelRequested bool }
LogChunk { Offset, NextOffset int64; Text string; Truncated, Done bool }
```

- An unknown ID is a plain-text `404`. `Job` is meaningful only when `Item.Live`. `HasLog` is false for history records (the raw log exists only for builds started by this server process).
- The page shows: an outcome banner by `Item.State` (running: "This page updates automatically"; failed: `Record.Failure.Stage`/`Error` and the side-effects warning when `SideEffectsPossible`; canceled: "external side effects may remain"), `Item.Error` verbatim as "Explorer diagnostic", the 7-stage progress, Outputs (publication reference/digest, a warning when `Digest` is not `Verified`, Docker reference, signing/attestation status, SPDX download from `Item.SPDXURL` with `Evidence.SPDXValidated`), Inputs (request, selection, index SHA-256, apko, lock and workspace paths as text), and the raw log behind a `<details>` toggle (open by default when failed).
- Show both Explorer's state and the record's stage outcomes; never infer success from either alone or from log text.

### `tracking`: `TrackingView`

```
TrackingView     { BaseView; Package, Selector string; Products *ProductsDocument; Error, Message string }
ProductsDocument { Kind string; Version int; Products []Product; Changed bool; Message string }
Product          { Package string; Selectors []string }
```

- `GET /products/track[?package=&selector=]` prefills the form. It is the no-JavaScript fallback for the "Track a product" dialog: every opener is `<a href="/products/track…" data-opens="track-dialog" [data-package="…"]>`; with JavaScript the page's `<dialog id="track-dialog">` opens instead (`[data-closes]` closes it).
- The page lists every tracked package/selector with a "Stop tracking" POST form. `Error` (e.g. a read-only products file) and `Message` are shown verbatim.

## Live updates (polling, no push)

- **Status:** background refreshes run at startup, every refresh interval (default 15 min), after each build ends, after products change, and on `POST /status/refresh`. Elements with `data-poll-url` + `data-poll-field` poll that JSON every ~2.5 s and reload the page when the field becomes false.
- **Stages:** an element with `data-live-url="/builds/{id}?format=json"` polls every ~2 s and updates each `[data-stage="<name>"]` item's class, icon and `[data-stage-state]` text from `item.stages`; when `item.state` is no longer `running` the page reloads for the record.
- **Log:** `GET /builds/{id}/logs?offset=N` (alias `/jobs/{id}/logs`) returns `LogChunk` JSON, never a template. `offset` is an absolute byte position (omitted = 0; negative/non-integer = `400`; unknown job = `404`). Only the most recent 1 MiB is kept: an older `offset` starts at the oldest retained byte with `truncated: true`; an offset past the end is clamped with empty `text`. Append `text`, set `offset = nextOffset`, repeat every ~1.5 s until `done: true` (that response already holds the final bytes), then reload. `text` may split lines or multibyte characters and invalid UTF-8 becomes U+FFFD; append with text nodes only. The log is CLI progress and tool diagnostics, not the result.
- **Build buttons:** forms marked `data-build-form` are disabled on submit and while `/builds?format=json` reports `running`; pages rendered during a build reload when it ends.

## POST actions

All POSTs:

- Body `application/x-www-form-urlencoded` (a normal `<form method="post">`), ≤ 8 KiB. Multipart bodies are not parsed: a `FormData` `fetch` body fails CSRF; use `URLSearchParams`.
- `csrfToken` must be **in the body** (the query string is ignored). Each field must appear exactly once; a duplicated field counts as empty.
- The `Host` must pass the allowlist first (an unlisted `Host` is `403` before token or Origin are examined).
- The request must be same-origin. If `Origin` is present, its scheme must be `http` or `https` and its authority must exactly equal the request `Host`, including any port (no path, query or userinfo). Either scheme is accepted so a TLS-terminating ingress that forwards plain HTTP works; no forwarded headers (`X-Forwarded-*`, `Forwarded`) are trusted. Without `Origin`, `Sec-Fetch-Site: same-origin` is required. Any `Sec-Fetch-Site` other than `same-origin` is rejected. Ordinary same-origin form posts from browsers satisfy this because the server sends `Referrer-Policy: same-origin`: under `no-referrer`, browsers send `Origin: null` on form posts, and `Origin: null` is always rejected (do not set a stricter referrer policy in templates). `same-origin` still sends no referrer to any other origin.
- Success is `303 See Other`. Failures are plain text (not templates), except products edits, which re-render `tracking` with `Error`.

| Action | Fields | Success | Errors |
| --- | --- | --- | --- |
| `POST /status/refresh` | `csrfToken` | 303 → `/`; asynchronous, no second run while one is running | 403 Host/origin/CSRF; 400 bad form |
| `POST /builds` | `csrfToken`, `package`, **exactly one** non-empty `selector` or `apkVersion`, `mode` (`publish`\|`local`; absent = `publish`) | 303 → `/builds/{id}` | 400 validation; 403 Host, builds disabled, origin/CSRF; 409 a build is already running; 503 shutting down |
| `POST /builds/{id}/cancel` (alias `/jobs/{id}/cancel`) | `csrfToken` | 303 → `/builds/{id}` | 404 unknown job; 409 no longer running; 403 Host/origin/CSRF |
| `POST /products/add` | `csrfToken`, `package`, `selector` (one or more selectors separated by whitespace) | 303 → `/?tracked=<package>` | `tracking` page with `Error`; 403 Host/origin/CSRF |
| `POST /products/remove` | `csrfToken`, `package`, `selector` | 303 → `/?untracked=<package>` | `tracking` page with `Error`; 403 Host/origin/CSRF |

Build field validation (the UI may mirror it): `package` ≤ 256 bytes, `^[A-Za-z0-9][A-Za-z0-9+._-]*(?::[A-Za-z0-9][A-Za-z0-9+._-]*)*$`; `selector` ≤ 128 bytes, `^[0-9]+(?:\.[0-9]+)*$`; `apkVersion` ≤ 256 bytes ending in `-r<digits>`. Explorer runs `lupetto build <package> (<selector> | --apk-version <apkVersion>) --json` plus `--no-load` for `publish`; publication and signing follow the inherited environment and are shown by `Record.Request.Publish`/`Sign`/`Load`. Products edits run `lupetto products add|remove --products <file> --json`; they are not gated by `--enable-builds`.

## Build records

`BuildItem.Record`/`Job.Record` is the CLI's version-6 record. It is nil when the invocation was rejected (exit 2), the output was incompatible, or the job was canceled before a record was printed; it can be present on a failed job as a partial record.

```
BuildRecord     { Version int; Command, Outcome, Workspace string; Failure *RecordFailure; Request RecordRequest; Selection *RecordSelection; Evidence *RecordEvidence; Stages RecordStages }
RecordFailure   { Stage, Error string; SideEffectsPossible bool }
RecordRequest   { BuildRequest; Load, Publish, Sign bool }
RecordSelection { Package, Version, Architecture, IndexSHA256 string }
RecordEvidence  { ApkoVersion, ImageDirectory, ImageDigest, LockPath, SPDXPath, SPDXSHA256 string; SPDXValidated bool }
RecordStages    { Build, Load, Publication, Signing, Attestation StageOutcome }
StageOutcome    { Status, Reference, Digest, ImmutableReference, ImageReference, BuildReference, DockerImageID string; Verified, ReadableReferenceConfirmed bool }
```

- Render every stage separately with its own status; never collapse them into one "built"/"published" badge. `skipped` (not requested) and `not-attempted` (requested, not reached because an earlier stage failed) are labelled differently and neither is a failure.
- **Partial success is not success.** Publication `published` with signing `failed` is shown as confirmed publication and an overall failed build.
- A publication `Digest` with `Verified` false is not a confirmed publication and never a basis for signing; say so.
- With `Failure`, show `Failure.Stage` and `Failure.Error`; if `SideEffectsPossible`, warn that local or remote side effects may remain and no rollback was attempted.
- `Workspace`, `LockPath`, `SPDXPath` are local paths: show them as text, not links.

## Security evidence (required wording)

`StatusDocument.Security` (`SecuritySource`: `URL`, `SHA256`, `Unsigned`, `FixedOnly`, `WolfiOnly`, `UnevaluatedFixCount`, `UnevaluatedFixes`, `Severity SeveritySummary`) is explained **once per page** in the `data-note` partial (a `<details>` "About this security data", `id="about-data"`), not as repeated warnings. The UI must:

- Show the feed `URL` and `SHA256`, that it is not signed, lists fixed issues only, and covers Wolfi packages only; severity comes from NVD/GitHub/OSV, `unknown` is shown honestly, and severity never changes a verdict. `Severity.PendingCount`/`FetchFailureCount` are mentioned when nonzero.
- **Never show a clean result.** No "secure", "no vulnerabilities" or green all-clear. "No missing fixes found" / "None found" only ever means "no known fixed-version advisories in this unsigned, fixed-only Wolfi feed" and is always paired with the note.
- Treat `UnevaluatedFixCount > 0` and a non-empty `Track.UnevaluatedFixes` as explicit warnings and list the entries. A `current` track with unevaluated entries or unreachable fixes must not look clean.
- Show reachable and unreachable missing fixes separately: **Fixed by rebuilding** (`ReachableByTrack`: top-level fixes through the track's selected APK; dependency fixes by index availability — not a solved future lock, and the rebuild may fail) and **Needs another version** (the top-level fix needs a version beyond this selector).
- A track in `error` shows its error and "could not be determined", never an empty (clean) list.

## Other routes

`GET /builds/{id}/sbom` downloads a local build's validated SPDX JSON (the `SPDXURL` fields). `GET /healthz` returns `text/plain` `ok` (the process is serving; nothing more). `GET /static/<path>` serves embedded assets. There are no other routes.
