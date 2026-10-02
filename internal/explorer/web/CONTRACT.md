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
            StatusComputedAt time.Time; StatusRefreshing bool; IndexSHA256, FeedSHA256, Architecture string;
            PublishLoad bool; PublishLoadReason string; Signatures SignatureConfigView }
SignatureConfigView { Enabled bool; Reason string }
```

- `Registry` is the configured `host/repository` ("" = not configured). `RegistryState` is the result of the last status comparison, not a separate health check: `ready` (comparison without errors), `error` (`Status.LastError` or any track error), or `unknown`/`""` (not compared yet). `DockerState` is `available`, `unavailable` (show `DockerReason`), or `""` (not known yet, e.g. `lupetto images` failed before any successful load). Only `available` may be presented as "no images in local Docker"; any other value reads "Local Docker state unknown or unavailable".
- `PublishLoad` is true exactly when the latest local inventory reports Docker as `available`; a "Build & publish" started now would then also load into local Docker. Otherwise `PublishLoadReason` says why it would publish only (the inventory's Docker reason, "Docker is unavailable", or "Docker availability is unknown"). Every enabled "Build & publish" control carries a short sub-line (`btn-note`): "also loads into local Docker", or "publish only: Docker unavailable" / "publish only: Docker state unknown" (by `DockerState`).
- `RunningBuild` is non-nil while a build runs. Only one build runs at a time: render every build control disabled with "Another build is running", show the nav count and a link to the running build.
- `Signatures.Enabled` is true when Explorer was started with `LUPETTO_COSIGN_PUBLIC_KEY` set. When false, nothing is verified, every registry image's signature is `not-checked`, and pages show `Signatures.Reason` once (the `sig-note` partial) instead of repeating it per image.
- `StatusComputedAt` can be zero (no successful check yet). The footer offers `POST /status/refresh` ("Check now").

## Read-only JSON (`?format=json`)

Adding `?format=json` to any GET page route returns its model as `application/json` (JSON names from the Go tags). There are no JSON write endpoints. Missing slices can be `null` in JSON. The JS uses: `/?format=json` → `status.refreshing`, `signaturesPending`; `/images/{package}/{selector}?format=json` → `signaturesPending`; `/catalog?format=json` → `refreshing`; `/builds?format=json` → `running`, `shell.runningBuild.detailURL`; `/builds/{id}?format=json` → `item.state`, `item.stages[].name|status`.

## Time values

- Pointers can be nil (`JobView.EndedAt`, `JobView.ExitCode`, `InventoryBuild.BuildTime`, `InspectDocument.Created`); guard them with `with`. `{{with .ExitCode}}` tests the pointer, so exit code `0` still renders. `ExitCode` can be `-1` when the process never started.
- Non-pointer times can be zero; check `.IsZero`. All times are UTC; the UI renders `2006-01-02` in dense cells (full time in `title`) and `2006-01-02 15:04 UTC` elsewhere, inside `<time datetime>`.

## Shared enumerations

| Value | Where | Values → UI |
| --- | --- | --- |
| `ProductRow.VerdictKind` | verdict chip colour/icon | `ok` (green check), `update` (amber up-arrow), `rebuild` (amber cycle), `notbuilt` (blue dashed plus), `local` (blue upload), `error` (red triangle); anything else renders muted. The text is always `ProductRow.Verdict` (Go display string, e.g. "Up to date", "Update available", "Fixes available", "Not in registry", "Unable to compare"); optional sub-line `VerdictDetail`. |
| `PrimaryAction.Kind` | row/page primary action | `build` → POST `/builds` form with `package`, `selector`, `mode`, label `Label`; `tracking` → link to `URL` (or `/products/track?package=`); `""` → "Details" link. |
| `PrimaryAction.Mode`, form `mode` | builds | `publish`: inherits registry/signing settings and also loads into local Docker when `Shell.PublishLoad` is true at submission; otherwise publish only (`--no-load`). `local`: loads into local Docker; publication and signing are suppressed. |
| severity | `MissingFix.MaxSeverity`, `Advisory.Severity` | `critical`, `high`, `medium`, `low`; anything else (including `""`) is shown as `unknown`. Meter segments filled: 4/3/2/1/0. Text label always present. |
| `BuildItem.State` | builds | `running`, `succeeded`, `failed`, `canceled` (Explorer jobs and records); `unsupported`, `invalid`, `unreadable` (history records that could not be used; show `Error`). |
| `BuildStage.Name` | 7-stage progress, always all seven in order | `resolve`, `build`, `validate`, `load`, `publish`, `sign`, `attest` → "Resolve", "Build", "Validate SBOM", "Load into Docker", "Publish", "Sign", "Attest SBOM". |
| `BuildStage.Status` | stage cells | record values `completed`, `loaded`, `published`, `signed`, `attested` (done), `failed`, `skipped` ("Skipped · not requested"; a publish-only job with `BuildItem.LoadReason` shows "Skipped · <LoadReason>" on its Load stage instead), `not-attempted` ("Not attempted · earlier stage failed"); live jobs also `running` ("In progress") and `pending` ("Waiting") for stages not yet reached. A live job's Load stage follows `BuildItem.Load`, not the button that was clicked. No percentages. |
| `PackageSet.Source` | packages/compare | `registry`, `local`. |
| `SignatureView.State` | signature chip (`sig-chip`) | `signed` → "Signed" (green seal), `unsigned` → "Unsigned" (amber), `invalid` → "Invalid" (red), `error` → "Error" (red; `Detail` is the sanitized CLI or verify error, one line, ≤ 240 characters), `checking` → "Checking…" (muted, dashed; no result yet, a check is queued or running), `not-checked` → "Not checked" (no trusted key; `Detail` says why) or "Not checked yet" (trusted key, check not started). `Label` is the Go display text. A signature state never changes `Verdict`, `VerdictKind`, `NeedsAction` or a track state. |
| `SignatureView.Attestation` | SBOM attestation chip (`att-chip`) | `attested` → "SBOM attested · N packages" (green), `absent` → "No SBOM attestation" (amber), `invalid` → "Invalid SBOM attestation" (red), `error` → "SBOM check error" (red); `""` when no result yet (no chip). |
| `SignatureView.TransparencyLog` | caveat | `verified`; `skipped-local` sets `LocalOnly` and renders "local only · no transparency log" next to the chip: verified with the loopback HTTP exception, not production evidence. |
| `PackageChange.Kind` | compare | `added`, `removed`, `changed`. Explorer does not order versions, so a change is never labelled an upgrade or downgrade. |

## Pages

### `images`: `ImagesView`

```
ImagesView   { BaseView; Status StatusView; Inventory InventoryView; Products []ProductRow; Groups []ProductGroup;
               Summary ImagesSummary; Notice ImagesNotice; Query, Filter string; TotalMatches int; SignaturesPending bool }
ProductGroup { Package, DetailURL string; Rows []ProductRow }
ImagesSummary{ All, NeedsAction, Current, NotInRegistry, MissingCritical int }
ImagesNotice { Tracked, Untracked string }
ProductRow   { Package, Selector string; Track Track; DetailURL string; Versions []VersionRow;
               Verdict, VerdictKind, VerdictDetail string; UnreachableCount int; NeedsAction bool;
               Severity SeverityCounts; Action PrimaryAction;
               Signatures map[string]*SignatureView; NewestSignature *SignatureView }
SignatureView{ State, Label, Detail, Attestation, AttestationLabel, AttestationDetail string; SBOMPackages int; SBOMURL string;
               TransparencyLog string; LocalOnly bool; KeySHA256 string; CheckedAt time.Time; Rechecking bool }
VersionRow   { Identity PackageIdentity; Key string; Registry []Image; LocalImages []DockerImage; Builds []BuildItem; Latest bool }
SeverityCounts { Critical, High, Medium, Low, Unknown, Total int }
StatusView   { Document *StatusDocument; LastError string; Refreshing bool }
InventoryView{ Document *ImagesDocument; Error string }
```

- Query string: `q` (≤ 256 bytes, else `400`) and `filter` = `all` | `needs-action` | `current` | `not-in-registry` (tracks in state `not-built`; an error track is not evidence of absence) | `critical` (tracks with any critical advisory) (aliases `action`, `notbuilt`); anything else is `400`. The toolbar is a GET form (no CSRF). Filtering happens in Go; `Groups` holds only matching rows, `Summary` counts all tracks.
- The ledger renders one `ProductGroup` per product (`product-head` + one `tracks` row per selector). Columns: Version (`Selector`, `Track.Latest.Name`), Registry (`Track.Newest`, `len Track.Images`), Local (first `VersionRow` with `LocalImages`, else first with `Builds`, else "None"; "Docker unavailable" when `Shell.DockerState` is `unavailable`), Latest in Wolfi (`Track.Latest.Version`), Missing fixes (`Severity` meter + "`UnreachableCount` need another version"; "No registry image" without `Track.Newest`; "Unknown (track error)" when `Track.State` is `error`), Verdict, Action.
- Signatures on the home page are compact: each row's `Signatures` holds only its newest registry image (also `NewestSignature`), rendered as a `sig-chip` under the Registry cell. `SignaturesPending` (any shown image still `checking`) adds a `data-poll-field="signaturesPending"` element that reloads the page when checks finish. With `Shell.Signatures.Enabled` false the page shows the reason once.
- `Severity` counts unique advisory IDs over all missing and unevaluated fixes of the newest registry image. `UnreachableCount` counts fixes that need a version outside the selector.
- `Notice.Tracked`/`Untracked` come from `?tracked=`/`?untracked=` after a products POST and render a confirmation banner.
- States: `Status.Document == nil && Status.Refreshing` → "Checking your images…" (polls `status.refreshing`, reloads); `Status.LastError` → error banner (with stale data if `Document` is set, showing `ComputedAt`); no tracks and no filter → "No products tracked yet" empty state; filter/query with no rows → "No images match"; `!BuildsEnabled` → read-only banner; `Shell.RunningBuild` → building banner; Docker unavailable / `Inventory.Error` → warning banners.
- The page carries the track dialog (see [Tracking](#tracking-trackingview)) and the single [security-data note](#security-evidence-required-wording).

### `image`: `ImageView` (one tracked version)

```
ImageView { BaseView; Status StatusView; Inventory InventoryView; Product ProductRow; Tab string;
            Versions []PackageSet; Packages PackageSet; Compare CompareView;
            FixedByRebuilding, NeedsAnotherVersion []MissingFix; Builds []BuildItem; Siblings []ImageSibling;
            SignaturesPending bool }
ImageSibling { Selector, URL string; Current bool }
PackageSet   { Key, Label, Source string; Packages []PackageIdentity; SPDXURL, Error string; Signature *SignatureView }
CompareView  { From, To string; Before, After PackageSet; Changes []PackageChange; Added, Removed, Changed, Unchanged int; Error string }
PackageChange{ Name, Architecture, Before, After, Kind string }
MissingFix   { Name, Architecture, InstalledVersion, FixedVersion, AvailableVersion string; IDs []string; ReachableByTrack bool;
               Advisories []Advisory; MaxSeverity string }
Advisory     { ID, Severity, SeveritySource string }
```

- `?tab=` `overview` (default) | `vulnerabilities` | `packages` | `compare` | `builds`; anything else is `400`. Packages: `?version=<PackageSet.Key>`. Compare: `?from=<Key>&to=<Key>`. Keys are registry digests or build IDs. A track missing from the cached status is a plain-text `404`.
- Tab links are `{{.Product.DetailURL}}?tab=…`; the version switcher uses `Siblings[].URL` and keeps the tab.
- The security-data note is rendered once per page, below the tab content, on the Overview and Vulnerabilities tabs (both can show "None found").
- **Overview:** verdict block, Registry (`Track.Images`, newest first; `UnidentifiedCount`/`ArtifactCount` are counts, not errors), Local Docker (`Versions[].LocalImages`), Recent builds (first three `Builds`), and a version strip from `Product.Versions` (index latest first, then registry newest-first, then local-only identities — not an APK ordering). Each registry image shows `index .Product.Signatures <digest>` with the `sig-full` partial (signature and SBOM chips, `Detail`, "checked <time>", "· rechecking" while a stale result is being refreshed, the trusted key's short SHA-256) and, when `SBOMURL` is set, a "Download signed SBOM (SPDX JSON)" link. `SignaturesPending` polls `{{.Product.DetailURL}}?format=json`. `Track.State == "error"` shows `Track.Error` and never a clean result; an empty `Track.Images` on an error track reads "Registry contents could not be determined", not "Nothing published yet".
- **Vulnerabilities:** scope line (newest registry image; local images are not checked), banner, severity tiles (`Product.Severity`), "Fixed by rebuilding" (`FixedByRebuilding`) and "Needs another version" (`NeedsAnotherVersion`) tables, then `Track.UnevaluatedFixes` as an explicit "Couldn't be evaluated" table. One row per fix; each advisory ID links to NVD/GitHub/pkg.go.dev by prefix with its own severity and `SeveritySource`. "No missing fixes found" only appears when all three lists are empty and the track is not in error, and always links to the data note.
- **Packages:** source switcher over `Versions`; local builds with `SPDXURL` get a "Download SPDX (JSON)" link (`download` attribute, served by `GET /builds/{id}/sbom`); registry sets show `PackageSet.Signature`: with an `SBOMURL` a "Download signed SBOM (SPDX JSON)" button, otherwise why there is nothing to download (checking, not checked, or no verified SPDX attestation). The registry package list itself still comes from `lupetto inspect`, not from the attestation. "Newer in Wolfi"/"Missing fixes" columns appear only for the newest registry image (they come from `Track.Outdated`/`Track.MissingFixes`). `PackageSet.Error` is shown verbatim.
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
- Each exact version has two POST `/builds` forms with `package` = the requested `Name` (preserves providers such as `cmd:curl`), `apkVersion` = the entry's `Version`, and `mode` = `publish` ("Build & publish") or `local` ("Build locally"). The help text below the table says whether "Build & publish" also loads into local Docker (`Shell.PublishLoad`) or publishes only and why (`Shell.PublishLoadReason`). "Track versions" opens the dialog prefilled with `Name`.

### `jobs`: `JobsView` (builds list)

```
JobsView  { BaseView; Items []BuildItem; Inventory InventoryView; Jobs []JobView; Running bool; HistoryLimit int }
BuildItem { ID, DetailURL, Package, Version, State string; StartedAt time.Time; Record *BuildRecord; Error string;
            Stages []BuildStage; Live bool; SPDXURL string; Mode string; Load bool; LoadReason string }
BuildStage{ Name, Status string }
```

- `Mode` (`publish`/`local`, empty when unknown), `Load` and `LoadReason` come from the live job's request, or from `Record.Request` for history records. `Load` is whether loading into Docker was requested. `LoadReason` is set only for jobs started by this server process whose publish build stays publish-only; it is the Docker reason recorded at submission. History records cannot recover that reason, so their skipped Load stage reads "Skipped · not requested".
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
- The page shows: an outcome banner by `Item.State` (running: "This page updates automatically"; failed: `Record.Failure.Stage`/`Error` and the side-effects warning when `SideEffectsPossible`; canceled: "external side effects may remain"), `Item.Error` verbatim as "Explorer diagnostic", the 7-stage progress, Outputs (publication reference/digest, a warning when `Digest` is not `Verified`, Docker reference, signing/attestation status, SPDX download from `Item.SPDXURL` with `Evidence.SPDXValidated`), Inputs (request; for a live job without a record its mode, "publish · also loads into local Docker" or "publish only · <LoadReason>"; with a record the requested publication/signing/load, plus "no Docker load: <LoadReason>" for a publish-only job; selection, index SHA-256, apko, lock and workspace paths as text), and the raw log behind a `<details>` toggle (open by default when failed).
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

- **Status:** background refreshes run at startup, every refresh interval (default 15 min), after each build ends, after products change, and on `POST /status/refresh`. Elements with `data-poll-url` + `data-poll-field` poll that JSON every ~2.5 s and reload the page when the field becomes false. With `data-poll-error-field` + `data-poll-unless-field` (the catalog uses `lastError`/`document`), an error while the second value is still missing stops polling and replaces the loading state with the error as text, because each catalog GET without a document starts another discovery.
- **Stages:** an element with `data-live-url="/builds/{id}?format=json"` polls every ~2 s and updates each `[data-stage="<name>"]` item's class, icon and `[data-stage-state]` text from `item.stages` (a skipped Load stage keeps "Skipped · <item.loadReason>" when `item.mode` is `publish` and `item.load` is false); when `item.state` is no longer `running` the page reloads for the record.
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

Build field validation (the UI may mirror it): `package` ≤ 256 bytes, `^[A-Za-z0-9][A-Za-z0-9+._-]*(?::[A-Za-z0-9][A-Za-z0-9+._-]*)*$`; `selector` ≤ 128 bytes, `^[0-9]+(?:\.[0-9]+)*$`; `apkVersion` ≤ 256 bytes ending in `-r<digits>`. Explorer runs `lupetto build <package> (<selector> | --apk-version <apkVersion>) --json`. For `publish` it adds `--no-load` only when the latest local inventory does not report Docker as available (decided once at submission and kept in the job's request as `load`/`loadReason`); otherwise the one CLI run loads, then publishes and signs/attests when configured, so a load failure fails the build before publication. Publication and signing follow the inherited environment and are shown by `Record.Request.Publish`/`Sign`/`Load`. `local` loads only, with publication and signing suppressed. Products edits run `lupetto products add|remove --products <file> --json`; they are not gated by `--enable-builds`.

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

## Signature checks

Explorer never verifies signatures itself. With `LUPETTO_COSIGN_PUBLIC_KEY` set in its environment it runs `lupetto verify --json <repository>@<digest>` in the background, adding `--cosign-allow-http` only when its own environment has `LUPETTO_COSIGN_ALLOW_HTTP=true` and the reference's registry is a literal loopback host. The key path is inherited through the environment and never appears in arguments. Only `kind: "verify"`, `version: 1` documents that echo the requested reference and digest and use the documented enumerations are accepted; anything else, and CLI exit codes 1/2, becomes an `error` result.

- At most two checks run at once, one per image reference at a time; pages never wait for them. Newest registry images are queued after each status refresh; detail pages queue the images they show.
- Results are cached per process by trusted-key path and image reference: about 1 hour when the results are `signed` and `attested`, otherwise (unsigned, absent, invalid, error) about 5 minutes, so a transient failure reported as `invalid` does not stick. When the CLI reports a different `trust.publicKeySHA256` than before (key replaced at the same path), every cached result is discarded. An expired result stays visible with "rechecking" until the new one arrives.
- When a build finishes, results for every digest its record published, signed or attested are discarded (all results when the build left no usable record), so the next page shows "Checking…".

## Other routes

`GET /builds/{id}/sbom` downloads a local build's validated SPDX JSON (the `SPDXURL` fields). `GET /images/{package}/{selector}/sbom/{digest}` downloads a registry image's signed SPDX SBOM (`SignatureView.SBOMURL`): the digest must be `sha256:<64 hex>` (else `400`), the image must be in that track of the cached status (else `404`), and its cached result must be `attested` (else `409`, also when no key is configured). Explorer then verifies again with `--sbom-out` into a new private temporary directory, requires the fresh result to still be `attested` (`409` and the cache is updated if not) and the file's SHA-256 to equal `attestation.sbom.sha256` (`502` on mismatch, CLI failure or invalid JSON), and serves it as `application/spdx+json` attachment `lupetto-<name>-<version>-<digest12>.spdx.json`. The temporary file is always removed. At most two downloads run at once (`503` when busy); each has 25 seconds. `GET /healthz` returns `text/plain` `ok` (the process is serving; nothing more). `GET /static/<path>` serves embedded assets. There are no other routes.
