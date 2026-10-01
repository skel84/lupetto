# Explorer UI contract

This is the contract between the Explorer Go server (`internal/explorer`) and the dashboard UI, which consists of the templates in `web/templates/` and the assets in `web/static/`. It describes the behavior of the current source. The Go types it names are in [`models.go`](../models.go); that is the only Go file a UI author needs to read.

Explorer supervises the standalone `lupetto` CLI. The UI only presents CLI documents and Explorer job state. It must not compute security conclusions, choose versions or invent outcomes.

## Files and template names

- Templates are every `web/templates/*.html` file. Only the top level is read; subdirectories are ignored. All files are parsed into one `html/template` set when the server starts.
- The server runs templates **by defined name, not by file name**. The set must define at least these six names with `{{define "<name>"}}`; additional layout/partial names are allowed:

| Template | Route | Model (root `.`) |
| --- | --- | --- |
| `overview` | `GET /` | `OverviewView` |
| `track` | `GET /tracks/{package}/{selector}` | `TrackView` |
| `packages` | `GET /packages?q=` | `PackagesView` |
| `package` | `GET /packages/{name}` | `PackageView` |
| `jobs` | `GET /jobs` | `JobsView` |
| `job` | `GET /jobs/{id}` | `JobDetailView` |

- Shared layout and partials can live in any file. Every `define` name is global across the set: if two files define the same name, one silently replaces the other. Use unique names such as `layout-head` or `partial-stages`.
- No custom template functions are registered. Use only the built-in functions (`len`, `index`, `eq`, `ne`, `lt`, `le`, `gt`, `ge`, `and`, `or`, `not`, `printf`, `slice`, `urlquery`) and methods on the model values, for example `.Format` and `.IsZero` on `time.Time`.
- Output is buffered. If a template is missing, or execution fails, the server returns a plain-text `500` that contains the error, and no partial HTML is sent. If no `.html` files exist, every HTML page returns `500` with `Explorer template "<name>" is missing; dashboard UI is not installed`. The `?format=json` responses still work in that case.
- Static assets are served from `web/static/` at `GET /static/<path>`, for example `/static/app.css` and `/static/app.js`. Both directories are embedded in the binary, so there is no CDN or runtime file loading.
- `CONTRACT.md` and `.gitkeep` are not templates.

## Security constraints for UI authors

Every response carries these headers:

```
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cache-Control: no-store
```

Consequences:

- **The CSP blocks inline code.** No inline `<script>`, `on*=` handler attributes, `javascript:` URLs, `<style>` elements or `style="…"` attributes. Use external files under `/static/` only.
- No third-party origins of any kind (fonts, CDNs, analytics, images) and no `data:` images, because `default-src 'self'` applies. `fetch`/XHR is allowed to the same origin only.
- The page cannot be framed.
- Every string in every model can come from the CLI, a registry or a package index, so treat all of them as untrusted. Rely on `html/template` contextual escaping and never bypass it (the server never provides `template.HTML`). In JavaScript, insert text with `textContent`, never `innerHTML`.
- When the listener is a loopback address (the default is `127.0.0.1:8080`), any request whose `Host` is not loopback is rejected with `403`.

## Common model: `BaseView`

Every page model embeds `BaseView`, so its fields are available at the root (`{{.CSRFToken}}`, `{{.BuildsEnabled}}`). Inside `range` or `with`, use `$.CSRFToken` and `$.BuildsEnabled`.

| Field | Meaning |
| --- | --- |
| `CSRFToken string` | A random token per process. Include it in every POST form as the hidden field `csrfToken`. It changes on every restart, so a page loaded before a restart gets `403`. |
| `BuildsEnabled bool` | `false` unless Explorer was started with `--enable-builds`. When false, hide or disable the build and cancel controls; the server rejects builds with `403` anyway. |

## Read-only JSON (`?format=json`)

Adding `?format=json` to any of the six GET page routes returns the same model as `application/json`, using the JSON names in `models.go`. JSON responses are read-only; there are no JSON write endpoints. Notes:

- The JSON includes `csrfToken`. Same-origin JavaScript may read it from there or from a `<meta>` element rendered by the template.
- Missing slices can be `null` in JSON and empty with `range` in templates. `OverviewView.tracks`, `PackagesView.packages` and `JobsView.jobs` are always arrays.
- `?format=json` has no effect on the error responses described below; those stay plain text.

## Time values

- Pointer fields can be `nil`: `JobView.EndedAt *time.Time` and `JobView.ExitCode *int` are both nil while a job runs. Guard them with `with` before use, e.g. `{{with .EndedAt}}{{.Format "2006-01-02 15:04:05 MST"}}{{end}}`; inside the guard, methods such as `.Format` are valid. Do not use `eq` on the pointers directly.
- `{{with .ExitCode}}` tests the pointer, not the number: a zero exit code is a non-nil pointer, so the block runs and `{{.}}` prints `0`. Do not treat exit code `0` as missing.
- Non-pointer times (`StatusDocument.ComputedAt`, `Image.Created`, `JobView.StartedAt`) can be the zero value when the CLI omits them. Check `.IsZero` before displaying them.
- `ExitCode` can be `-1` when the process never started or its state is unknown.
- All Explorer times are UTC.

## Pages

### `overview`: `OverviewView`

```
OverviewView { BaseView; Status StatusView; Tracks []TrackSummary }
StatusView   { Document *StatusDocument; LastError string; Refreshing bool }
TrackSummary { Track Track; DetailURL string; OutdatedCount, ReachableFixCount, UnreachableFixCount, UnevaluatedFixCount int }
```

- `Status.Document` is nil until the first successful `lupetto status --products … --json`.
- If a later refresh fails, `LastError` is set and **`Document` keeps the previous successful document**. Show `LastError` together with the stale data and `Document.ComputedAt`.
- `Refreshing` is true while a status run is in progress.
- Status refreshes run in the background: at startup, every refresh interval (default 15 minutes), after each build ends, and on `POST /status/refresh`. Nothing pushes updates to the page. Reload it, or poll `/?format=json`.
- Link each track with `DetailURL`, which the server has already escaped. Do not build track URLs yourself.
- `ReachableFixCount` counts missing fixes the CLI marks reachable: top-level fixes are reachable through the track's selected APK; dependency fixes use same-name/same-architecture availability in the current index. This is not a solved future dependency lock or a guarantee that rebuilding picks up the fix; the rebuild may fail. `UnreachableFixCount` counts fixes for the top-level package that need a version outside this track's selector.
- Document header fields: `Architecture`, `Registry`, `Repository`, `IndexSHA256`, `ComputedAt` and `Security` (see [Security evidence](#security-evidence-required-wording)).

### `track`: `TrackView`

```
TrackView { BaseView; Status StatusView; Track Track }
Track {
  Package, Selector, State, Error, Repository string
  Latest *PackageIdentity            // nil when the index selection is unavailable
  Images []Image; Newest *Image      // Newest is nil when no images exist
  Installed []PackageIdentity
  Outdated []OutdatedPackage
  MissingFixes []MissingFix
  UnevaluatedFixes []UnevaluatedFix
  ArtifactCount, UnidentifiedCount int
}
PackageIdentity { Name, Version, Architecture string }
Image           { Digest string; Tags []string; Name, Version, Architecture string; Created time.Time; Annotations map[string]string }
OutdatedPackage { Name, Architecture, InstalledVersion, LatestVersion string }
MissingFix      { Name, Architecture, InstalledVersion, FixedVersion, AvailableVersion string; IDs []string; ReachableByTrack bool }
UnevaluatedFix  { Name, InstalledVersion, Architecture, FixedVersion string; IDs []string }
```

- If the track is not in the cached status, the route returns a plain-text `404`: `track is not present in cached status; wait for or request a refresh`.
- `State` is one of `not-built`, `update-available`, `fixes-available`, `current` or `error`. Display `Error` whenever it is not empty.
- `ArtifactCount` and `UnidentifiedCount` count unique registry manifest digests (not tags) that are not shown as images. Display them when they are nonzero; they are not errors.
- `Annotations` is a map, and `range` visits its keys in sorted order.
- `Status` is included so the page can show the security source and how fresh the data is.

### `packages`: `PackagesView`

```
PackagesView { BaseView; Query string; Packages []PackageItem; TotalMatches, Limit int; Document *DiscoverDocument; LastError string; Refreshing bool }
PackageItem  { DiscoveredPackage; DetailURL string }        // DiscoveredPackage { Name, Version, Description string }
DiscoverDocument { Kind string; Version int; Package, Architecture, IndexSHA256 string; Packages []DiscoveredPackage }
```

- Search uses a GET form with the single field `q`, so it needs no CSRF token. A `q` longer than 256 bytes returns a plain-text `400`.
- Matching is a case-insensitive substring match on **name or description**. An empty `q` matches every package.
- `Packages` is capped at `Limit` (200). `TotalMatches` is the full number of matches. When `TotalMatches > Limit`, tell the user the results are truncated.
- `Document` holds metadata only: `Document.Packages` is always nil. Use `Architecture` and `IndexSHA256` from it.
- If discovery has never loaded, the request starts it in the background and returns with `Refreshing` true. In that state `Document` is nil and `Packages` is empty; that means "not loaded yet", not "no matches". `LastError` contains the last discovery failure.

### `package`: `PackageView`

```
PackageView { BaseView; Name string; Document *DiscoverDocument; Error string }
```

- The route runs `lupetto discover --json <name>` synchronously, with a 25-second limit. An invalid name returns a plain-text `400`.
- At most four package-detail discovery calls run concurrently. When all four slots are busy, the route returns a plain-text `503` (`package discovery is busy; retry shortly`) instead of queueing.
- `Document` is nil when `Error` is set. Display `Error` verbatim.
- `Document.Packages` lists the exact available versions (`Name`, `Version`, `Description`) for `Name`, which can be a package or a provider such as `cmd:curl`.
- An exact-build form per entry should send `package` = the requested `PackageView.Name` (preserving a provider such as `cmd:curl`) and `apkVersion` = entry `Version` (see [Build](#post-builds)). The entry's actual `Name` is also a valid `package`, but use the requested name by default.

### `jobs`: `JobsView`

```
JobsView { BaseView; Jobs []JobView; Running bool; HistoryLimit int }
JobView  { ID string; Request BuildRequest; State string; StartedAt time.Time; EndedAt *time.Time; ExitCode *int; Record *BuildRecord; Error string; CancelRequested bool }
BuildRequest { Package, Selector, APKVersion string }   // exactly one of Selector/APKVersion is set
```

- `Jobs` is ordered newest first.
- **Job history is held in memory only.** It keeps the 50 most recent jobs (`HistoryLimit`) and is lost when Explorer restarts. Tell the user this.
- Job IDs are decimal sequence numbers that restart at `1` in each process, so an old link can point to a different job after a restart.
- Only one build runs at a time. While `Running` is true, disable the build controls.
- `State` is one of `running`, `succeeded`, `failed` or `canceled`.

### `job`: `JobDetailView`

```
JobDetailView { BaseView; Job JobView; Log LogChunk }
LogChunk      { Offset, NextOffset int64; Text string; Truncated, Done bool }
```

- An unknown ID returns a plain-text `404`.
- `Log` holds the retained stderr tail starting at offset 0. If earlier output was discarded, `Truncated` is true.
- Start live polling from `Log.NextOffset`. Polling is needed only while `Log.Done` is false.
- `Job.Error` is Explorer's diagnostic. Display it verbatim. It can be set even when a `Record` exists.
- `CancelRequested` is true after a cancel request or a shutdown, which can happen before the state becomes `canceled`. Show it as "cancellation requested".
- `canceled` means: "build canceled; external side effects may remain".
- Show **both** Explorer's `Job.State` and the CLI's `Record.Outcome`, and never infer success from either one alone (see [Build records](#build-records)).

## Log polling: `GET /jobs/{id}/logs?offset=N`

The response is always `application/json` in the `LogChunk` shape. It is not a template.

- `offset` is an **absolute byte position** in the job's stderr since the job started. Omitting it means `0`. A negative or non-integer value returns a plain-text `400`. An unknown job returns `404`.
- The server keeps only the most recent **1 MiB** of stderr. Offsets keep counting after older bytes are discarded.
  - If `N` is older than the retained tail, the response starts at the oldest retained byte and has `"truncated": true`. Show a "earlier output discarded" marker.
  - If `N` is beyond the end, it is clamped to the end and `text` is empty.
- Response fields:
  - `offset`: where `text` actually starts.
  - `nextOffset`: the total number of bytes written so far; use it as the next request's `offset`.
  - `text`: the bytes from `offset` to the end.
  - `done`: true when the job is no longer `running`.
- Polling loop: append `text`, set `offset = nextOffset`, and repeat (an interval of about 1–2 seconds is enough) until a response has `done: true`. That response already contains the final bytes, so stop after appending it. Then reload or fetch `/jobs/{id}?format=json` to get the final `Job`, which includes its `Record`.
- `text` can start or end in the middle of a line or a multibyte character, and invalid UTF-8 becomes `U+FFFD`. Append it with `textContent` only.
- stderr contains the CLI's progress output and the actual CLI/tool diagnostics (e.g. apko, registry, signing errors). It is not the result: the CLI's machine-readable result is `Job.Record`; never infer an outcome from log text.

## POST actions

All POSTs share these rules:

- The body must be `application/x-www-form-urlencoded`, which is the default for an HTML `<form method="post">`. **Multipart bodies are not parsed**: a `FormData` body sent with `fetch` fails CSRF. Use `URLSearchParams` instead.
- The body is limited to 8 KiB.
- Include `csrfToken` **in the body**. A token in the query string is ignored. Each field must appear exactly once; a duplicated field counts as empty.
- The request must be same-origin. If `Origin` is present, its scheme must be `http` or `https` and its authority must exactly equal the request `Host`, including any port (no path, query or userinfo). Either scheme is accepted so a TLS-terminating ingress that forwards plain HTTP works; no forwarded headers (`X-Forwarded-*`, `Forwarded`) are trusted. Without `Origin`, `Sec-Fetch-Site: same-origin` is required. Any `Sec-Fetch-Site` other than `same-origin` is rejected. Ordinary same-origin form posts from browsers satisfy this because the server sends `Referrer-Policy: same-origin`: under `no-referrer`, browsers send `Origin: null` on form posts, and `Origin: null` is always rejected (do not set a stricter referrer policy in templates). `same-origin` still sends no referrer to any other origin.
- Success returns `303 See Other`. Failures return plain-text errors (not templates). A JavaScript caller should display the response text.

| Action | Fields | Success | Errors |
| --- | --- | --- | --- |
| `POST /status/refresh` | `csrfToken` | 303 → `/`. The refresh is asynchronous; if one is already running, no new run starts. | 403 origin/CSRF; 400 bad form |
| `POST /builds` | `csrfToken`, `package`, and **exactly one** non-empty `selector` or `apkVersion` | 303 → `/jobs/{id}` | 400 validation; 403 builds disabled or origin/CSRF; 409 a build is already running; 503 shutting down |
| `POST /jobs/{id}/cancel` | `csrfToken` | 303 → `/jobs/{id}` | 404 unknown job; 409 job no longer running; 403 origin/CSRF |

### `POST /builds`

The server validates these fields, and the UI may mirror the rules in HTML `pattern` and `maxlength` attributes:

- `package`: at most 256 bytes; `^[A-Za-z0-9][A-Za-z0-9+._-]*(?::[A-Za-z0-9][A-Za-z0-9+._-]*)*$` (APK names or providers such as `cmd:curl`).
- `selector`: at most 128 bytes; dotted numeric, `^[0-9]+(?:\.[0-9]+)*$`. Use this for a major or minor track build.
- `apkVersion`: at most 256 bytes; an exact APK version ending in `-r<digits>`. Use this for an exact build.

Sending an empty `selector` together with a filled `apkVersion` (or the reverse) is valid.

Explorer always runs `lupetto build <package> (<selector> | --apk-version <apkVersion>) --no-load --json`. The UI cannot request loading, publication or signing. Whether publication and signing were requested is shown by `Record.Request.Publish` and `Record.Request.Sign`.

## Build records

`Job.Record` is the CLI's version-6 record. It is **nil** when:

- the invocation was rejected (exit 2, no stdout),
- the output was incompatible, or
- the job was canceled before a record was printed.

It can be present on a `failed` job as a partial record.

```
BuildRecord     { Version int; Command, Outcome, Workspace string; Failure *RecordFailure; Request RecordRequest; Selection *RecordSelection; Evidence *RecordEvidence; Stages RecordStages }
RecordFailure   { Stage, Error string; SideEffectsPossible bool }
RecordRequest   { BuildRequest; Load, Publish, Sign bool }
RecordSelection { Package, Version, Architecture, IndexSHA256 string }
RecordEvidence  { ApkoVersion, ImageDirectory, ImageDigest, LockPath, SPDXPath, SPDXSHA256 string; SPDXValidated bool }
RecordStages    { Build, Load, Publication, Signing, Attestation StageOutcome }
StageOutcome    { Status, Reference, Digest, ImmutableReference, ImageReference, BuildReference, DockerImageID string; Verified, ReadableReferenceConfirmed bool }
```

- `Outcome` is `succeeded` or `failed`.
- `Selection` and `Evidence` can be nil. Show `Evidence.SPDXValidated` as given.
- **Render all five stages separately**, each with its own status. Never collapse them into a single "built" or "published" badge.
- `skipped` and `not-attempted` mean different things. Label them differently and do not call either a failure:
  - `skipped` means the stage **was not requested**.
  - `not-attempted` means the stage **was requested but not reached** because an earlier stage failed.
- Statuses by stage:
  - Build: `completed`, `failed` or `not-attempted`.
  - Load: `loaded`, `skipped`, `failed` or `not-attempted`. It is always `skipped` under Explorer.
  - Publication: `published`, `failed`, `skipped` or `not-attempted`.
  - Signing: `signed`, `failed`, `skipped` or `not-attempted`.
  - Attestation: `attested`, `failed`, `skipped` or `not-attempted`.
- **Partial success is not success.** For example, a record can have publication `published` with signing `failed` and attestation `not-attempted`, or signing `signed` with attestation `failed`. Show each confirmed stage as confirmed and the overall job as failed.
- Publication: show `Digest` and `ImmutableReference`. A `Digest` with `Verified` false means the push was captured but its identity was not verified. That is not a confirmed publication, and it is never a basis for signing.
- When `Failure` is present, show `Failure.Stage` and `Failure.Error`. If `SideEffectsPossible` is true, warn that local or remote side effects may remain (for example a pushed tag, signature or attestation) and that no rollback was attempted.
- `Workspace`, `LockPath` and `SPDXPath` are local filesystem paths. Show them as text, not links.

## Security evidence (required wording)

`StatusDocument.Security` (`SecuritySource`) has the fields `URL`, `SHA256`, `Unsigned`, `FixedOnly`, `WolfiOnly`, `UnevaluatedFixCount` and `UnevaluatedFixes`. The UI must:

- Always show the source `URL` and `SHA256`, and a warning for each true flag:
  - **Unsigned**: the feed is not signed.
  - **FixedOnly**: it lists fixed vulnerabilities only.
  - **WolfiOnly**: it covers Wolfi packages only.
- **Never show a clean result.** No "secure", "no vulnerabilities" or green all-clear status. An empty `MissingFixes` list only means "no known fixed-version advisories in this unsigned, fixed-only Wolfi feed". This is not a vulnerability scan.
- Treat `UnevaluatedFixCount > 0` (source-wide) and a non-empty `Track.UnevaluatedFixes` as explicit warnings. These entries have a fixed version or advisory IDs the CLI could not evaluate. List the entries; do not hide them.
- Even with unevaluated entries, the track `State` can still be `current`, and such a track must not look clean.
- Show reachable and unreachable missing fixes separately (`ReachableByTrack`; the counts are on `TrackSummary`):
  - **Reachable**: the CLI marks this fix reachable: top-level fixes are reachable through the track's selected APK; dependency fixes use index availability. This is not a solved future dependency lock or a guarantee that rebuilding picks up the fix; the rebuild may fail.
  - **Unreachable**: the fix for the top-level package needs a version beyond this track's selector.

## Other routes

`GET /static/<path>` serves the embedded assets (see [Files and template names](#files-and-template-names)). `GET /healthz` returns `text/plain` `ok`; it means only that the Explorer process is up and serving, not that status comparison, discovery or the CLI is healthy. There are no other routes.
