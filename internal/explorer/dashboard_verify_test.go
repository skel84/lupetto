package explorer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var verifyCheckedAt = time.Date(2026, 10, 2, 9, 0, 0, 0, time.UTC)

func testDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }
func verifyDoc(reference, signature, attestation, sbomSHA, transparencyLog string) string {
	d := VerifyDocument{Kind: "verify", Version: 1, Reference: reference, Digest: reference[len(reference)-71:], CheckedAt: verifyCheckedAt,
		Trust: VerifyTrust{PublicKeySHA256: strings.Repeat("c", 64)}, TransparencyLog: transparencyLog,
		Signature: VerifySignature{State: signature, Artifacts: 1}, Attestation: VerifyAttestation{State: attestation, Artifacts: 1}}
	if signature == "error" {
		d.Signature.Error = "signature verification could not complete"
	}
	if attestation == "attested" {
		d.Attestation.PredicateType = "https://spdx.dev/Document"
		d.Attestation.SBOM = &VerifySBOM{SHA256: sbomSHA, Packages: 2, Path: "__SBOM_PATH__"}
	}
	data, _ := json.Marshal(d)
	return string(data)
}

// signatureTrack has one image per digest letter; the first is the newest.
func signatureTrack(letters ...string) Track {
	track := fixtureTrack()
	track.Images = nil
	for i, letter := range letters {
		track.Images = append(track.Images, Image{Digest: testDigest(letter), Name: "curl", Version: "1." + string(rune('9'-i)) + "-r0", Architecture: "x86_64"})
	}
	newest := track.Images[0]
	track.Newest = &newest
	return track
}
func signatureEnv(t *testing.T, key bool) string {
	t.Helper()
	keyPath := ""
	if key {
		keyPath = filepath.Join(t.TempDir(), "trusted-cosign.pub")
	}
	t.Setenv("LUPETTO_COSIGN_PUBLIC_KEY", keyPath)
	t.Setenv("LUPETTO_COSIGN_ALLOW_HTTP", "")
	t.Setenv("COSIGN_PASSWORD", "hunter2-secret")
	t.Setenv("TMPDIR", t.TempDir())
	return keyPath
}
func callLines(t *testing.T, calls, prefix string) []string {
	t.Helper()
	data, err := os.ReadFile(calls)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	lines := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, prefix) {
			lines = append(lines, line)
		}
	}
	return lines
}
func imageJSON(t *testing.T, server *Server, path string) ImageView {
	t.Helper()
	w := request(server, "GET", path, nil)
	var view ImageView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil {
		t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
	}
	return view
}
func signatureStates(view ImageView) map[string]string {
	states := map[string]string{}
	for digest, signature := range view.Product.Signatures {
		states[digest[7:8]] = signature.State
	}
	return states
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func TestSignaturesWithoutTrustAreNeverVerified(t *testing.T) {
	signatureEnv(t, false)
	track := signatureTrack("a", "b")
	config := goodFake()
	config.Verify = map[string]string{track.Repository + "@" + testDigest("a"): verifyDoc(track.Repository+"@"+testDigest("a"), "signed", "attested", strings.Repeat("0", 64), "verified")}
	server, _, calls := testServer(t, config, false)
	document := &StatusDocument{Kind: "status", Version: 2, Tracks: []Track{track}}
	server.status.finish(document, nil)
	server.warmSignatures(document)

	w := request(server, "GET", "/?format=json", nil)
	var home ImagesView
	if err := json.Unmarshal(w.Body.Bytes(), &home); err != nil {
		t.Fatal(err)
	}
	if home.Shell.Signatures.Enabled || !strings.Contains(home.Shell.Signatures.Reason, "LUPETTO_COSIGN_PUBLIC_KEY") || home.SignaturesPending {
		t.Fatalf("shell: %+v pending=%v", home.Shell.Signatures, home.SignaturesPending)
	}
	if s := home.Products[0].NewestSignature; s == nil || s.State != "not-checked" || s.Label != "Not checked" || s.SBOMURL != "" {
		t.Fatalf("home signature: %+v", s)
	}
	view := imageJSON(t, server, "/images/cmd:curl/1?format=json")
	if states := signatureStates(view); states["a"] != "not-checked" || states["b"] != "not-checked" || view.SignaturesPending {
		t.Fatalf("detail: %v", states)
	}
	if view.Product.Verdict != "Up to date" {
		t.Fatalf("signature status changed verdict: %s", view.Product.Verdict)
	}
	for _, path := range []string{"/", "/images/cmd:curl/1"} {
		html := request(server, "GET", path, nil).Body.String()
		for _, want := range []string{"Signatures: Not checked.", "sig sig-not-checked", "LUPETTO_COSIGN_PUBLIC_KEY is not set"} {
			if !strings.Contains(html, want) {
				t.Fatalf("%s missing %q", path, want)
			}
		}
	}
	if w := request(server, "GET", "/images/cmd:curl/1/sbom/"+testDigest("a"), nil); w.Code != http.StatusConflict {
		t.Fatalf("sbom without trust: %d", w.Code)
	}
	if lines := callLines(t, calls, "verify"); len(lines) != 0 {
		t.Fatalf("verify ran without trust: %v", lines)
	}
}

func TestSignatureStatesArgvAndRendering(t *testing.T) {
	keyPath := signatureEnv(t, true)
	t.Setenv("LUPETTO_COSIGN_ALLOW_HTTP", "true")
	track := signatureTrack("a", "b", "c", "d", "e", "f")
	ref := func(letter string) string { return track.Repository + "@" + testDigest(letter) }
	incompatible := strings.Replace(verifyDoc(ref("e"), "signed", "absent", "", "verified"), `"version":1`, `"version":2`, 1)
	config := goodFake()
	config.VerifyDelay = 200
	config.VerifyEnvironment = filepath.Join(t.TempDir(), "env")
	config.Verify = map[string]string{
		ref("a"): verifyDoc(ref("a"), "signed", "attested", strings.Repeat("1", 64), "skipped-local"),
		ref("b"): verifyDoc(ref("b"), "unsigned", "absent", "", "verified"),
		ref("c"): verifyDoc(ref("c"), "invalid", "invalid", "", "verified"),
		ref("d"): verifyDoc(ref("d"), "error", "error", "", "verified"),
		ref("e"): incompatible,
		// "f" has no fixture: the fake CLI exits 1 (global failure, no JSON).
	}
	server, _, calls := testServer(t, config, false)
	server.status.finish(&StatusDocument{Kind: "status", Version: 2, Tracks: []Track{track}}, nil)

	view := imageJSON(t, server, "/images/cmd:curl/1?format=json")
	if !view.SignaturesPending || signatureStates(view)["a"] != "checking" {
		t.Fatalf("expected pending checks: %v", signatureStates(view))
	}
	if html := request(server, "GET", "/images/cmd:curl/1", nil).Body.String(); !strings.Contains(html, "Checking…") || !strings.Contains(html, `data-poll-field="signaturesPending"`) {
		t.Fatal("pending state not rendered")
	}
	want := map[string]string{"a": "signed", "b": "unsigned", "c": "invalid", "d": "error", "e": "error", "f": "error"}
	eventually(t, func() bool {
		states := signatureStates(imageJSON(t, server, "/images/cmd:curl/1?format=json"))
		for k, v := range want {
			if states[k] != v {
				return false
			}
		}
		return true
	})
	view = imageJSON(t, server, "/images/cmd:curl/1?format=json")
	a, e, f := view.Product.Signatures[testDigest("a")], view.Product.Signatures[testDigest("e")], view.Product.Signatures[testDigest("f")]
	if a.Label != "Signed" || a.Attestation != "attested" || !a.LocalOnly || a.SBOMURL != "/images/cmd:curl/1/sbom/"+testDigest("a") || a.SBOMPackages != 2 || !a.CheckedAt.Equal(verifyCheckedAt) {
		t.Fatalf("signed view: %+v", a)
	}
	if !strings.Contains(e.Detail, "incompatible lupetto CLI") || !strings.Contains(e.Detail, "version 2") {
		t.Fatalf("incompatible version accepted: %+v", e)
	}
	if !strings.Contains(f.Detail, "lupetto verify failed (exit 1)") || strings.Contains(f.Detail, "\n") {
		t.Fatalf("exit failure: %+v", f)
	}
	if b := view.Product.Signatures[testDigest("b")]; b.SBOMURL != "" || b.AttestationLabel != "No SBOM attestation" {
		t.Fatalf("unsigned view: %+v", b)
	}
	if view.Product.Verdict != "Up to date" || view.Product.VerdictKind != "ok" || view.SignaturesPending {
		t.Fatalf("verdict changed or still pending: %s %v", view.Product.Verdict, view.SignaturesPending)
	}

	html := request(server, "GET", "/images/cmd:curl/1", nil).Body.String()
	for _, want := range []string{"sig sig-signed", "sig sig-unsigned", "sig sig-invalid", "sig sig-error", "Unsigned", "Invalid", "SBOM attested", "No SBOM attestation", "Invalid SBOM attestation",
		"local only · no transparency log", `href="/images/cmd:curl/1/sbom/` + testDigest("a") + `" download`, "Download signed SBOM (SPDX JSON)", "signature verification could not complete"} {
		if !strings.Contains(html, want) {
			t.Errorf("detail missing %q", want)
		}
	}
	if strings.Contains(html, "Signatures: Not checked.") {
		t.Error("trust note shown while trust is configured")
	}
	w := request(server, "GET", "/?format=json", nil)
	var home ImagesView
	if err := json.Unmarshal(w.Body.Bytes(), &home); err != nil {
		t.Fatal(err)
	}
	if s := home.Products[0].NewestSignature; s == nil || s.State != "signed" || len(home.Products[0].Signatures) != 1 {
		t.Fatalf("home compact: %+v", home.Products[0])
	}
	if html := request(server, "GET", "/", nil).Body.String(); !strings.Contains(html, `<span class="where-line sig-line"><span class="sig sig-signed"`) {
		t.Error("home compact indicator missing")
	}
	packages := imageJSON(t, server, "/images/cmd:curl/1?tab=packages&version="+testDigest("a")+"&format=json")
	if packages.Packages.Signature == nil || packages.Packages.Signature.State != "signed" {
		t.Fatalf("packages signature: %+v", packages.Packages)
	}

	// Trust reaches the CLI only through the environment, never argv.
	lines := callLines(t, calls, "verify")
	if len(lines) != len(want) {
		t.Fatalf("verify calls: %v", lines)
	}
	for _, line := range lines {
		args := strings.Split(line, "|")
		if len(args) != 4 || args[1] != "--json" || args[2] != "--cosign-allow-http" || !digestReferencePattern.MatchString(args[3]) {
			t.Fatalf("argv: %q", line)
		}
		if strings.Contains(line, keyPath) || strings.Contains(line, "hunter2") || strings.Contains(line, "cosign.pub") {
			t.Fatalf("secret or key path in argv: %q", line)
		}
	}
	envs, _ := filepath.Glob(config.VerifyEnvironment + ".*")
	if len(envs) != len(want) {
		t.Fatalf("environment records: %v", envs)
	}
	for _, path := range envs {
		data, _ := os.ReadFile(path)
		var env map[string]string
		if json.Unmarshal(data, &env) != nil || env["key"] != keyPath {
			t.Fatalf("key not inherited through environment: %s", data)
		}
	}
}

func TestSignatureVerifySingleFlightAndBoundedConcurrency(t *testing.T) {
	signatureEnv(t, true)
	letters := []string{"a", "b", "c", "d", "e"}
	track := signatureTrack(letters...)
	config := goodFake()
	config.VerifyDelay = 700
	config.VerifyActive = t.TempDir()
	config.VerifyMax = verifyWorkers
	config.Verify = map[string]string{}
	for _, l := range letters {
		r := track.Repository + "@" + testDigest(l)
		config.Verify[r] = verifyDoc(r, "signed", "absent", "", "verified")
	}
	server, _, calls := testServer(t, config, false)
	// Load the Docker inventory first so page latency below excludes the
	// fake CLI's process start-up and measures only signature handling.
	if server.inventory(context.Background()).Document == nil {
		t.Fatal("inventory not loaded")
	}
	server.status.finish(&StatusDocument{Kind: "status", Version: 2, Tracks: []Track{track}}, nil)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			started := time.Now()
			request(server, "GET", "/images/cmd:curl/1?format=json", nil)
			request(server, "GET", "/?format=json", nil)
			if elapsed := time.Since(started); elapsed > 400*time.Millisecond {
				t.Errorf("page waited for verification: %v", elapsed)
			}
		}()
	}
	wg.Wait()
	if !imageJSON(t, server, "/images/cmd:curl/1?format=json").SignaturesPending {
		t.Fatal("verification finished before pages returned; pages may have blocked")
	}
	eventually(t, func() bool {
		for _, state := range signatureStates(imageJSON(t, server, "/images/cmd:curl/1?format=json")) {
			if state != "signed" {
				return false
			}
		}
		return true
	})
	if lines := callLines(t, calls, "verify"); len(lines) != len(letters) {
		t.Fatalf("not single-flight per digest: %d calls %v", len(lines), lines)
	}
	if _, err := os.Stat(config.VerifyActive + ".violation"); err == nil {
		t.Fatal("more than two verify processes ran at once")
	}
	if _, err := os.Stat(config.VerifyActive + ".parallel"); err != nil {
		t.Fatal("background verification did not use its two workers")
	}
}

func TestSignatureCacheTTLAndBuildInvalidation(t *testing.T) {
	signatureEnv(t, true)
	track := signatureTrack("a", "b")
	refA, refB := track.Repository+"@"+testDigest("a"), track.Repository+"@"+testDigest("b")
	config := goodFake()
	config.Verify = map[string]string{refA: verifyDoc(refA, "signed", "attested", strings.Repeat("1", 64), "verified"), refB: verifyDoc(refB, "unsigned", "absent", "", "verified")}
	config.Status = encodeFixture(t, StatusDocument{Kind: "status", Version: 2, Tracks: []Track{track}})
	config.Build = strings.ReplaceAll(goodRecord, "sha256:fixture", testDigest("a"))
	server, update, calls := testServer(t, config, true)
	clock := &testClock{t: time.Date(2026, 10, 2, 10, 0, 0, 0, time.UTC)}
	server.signatures.now = clock.now
	server.status.finish(&StatusDocument{Kind: "status", Version: 2, Tracks: []Track{track}}, nil)
	count := func(reference string) int { return len(callLines(t, calls, "verify|--json|"+reference)) }
	settled := func(a, b string) func() bool {
		return func() bool {
			view := imageJSON(t, server, "/images/cmd:curl/1?format=json")
			states := signatureStates(view)
			return states["a"] == a && states["b"] == b && !view.Product.Signatures[testDigest("a")].Rechecking && !view.Product.Signatures[testDigest("b")].Rechecking
		}
	}
	eventually(t, settled("signed", "unsigned"))
	if count(refA) != 1 || count(refB) != 1 {
		t.Fatalf("initial calls a=%d b=%d", count(refA), count(refB))
	}

	// Unsigned/absent results are short-lived; signed/attested ones are not.
	clock.add(verifyShortTTL + time.Minute)
	view := imageJSON(t, server, "/images/cmd:curl/1?format=json")
	if b := view.Product.Signatures[testDigest("b")]; b.State != "unsigned" {
		t.Fatalf("expired result not kept while rechecking: %+v", b)
	}
	eventually(t, func() bool { return count(refB) == 2 })
	eventually(t, settled("signed", "unsigned"))
	if count(refA) != 1 {
		t.Fatal("long-lived signed result rechecked early")
	}
	clock.add(verifyLongTTL)
	imageJSON(t, server, "/images/cmd:curl/1?format=json")
	eventually(t, func() bool { return count(refA) == 2 && count(refB) == 3 })
	eventually(t, settled("signed", "unsigned"))

	// A finished build that published digest a drops only a's result; the
	// following status refresh queues it again.
	update(func() fakeConfig {
		c := config
		c.Verify = map[string]string{refA: verifyDoc(refA, "invalid", "absent", "", "verified"), refB: config.Verify[refB]}
		return c
	}())
	w := request(server, "POST", "/builds", buildForm(server))
	if w.Code != http.StatusSeeOther {
		t.Fatalf("build: %d %s", w.Code, w.Body.String())
	}
	eventually(t, func() bool { _, running := server.jobs.list(); return !running && count(refA) == 3 })
	eventually(t, settled("invalid", "unsigned"))
	if count(refB) != 3 {
		t.Fatalf("unrelated digest invalidated: %d", count(refB))
	}

	// Invalidation during an in-flight check discards that result and checks again.
	update(func() fakeConfig { c := config; c.VerifyDelay = 400; return c }())
	server.invalidateSignatures(&BuildRecord{Stages: RecordStages{Publication: StageOutcome{Digest: testDigest("b")}}})
	imageJSON(t, server, "/images/cmd:curl/1?format=json")
	eventually(t, func() bool { return count(refB) == 4 })
	server.invalidateSignatures(&BuildRecord{Stages: RecordStages{Signing: StageOutcome{Digest: testDigest("b")}}})
	eventually(t, func() bool { return count(refB) == 5 })
	eventually(t, settled("invalid", "unsigned"))
	if count(refB) != 5 {
		t.Fatalf("in-flight invalidation calls: %d", count(refB))
	}
	// A build without a record has unknown registry side effects: drop all.
	server.invalidateSignatures(nil)
	imageJSON(t, server, "/images/cmd:curl/1?format=json")
	eventually(t, func() bool { return count(refA) == 4 && count(refB) == 6 })
	eventually(t, settled("signed", "unsigned"))

	// Invalid is short-lived: a transient Cosign/Rekor/TUF failure the CLI
	// reports as invalid must not hide a correct signature for long.
	invalidA := verifyDoc(refA, "invalid", "invalid", "", "verified")
	update(func() fakeConfig {
		c := config
		c.Verify = map[string]string{refA: invalidA, refB: config.Verify[refB]}
		return c
	}())
	server.invalidateSignatures(&BuildRecord{Stages: RecordStages{Publication: StageOutcome{Digest: testDigest("a")}}})
	imageJSON(t, server, "/images/cmd:curl/1?format=json")
	eventually(t, func() bool { return count(refA) == 5 })
	eventually(t, settled("invalid", "unsigned"))
	clock.add(verifyShortTTL + time.Minute)
	imageJSON(t, server, "/images/cmd:curl/1?format=json")
	eventually(t, func() bool { return count(refA) == 6 && count(refB) == 7 })
	eventually(t, settled("invalid", "unsigned"))

	// A key rotated in place (same path, new fingerprint) discards every
	// cached result, not only the one that revealed the new fingerprint.
	rotated := func(doc string) string {
		return strings.ReplaceAll(doc, strings.Repeat("c", 64), strings.Repeat("d", 64))
	}
	update(func() fakeConfig {
		c := config
		c.Verify = map[string]string{refA: rotated(invalidA), refB: rotated(config.Verify[refB])}
		return c
	}())
	server.invalidateSignatures(&BuildRecord{Stages: RecordStages{Publication: StageOutcome{Digest: testDigest("a")}}})
	imageJSON(t, server, "/images/cmd:curl/1?format=json")
	eventually(t, func() bool { return count(refA) == 7 })
	// The reset results are queued again when a page next shows them.
	imageJSON(t, server, "/images/cmd:curl/1?format=json")
	eventually(t, func() bool { return count(refB) == 8 })
	eventually(t, settled("invalid", "unsigned"))
	if count(refA) != 7 || count(refB) != 8 {
		t.Fatalf("calls after key rotation a=%d b=%d", count(refA), count(refB))
	}
}

func TestSignedSBOMDownload(t *testing.T) {
	signatureEnv(t, true)
	tmp := os.Getenv("TMPDIR")
	track := signatureTrack("a", "b")
	refA, refB := track.Repository+"@"+testDigest("a"), track.Repository+"@"+testDigest("b")
	sbom := `{"spdxVersion":"SPDX-2.3","name":"curl","packages":[]}`
	sum := sha256.Sum256([]byte(sbom))
	sha := hex.EncodeToString(sum[:])
	config := goodFake()
	config.VerifySBOM = sbom
	config.Verify = map[string]string{refA: verifyDoc(refA, "signed", "attested", sha, "verified"), refB: verifyDoc(refB, "signed", "absent", "", "verified")}
	server, update, calls := testServer(t, config, false)
	server.status.finish(&StatusDocument{Kind: "status", Version: 2, Tracks: []Track{track}}, nil)
	sbomURL := "/images/cmd:curl/1/sbom/"

	for path, code := range map[string]int{
		sbomURL + testDigest("a"):                 http.StatusConflict, // not verified yet
		sbomURL + "sha256:ABC":                    http.StatusBadRequest,
		sbomURL + "..%2f..%2fetc%2fpasswd":        http.StatusBadRequest,
		sbomURL + testDigest("9"):                 http.StatusNotFound,
		"/images/nginx/1/sbom/" + testDigest("a"): http.StatusNotFound,
	} {
		if w := request(server, "GET", path, nil); w.Code != code {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
	}
	if lines := callLines(t, calls, "verify"); len(lines) != 0 {
		t.Fatalf("unverified download invoked the CLI: %v", lines)
	}
	imageJSON(t, server, "/images/cmd:curl/1?format=json")
	eventually(t, func() bool {
		states := imageJSON(t, server, "/images/cmd:curl/1?format=json").Product.Signatures
		return states[testDigest("a")].Attestation == "attested" && states[testDigest("b")].Attestation == "absent"
	})
	if w := request(server, "GET", sbomURL+testDigest("b"), nil); w.Code != http.StatusConflict {
		t.Fatalf("absent attestation served: %d", w.Code)
	}
	if lines := callLines(t, calls, "verify"); len(lines) != 2 {
		t.Fatalf("absent download invoked the CLI: %v", lines)
	}
	empty := func() {
		t.Helper()
		entries, err := os.ReadDir(tmp)
		if err != nil || len(entries) != 0 {
			t.Fatalf("temporary SBOM files remain: %v %v", entries, err)
		}
	}

	w := request(server, "GET", sbomURL+testDigest("a"), nil)
	if w.Code != 200 || w.Body.String() != sbom || w.Header().Get("Content-Type") != "application/spdx+json" ||
		w.Header().Get("Content-Disposition") != `attachment; filename="lupetto-curl-1.9-r0-aaaaaaaaaaaa.spdx.json"` || w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("download: %d %v %s", w.Code, w.Header(), w.Body.String())
	}
	lines := callLines(t, calls, "verify")
	last := strings.Split(lines[len(lines)-1], "|")
	if len(last) != 5 || last[2] != "--sbom-out" || !strings.HasPrefix(last[3], tmp) || last[4] != refA {
		t.Fatalf("fresh verify argv: %v", last)
	}
	if _, err := os.Stat(last[3]); !os.IsNotExist(err) {
		t.Fatalf("temporary SBOM not removed: %v", err)
	}
	empty()

	// The served bytes must match the SHA-256 the fresh verification reports.
	update(func() fakeConfig {
		c := config
		c.Verify = map[string]string{refA: verifyDoc(refA, "signed", "attested", strings.Repeat("f", 64), "verified"), refB: config.Verify[refB]}
		return c
	}())
	if w := request(server, "GET", sbomURL+testDigest("a"), nil); w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "spdxVersion") {
		t.Fatalf("checksum mismatch served: %d %s", w.Code, w.Body.String())
	}
	empty()

	// A CLI failure during the fresh check is an error, not cached bytes.
	update(func() fakeConfig { c := config; c.VerifyExit = 1; return c }())
	if w := request(server, "GET", sbomURL+testDigest("a"), nil); w.Code != http.StatusBadGateway {
		t.Fatalf("failed fresh verification: %d", w.Code)
	}
	empty()

	// The attestation is no longer verified: refuse, and remember the new state.
	update(func() fakeConfig {
		c := config
		c.Verify = map[string]string{refA: verifyDoc(refA, "signed", "invalid", "", "verified"), refB: config.Verify[refB]}
		return c
	}())
	if w := request(server, "GET", sbomURL+testDigest("a"), nil); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "no longer verified") {
		t.Fatalf("invalid attestation served: %d %s", w.Code, w.Body.String())
	}
	before := len(callLines(t, calls, "verify"))
	if w := request(server, "GET", sbomURL+testDigest("a"), nil); w.Code != http.StatusConflict || len(callLines(t, calls, "verify")) != before {
		t.Fatalf("stale attested cache used: %d", w.Code)
	}
	empty()
}

func TestVerifyCLIContract(t *testing.T) {
	signatureEnv(t, true)
	reference := "127.0.0.1:5000/team/curl@" + testDigest("a")
	remote := "harbor.example.invalid/lupetto/images/curl@" + testDigest("a")
	config := goodFake()
	config.Verify = map[string]string{remote: verifyDoc(remote, "signed", "absent", "", "verified")}
	binary, update, calls := fakeCLI(t, config)
	cli, err := NewCLI(binary)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := cli.Verify(ctx, remote, "", true); err != nil {
		t.Fatal(err)
	}
	if lines := callLines(t, calls, "verify"); len(lines) != 1 || lines[0] != "verify|--json|"+remote {
		t.Fatalf("remote registry must not get the local HTTP flag: %v", lines)
	}
	for name, document := range map[string]string{
		"kind":        strings.Replace(verifyDoc(reference, "signed", "absent", "", "verified"), `"kind":"verify"`, `"kind":"inspect"`, 1),
		"version":     strings.Replace(verifyDoc(reference, "signed", "absent", "", "verified"), `"version":1`, `"version":2`, 1),
		"reference":   verifyDoc("127.0.0.1:5000/team/other@"+testDigest("a"), "signed", "absent", "", "verified"),
		"signature":   verifyDoc(reference, "trusted", "absent", "", "verified"),
		"attestation": verifyDoc(reference, "signed", "present", "", "verified"),
		"tlog":        verifyDoc(reference, "signed", "absent", "", "ignored"),
		"sbom":        strings.Replace(verifyDoc(reference, "signed", "attested", strings.Repeat("1", 64), "verified"), strings.Repeat("1", 64), "nothex", 1),
		"extra":       verifyDoc(reference, "signed", "absent", "", "verified") + "{}",
	} {
		update(func() fakeConfig { c := config; c.Verify = map[string]string{reference: document}; return c }())
		if _, err := cli.Verify(ctx, reference, "", false); err == nil || !strings.Contains(err.Error(), "incompatible lupetto CLI") {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	// Requested --sbom-out must be reported as written.
	update(func() fakeConfig {
		c := config
		c.Verify = map[string]string{reference: strings.Replace(verifyDoc(reference, "signed", "attested", strings.Repeat("1", 64), "verified"), `"__SBOM_PATH__"`, `"/elsewhere"`, 1)}
		return c
	}())
	if _, err := cli.Verify(ctx, reference, filepath.Join(t.TempDir(), "out.json"), false); err == nil {
		t.Error("unreported --sbom-out accepted")
	}
	before := len(callLines(t, calls, "verify"))
	for _, bad := range []string{"127.0.0.1:5000/team/curl:latest", "--sbom-out=/x", "curl@" + testDigest("a"), "127.0.0.1:5000/team/curl@sha256:ABC"} {
		if _, err := cli.Verify(ctx, bad, "", false); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if _, err := cli.Verify(ctx, reference, "relative.json", false); err == nil {
		t.Error("relative --sbom-out accepted")
	}
	if len(callLines(t, calls, "verify")) != before {
		t.Fatal("invalid input invoked the CLI")
	}
	for authority, loopback := range map[string]bool{"127.0.0.1:5000": true, "localhost:5000": true, "[::1]:5000": true, "localhost": true, "127.0.0.2": true, "harbor.example.invalid": false, "10.0.0.1:5000": false, "localhost.example.invalid": false} {
		if loopbackReference(authority+"/x@"+testDigest("a")) != loopback {
			t.Errorf("loopback(%s) != %v", authority, loopback)
		}
	}
	if name := signedSBOMFilename(Image{Digest: testDigest("a"), Name: `cu"rl/../x`, Version: "1.0-r0\r\n"}); name != "lupetto-cu_rl_.._x-1.0-r0__-aaaaaaaaaaaa.spdx.json" {
		t.Errorf("filename: %s", name)
	}
}

func TestEmbeddedTemplatesShowSignatureStates(t *testing.T) {
	created := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	digest := testDigest("a")
	image := Image{Digest: digest, Name: "curl", Version: "1.9-r0", Architecture: "x86_64", Created: created}
	track := Track{Package: "curl", Selector: "1", State: "current", Repository: "harbor.example.invalid/lupetto/curl", Images: []Image{image}, Newest: &image}
	base := BaseView{CSRFToken: "tok-123", Shell: ShellView{Signatures: SignatureConfigView{Enabled: true}}}
	evil := `<script>alert(1)</script>`
	states := map[string]*SignatureView{
		"signed":      {State: "signed", Label: "Signed", Attestation: "attested", AttestationLabel: "SBOM attested", SBOMURL: "/images/curl/1/sbom/" + digest, SBOMPackages: 12, CheckedAt: created, KeySHA256: strings.Repeat("c", 64)},
		"local":       {State: "signed", Label: "Signed", Attestation: "absent", AttestationLabel: "No SBOM attestation", LocalOnly: true, TransparencyLog: "skipped-local", CheckedAt: created},
		"unsigned":    {State: "unsigned", Label: "Unsigned", Attestation: "absent", AttestationLabel: "No SBOM attestation", CheckedAt: created},
		"invalid":     {State: "invalid", Label: "Invalid", Attestation: "invalid", AttestationLabel: "Invalid SBOM attestation", CheckedAt: created},
		"error":       {State: "error", Label: "Error", Detail: evil, CheckedAt: created},
		"checking":    {State: "checking", Label: "Checking…", Detail: "Verification is running in the background."},
		"not-checked": {State: "not-checked", Label: "Not checked yet"},
	}
	cases := []templateCase{}
	for name, signature := range states {
		row := ProductRow{Package: "curl", Selector: "1", Track: track, DetailURL: "/images/curl/1", Verdict: "Up to date", VerdictKind: "ok", Signatures: map[string]*SignatureView{digest: signature}, NewestSignature: signature}
		want := []string{`class="sig sig-` + map[bool]string{true: "signed", false: signature.State}[name == "local"] + `"`, signature.Label}
		absent := []string{"Signatures: Not checked."}
		if name == "local" {
			want = append(want, "local only · no transparency log")
		} else {
			absent = append(absent, "no transparency log")
		}
		cases = append(cases, templateCase{"images " + name, "images", ImagesView{BaseView: base, Status: StatusView{Document: &StatusDocument{}}, Groups: []ProductGroup{{Package: "curl", DetailURL: "/images/curl/1", Rows: []ProductRow{row}}}, Summary: ImagesSummary{All: 1}, SignaturesPending: name == "checking"}, want, absent})
		detailWant := append([]string{}, want...)
		detailAbsent := []string{}
		if signature.SBOMURL != "" {
			detailWant = append(detailWant, `href="/images/curl/1/sbom/`+digest+`" download`, "SBOM attested", "12 packages", "Download signed SBOM (SPDX JSON)")
		} else {
			detailAbsent = append(detailAbsent, "Download signed SBOM")
		}
		if name == "error" {
			detailWant = append(detailWant, "&lt;script&gt;alert(1)&lt;/script&gt;")
		}
		if name == "checking" {
			detailWant = append(detailWant, `data-poll-url="/images/curl/1?format=json" data-poll-field="signaturesPending"`)
		}
		cases = append(cases, templateCase{"image " + name, "image", ImageView{BaseView: base, Product: row, Tab: "overview", SignaturesPending: name == "checking"}, detailWant, detailAbsent})
		set := PackageSet{Key: digest, Label: "1.9-r0 · registry", Source: "registry", Packages: []PackageIdentity{{Name: "curl", Version: "1.9-r0", Architecture: "x86_64"}}, Signature: signature}
		packagesWant := []string{"Packages read from the registry image"}
		if signature.SBOMURL != "" {
			packagesWant = append(packagesWant, "Download signed SBOM (SPDX JSON)", "downloading verifies it again first")
		}
		cases = append(cases, templateCase{"packages " + name, "image", ImageView{BaseView: base, Product: row, Tab: "packages", Versions: []PackageSet{set}, Packages: set}, packagesWant, detailAbsent})
	}
	disabled := BaseView{CSRFToken: "tok-123", Shell: ShellView{Signatures: SignatureConfigView{Reason: "No trusted public key is configured (LUPETTO_COSIGN_PUBLIC_KEY is not set), so signatures are not checked."}}}
	notChecked := &SignatureView{State: "not-checked", Label: "Not checked", Detail: disabled.Shell.Signatures.Reason}
	row := ProductRow{Package: "curl", Selector: "1", Track: track, DetailURL: "/images/curl/1", Verdict: "Up to date", VerdictKind: "ok", Signatures: map[string]*SignatureView{digest: notChecked}, NewestSignature: notChecked}
	set := PackageSet{Key: digest, Source: "registry", Signature: notChecked}
	cases = append(cases,
		templateCase{"images no trust", "images", ImagesView{BaseView: disabled, Status: StatusView{Document: &StatusDocument{}}, Groups: []ProductGroup{{Package: "curl", Rows: []ProductRow{row}}}, Summary: ImagesSummary{All: 1}},
			[]string{"Signatures: Not checked.", "LUPETTO_COSIGN_PUBLIC_KEY is not set", "sig sig-not-checked"}, []string{"Signed SBOM", "signaturesPending"}},
		templateCase{"image no trust", "image", ImageView{BaseView: disabled, Product: row, Tab: "overview"}, []string{"Signatures: Not checked.", ">Not checked</span>"}, []string{"Download signed SBOM"}},
		templateCase{"packages no trust", "image", ImageView{BaseView: disabled, Product: row, Tab: "packages", Versions: []PackageSet{set}, Packages: set}, []string{"Its signature and SBOM attestation are not checked: No trusted public key"}, []string{"Download signed SBOM"}},
	)
	renderCases(t, cases)
}
