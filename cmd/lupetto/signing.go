package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/distribution/reference"
)

const cosignSigningVersion = "v3.1.3"

var cosignReleaseVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

// Unlike the local command adapter, this adapter never captures or streams
// secret-bearing signing diagnostics. A nil Env deliberately inherits the
// process environment, including COSIGN_PASSWORD, without inspecting it.
func executeSigningCommand(ctx context.Context, executable string, args ...string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if executable != "cosign" || len(args) == 0 {
		return nil, errors.New("unsupported signing command")
	}
	command := exec.CommandContext(ctx, executable, args...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	var version *boundedIdentityOutput
	switch args[0] {
	case "version":
		if len(args) != 2 || args[1] != "--json" {
			return nil, errors.New("invalid Cosign version command")
		}
		version = &boundedIdentityOutput{}
		command.Stdout = version
	case "sign", "attest":
	default:
		return nil, errors.New("unsupported signing command")
	}
	if err := command.Run(); err != nil {
		return nil, safeStageError(ctx, "Cosign "+args[0], err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if version == nil {
		return nil, nil
	}
	var release struct {
		GitVersion string `json:"gitVersion"`
	}
	if version.overflow || json.Unmarshal(version.data, &release) != nil || !cosignReleaseVersion.MatchString(release.GitVersion) {
		return nil, errors.New("invalid Cosign version output")
	}
	// Return only the validated version, never other fields or raw JSON.
	return []byte(release.GitVersion), nil
}

func requireCosignVersion(ctx context.Context, command localCommand) error {
	if err := ctx.Err(); err != nil {
		return safeStageError(ctx, "Cosign version preflight", err)
	}
	if command == nil {
		return safeStageError(ctx, "Cosign version preflight", nil)
	}
	output, err := command(ctx, "cosign", "version", "--json")
	if err != nil || ctx.Err() != nil {
		return safeStageError(ctx, "Cosign version preflight", err)
	}
	if string(output) != cosignSigningVersion {
		return safeStageError(ctx, "Cosign v3.1.3 required", nil)
	}
	return nil
}

type signingOutcome struct {
	signing, attestation string
}

func verifiedSigningReference(result buildResult) bool {
	p := result.publication
	if p.status != "published" || !p.verified || !digestPattern.MatchString(p.pushedDigest) {
		return false
	}
	tag, err := reference.ParseNormalizedNamed(p.reference)
	if err != nil || tag.String() != p.reference {
		return false
	}
	named, ok := tag.(reference.NamedTagged)
	if !ok {
		return false
	}
	if _, digested := tag.(reference.Digested); digested {
		return false
	}
	immutable, err := reference.Parse(p.immutableReference)
	if err != nil {
		return false
	}
	canonical, ok := immutable.(reference.Canonical)
	if !ok {
		return false
	}
	return canonical.Name() == named.Name() && canonical.Digest().String() == p.pushedDigest &&
		p.immutableReference == named.Name()+"@"+p.pushedDigest
}

func signAndAttestDigest(ctx context.Context, command localCommand, result buildResult, opts signingOptions) (signingOutcome, error) {
	outcome := signingOutcome{signing: "skipped", attestation: "skipped"}
	if !opts.enabled() {
		return outcome, nil
	}
	outcome.signing, outcome.attestation = "failed", "not-attempted"
	fail := func(stage string, err error) (signingOutcome, error) {
		return outcome, safeStageError(ctx, stage, err)
	}
	if !verifiedSigningReference(result) {
		return fail("signing requires verified canonical pushed digest", nil)
	}
	target, _ := reference.ParseNormalizedNamed(result.publication.reference)
	path := reference.Path(target)
	slash := strings.LastIndexByte(path, '/')
	if slash <= 0 {
		return fail("signing target repository", nil)
	}
	if err := validateSigningOptions(opts, publicationOptions{registry: reference.Domain(target), repository: path[:slash]}, false); err != nil {
		return fail("signing configuration", err)
	}
	if err := ctx.Err(); err != nil {
		return fail("image signing", err)
	}
	if command == nil {
		return fail("image signing", nil)
	}
	common := []string{"--yes", "--key", opts.key}
	if opts.config != "" {
		common = append(common, "--signing-config", opts.config)
		buildMessage(ctx, "Cosign uses an operator-supplied custom service configuration")
	}
	if opts.allowHTTP {
		common = append(common, "--allow-http-registry")
		buildMessage(ctx, "Cosign loopback HTTP access explicitly enabled; local-development exception")
	}
	immutable := result.publication.immutableReference
	buildStage(ctx, "Signing verified immutable registry image")
	if err := ctx.Err(); err != nil {
		return fail("image signing", err)
	}
	signArgs := append([]string{"sign"}, common...)
	signArgs = append(signArgs, immutable)
	if _, err := command(ctx, "cosign", signArgs...); err != nil || ctx.Err() != nil {
		return fail("image signing", err)
	}
	outcome.signing, outcome.attestation = "signed", "failed"
	buildStage(ctx, "Attesting validated architecture SPDX")
	if err := ctx.Err(); err != nil {
		return fail("SPDX attestation", err)
	}
	// Use the already lock-validated architecture document, never the index SPDX
	// or regenerated evidence. Recheck its bytes immediately before the command.
	predicate, err := os.ReadFile(result.spdxPath)
	if err != nil {
		return fail("SPDX attestation predicate read", err)
	}
	if len(result.spdxSHA256) != 64 || sha256Hex(predicate) != result.spdxSHA256 {
		return fail("SPDX attestation predicate checksum", nil)
	}
	if err := ctx.Err(); err != nil {
		return fail("SPDX attestation", err)
	}
	attestArgs := append([]string{"attest"}, common...)
	attestArgs = append(attestArgs, "--type", "spdxjson", "--predicate", result.spdxPath, immutable)
	if _, err := command(ctx, "cosign", attestArgs...); err != nil || ctx.Err() != nil {
		return fail("SPDX attestation", err)
	}
	outcome.attestation = "attested"
	return outcome, nil
}
