package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"lupetto/internal/build"
	"lupetto/internal/storage"
	"lupetto/internal/wolfi"
)

const usage = "Usage:\n  lupetto doctor\n  lupetto discover <package-or-provider> [--arch <arch>]\n  lupetto discover --json [<package-or-provider>] [--arch <arch>]\n  lupetto build <package-or-provider> <major[.minor[.patch]]> [--arch <arch>] [--entrypoint <element>]... [--no-load] [--json] [--registry <authority> --repository <prefix>] [(--cosign-key <key> | --cosign-identity-token <file>) [--cosign-signing-config <file>] [--cosign-allow-http[=true|false]]] [--require-signing[=true|false]]\n  lupetto build <package-or-provider> --apk-version <exact-version> [--arch <arch>] [--entrypoint <element>]... [--no-load] [--json] [--registry <authority> --repository <prefix>] [(--cosign-key <key> | --cosign-identity-token <file>) [--cosign-signing-config <file>] [--cosign-allow-http[=true|false]]] [--require-signing[=true|false]]\n  lupetto sbom <package-or-provider> --apk-version <exact-version> [--arch <arch>] [--entrypoint <element>]... [--json]\n\nDiscover, build, and sbom target the host architecture unless --arch selects x86_64 (amd64) or aarch64 (arm64); one run builds one architecture.\nDiscover lists exact versions from the current signed Wolfi APKINDEX for the target architecture.\nDiscover --json prints a kind discover, version-1 document; without a name it lists each package's latest version and description.\nListed versions are not guaranteed buildable; builds validate apko dependencies and installed packages.\nA numeric selector chooses the highest matching APK version/revision; an exact version includes -rN.\nThe package name must match an APK name or a version-matched provider; ambiguous build matches fail.\nBuild and sbom compose a local OCI layout and validate apko SPDX against the lock.\nRepeat --entrypoint once per element, in order, to set the image ENTRYPOINT (the default is none); the first element is an absolute executable path\nthat must exist in the package closure, and an element starting with - needs the --entrypoint=<element> form. It is recorded in the image annotations and result record.\nBuild and sbom log stages and live tool diagnostics to stderr, with an ASCII spinner on interactive terminals.\nFor build and sbom, --json prints the version-6 result record (also retained as result.json or failure.json) to stdout instead of the summary.\nBuild loads Docker by default; --no-load skips loading. SBOM always skips loading.\nBuild and sbom create a private workspace under <data>/lupetto/builds, where <data> is LUPETTO_DATA_DIR (an absolute path) or the OS user data directory.\nBuild optionally publishes with --registry / LUPETTO_REGISTRY and --repository / LUPETTO_REPOSITORY.\nEach explicit flag independently overrides its environment input; both publication settings are required, and empty string flags are invalid.\nRegistry is an authority (not a URL); repository is a nested lower-case prefix such as team/lupetto/images.\nPublication pushes the validated OCI layout directly to the registry (with or without --no-load), using Docker's credential store/configuration (DOCKER_CONFIG or ~/.docker/config.json).\nThe pushed manifest, tag, config, and layers are read back by digest and verified before the immutable digest is reported.\nPlain HTTP registry access is used only for literal localhost or loopback IP registries.\nBuild optionally signs and attests the validated architecture SPDX to that same immutable digest using Cosign v3.1.3.\nSigning requires --cosign-key / LUPETTO_COSIGN_KEY and publication; there is no implicit keyless path.\nAn optional --cosign-signing-config / LUPETTO_COSIGN_SIGNING_CONFIG selects an upstream config file, not a Lupetto key store.\n--cosign-allow-http / LUPETTO_COSIGN_ALLOW_HTTP accepts only true or false; a valueless flag means true.\nExplicit false overrides environment true. HTTP allowance is restricted to literal localhost or loopback IP registries.\nPublishing without a Cosign key prints one warning on stderr: the image is pushed with no signature or SPDX attestation.\n--require-signing / LUPETTO_REQUIRE_SIGNING (true or false; a valueless flag means true; explicit false overrides environment true)\nrefuses that as invalid configuration (exit 2) before any tool, network, or workspace work; it does not affect builds that do not publish.\nSigning on literal loopback requires explicit effective HTTP consent, including when HTTPS might be available.\nProduction defaults preserve upstream HTTPS/TUF/transparency-log services; custom signing configs can change services.\nFor a local/offline exception, generate a no-service config with cosign signing-config create --out <file> (without --with-default-services).\nInherit COSIGN_PASSWORD only from the process environment; never pass or retain passwords, key/config contents, or Cosign diagnostics.\nRegistry error bodies and Cosign tool diagnostics are discarded. Publication, image signing, and SPDX attestation are reported separately.\nSBOM rejects publication and signing flags (including false/empty forms) and ignores publication and signing environment inputs."

var (
	apkVersion      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]*-r[0-9]+$`)
	numericSelector = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)
)

// cliRequest is the parsed invocation: the pipeline request plus CLI-only
// output selection and the raw flags that resolution consumed.
type cliRequest struct {
	build.Request
	json             bool
	publicationFlags build.PublicationFlags
	signingFlags     build.SigningFlags
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithBuild(ctx, args, stdout, stderr, func(ctx context.Context, request cliRequest) (build.Result, error) {
		return build.Run(ctx, request.Request)
	})
}

func runWithBuild(ctx context.Context, args []string, stdout, stderr io.Writer, runBuild func(context.Context, cliRequest) (build.Result, error)) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage+statusUsage+inspectUsage+verifyUsage+productsUsage+imagesUsage)
		return 2
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage+statusUsage+inspectUsage+verifyUsage+productsUsage+imagesUsage)
		return 0
	case "doctor":
		return runDoctor(stdout, stderr, args[1:])
	case "discover":
		return runDiscover(ctx, args[1:], stdout, stderr)
	case "status":
		return runStatus(ctx, args[1:], stdout, stderr)
	case "inspect":
		return runInspect(ctx, args[1:], stdout, stderr)
	case "verify":
		return runVerify(ctx, args[1:], stdout, stderr)
	case "products":
		return runProducts(args[1:], stdout, stderr)
	case "images":
		return runImages(ctx, args[1:], stdout, stderr)
	case "build", "sbom":
		request, err := parseBuild(args[1:])
		if err == nil && args[0] == "sbom" && request.NoLoad {
			err = fmt.Errorf("sbom does not accept --no-load")
		}
		if err == nil && args[0] == "sbom" && (request.publicationFlags.Registry.Set || request.publicationFlags.Repository.Set) {
			err = fmt.Errorf("sbom does not accept --registry or --repository")
		}
		if err == nil && args[0] == "sbom" && (request.signingFlags.Key.Set || request.signingFlags.Config.Set || request.signingFlags.IdentityTokenFile.Set || request.signingFlags.AllowHTTP.Set || request.signingFlags.Require.Set) {
			err = fmt.Errorf("sbom does not accept --cosign-key, --cosign-identity-token, --cosign-signing-config, --cosign-allow-http, or --require-signing")
		}
		if err == nil && args[0] == "sbom" && request.Version == "" {
			err = fmt.Errorf("sbom requires --apk-version with an exact APK revision")
		}
		if err == nil && args[0] == "build" {
			request.Publication, err = build.ResolvePublication(request.publicationFlags, os.LookupEnv)
			if err == nil {
				request.Signing, err = build.ResolveSigning(request.signingFlags, request.Publication, os.LookupEnv)
			}
		}
		if err == nil {
			// Workspaces are created under the data root; reject an invalid
			// LUPETTO_DATA_DIR before any tool, network, or workspace work.
			_, err = storage.DataDir()
		}
		if err != nil {
			fmt.Fprintf(stderr, "lupetto: %v\n", err)
			return 2
		}
		request.Command = args[0]
		if args[0] == "sbom" {
			request.NoLoad = true
		}
		if build.UnsignedPublication(request.Publication, request.Signing) {
			// Printed once, before the build starts and before any stage log.
			// It never reaches stdout, the --json document, or the record.
			fmt.Fprintln(stderr, "lupetto: "+build.UnsignedPublicationWarning)
		}
		progress := newBuildProgress(ctx, stderr, progressTerminal(stderr))
		defer progress.Close()
		buildCtx := build.WithReporter(ctx, progress)
		result, err := runBuild(buildCtx, request)
		progress.Close()
		if err != nil {
			if !reportWorkflowFailure(stderr, err) {
				fmt.Fprintf(stderr, "lupetto: %s\n", build.PlainText(err.Error()))
			}
			var failure *build.WorkflowFailure
			if request.json && errors.As(err, &failure) && len(failure.Record) != 0 {
				writeJSONRecord(stdout, stderr, failure.Record)
			}
			return 1
		}
		if request.json {
			record := result.Record
			if len(record) == 0 {
				// Only injected callbacks reach this; the pipeline always
				// returns the exact document it wrote to result.json.
				if record, err = build.EncodeRecord(result.RecordDocument(nil)); err != nil {
					fmt.Fprintln(stderr, "lupetto: could not write JSON result")
					return 1
				}
			}
			if !writeJSONRecord(stdout, stderr, record) {
				return 1
			}
			return 0
		}
		fmt.Fprintln(stdout, "Build completed")
		fmt.Fprintf(stdout, "Selected %s@%s (APKINDEX sha256:%s)\nOCI image: %s\nValidated SPDX: %s (sha256:%s)\nBuild evidence: %s\n", result.PackageName, result.Version, result.IndexSHA256, result.ImageDir, result.SPDXPath, result.SPDXSHA256, result.Workspace)
		fmt.Fprintf(stdout, "Image reference: %s\nBuild reference: %s\n", result.ImageReference, result.BuildReference)
		if result.DockerLoad == "loaded" {
			fmt.Fprintf(stdout, "Docker loaded: %s (image ID: %s)\n", result.ImageReference, result.DockerImageID)
		} else {
			fmt.Fprintln(stdout, "Docker loading: skipped")
		}
		if result.Publication.Status == "published" && result.Publication.Verified {
			fmt.Fprintf(stdout, "Registry published: %s\nImmutable reference: %s\n", result.Publication.Reference, result.Publication.ImmutableReference)
		} else {
			fmt.Fprintln(stdout, "Registry publication: skipped")
		}
		if result.Signing == "signed" {
			fmt.Fprintf(stdout, "Image signing: signed (%s)\n", result.Publication.ImmutableReference)
		} else {
			fmt.Fprintln(stdout, "Image signing: skipped")
		}
		if result.Attestation == "attested" {
			fmt.Fprintf(stdout, "SPDX attestation: attested (%s)\n", result.Publication.ImmutableReference)
		} else {
			fmt.Fprintln(stdout, "SPDX attestation: skipped")
		}
		return 0
	default:
		fmt.Fprintf(stderr, "lupetto: unknown command %q\n", args[0])
		return 2
	}
}

func writeJSONRecord(stdout, stderr io.Writer, record []byte) bool {
	if n, err := stdout.Write(record); err != nil || n != len(record) {
		fmt.Fprintln(stderr, "lupetto: could not write JSON result")
		return false
	}
	return true
}

func parseBuild(args []string) (cliRequest, error) {
	var request cliRequest
	var positional []string
	seenVersion, seenArch := false, false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--no-load":
			if request.NoLoad {
				return cliRequest{}, fmt.Errorf("--no-load may be specified only once")
			}
			request.NoLoad = true
		case arg == "--json":
			if request.json {
				return cliRequest{}, fmt.Errorf("--json may be specified only once")
			}
			request.json = true
		case arg == "--apk-version" || strings.HasPrefix(arg, "--apk-version="):
			if seenVersion {
				return cliRequest{}, fmt.Errorf("--apk-version may be specified only once")
			}
			seenVersion = true
			if arg == "--apk-version" {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return cliRequest{}, fmt.Errorf("--apk-version requires an exact APK version")
				}
				request.Version = args[i]
			} else {
				request.Version = strings.TrimPrefix(arg, "--apk-version=")
			}
		case arg == "--arch" || strings.HasPrefix(arg, "--arch="):
			if seenArch {
				return cliRequest{}, fmt.Errorf("--arch may be specified only once")
			}
			seenArch = true
			value, inline := strings.CutPrefix(arg, "--arch=")
			if !inline {
				i++
				if i == len(args) {
					return cliRequest{}, fmt.Errorf("--arch requires a value")
				}
				value = args[i]
			}
			arch, err := wolfi.ParseArch(value)
			if err != nil {
				return cliRequest{}, err
			}
			request.Arch = arch
		case arg == "--registry" || strings.HasPrefix(arg, "--registry=") || arg == "--repository" || strings.HasPrefix(arg, "--repository="):
			flagName, value, inline := strings.Cut(arg, "=")
			target := &request.publicationFlags.Registry
			if flagName == "--repository" {
				target = &request.publicationFlags.Repository
			}
			if target.Set {
				return cliRequest{}, fmt.Errorf("%s may be specified only once", flagName)
			}
			if !inline {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return cliRequest{}, fmt.Errorf("%s requires a value", flagName)
				}
				value = args[i]
			}
			*target = build.OptionalString{Value: value, Set: true}
		case arg == "--cosign-key" || strings.HasPrefix(arg, "--cosign-key=") || arg == "--cosign-signing-config" || strings.HasPrefix(arg, "--cosign-signing-config=") || arg == "--cosign-identity-token" || strings.HasPrefix(arg, "--cosign-identity-token="):
			flagName, value, inline := strings.Cut(arg, "=")
			target := &request.signingFlags.Key
			switch flagName {
			case "--cosign-signing-config":
				target = &request.signingFlags.Config
			case "--cosign-identity-token":
				target = &request.signingFlags.IdentityTokenFile
			}
			if target.Set {
				return cliRequest{}, fmt.Errorf("%s may be specified only once", flagName)
			}
			if !inline {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return cliRequest{}, fmt.Errorf("%s requires a value", flagName)
				}
				value = args[i]
			}
			*target = build.OptionalString{Value: value, Set: true}
		case arg == "--cosign-allow-http" || strings.HasPrefix(arg, "--cosign-allow-http=") || arg == "--require-signing" || strings.HasPrefix(arg, "--require-signing="):
			// Valueless booleans mean true and never consume the next argument.
			flagName, value, inline := strings.Cut(arg, "=")
			target := &request.signingFlags.AllowHTTP
			if flagName == "--require-signing" {
				target = &request.signingFlags.Require
			}
			if target.Set {
				return cliRequest{}, fmt.Errorf("%s may be specified only once", flagName)
			}
			if !inline {
				value = "true"
			}
			if value != "true" && value != "false" {
				return cliRequest{}, fmt.Errorf("%s must be true or false", flagName)
			}
			*target = build.OptionalBool{Value: value == "true", Set: true}
		case arg == "--entrypoint" || strings.HasPrefix(arg, "--entrypoint="):
			// Repeat once per element, in order; an element starting with "-"
			// needs the inline --entrypoint=<element> form.
			value, inline := strings.CutPrefix(arg, "--entrypoint=")
			if !inline {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return cliRequest{}, fmt.Errorf("--entrypoint requires a value; use --entrypoint=<element> for an element starting with -")
				}
				value = args[i]
			}
			request.Image.Entrypoint = append(request.Image.Entrypoint, value)
		case strings.HasPrefix(arg, "-"):
			return cliRequest{}, fmt.Errorf("unknown flag %q", arg)
		default:
			positional = append(positional, arg)
		}
	}
	if err := request.Image.Validate(); err != nil {
		return cliRequest{}, err
	}

	if len(positional) < 1 || len(positional) > 2 {
		return cliRequest{}, fmt.Errorf("build requires a package name and numeric version selector, or --apk-version")
	}
	request.PackageName = positional[0]
	if !wolfi.RequestedNamePattern.MatchString(request.PackageName) {
		return cliRequest{}, fmt.Errorf("invalid package or provider name")
	}
	if seenVersion {
		if len(positional) != 1 {
			return cliRequest{}, fmt.Errorf("cannot combine a selector with --apk-version")
		}
		if !apkVersion.MatchString(request.Version) {
			return cliRequest{}, fmt.Errorf("--apk-version must include an exact APK revision (-rN)")
		}
	} else {
		if len(positional) != 2 || !numericSelector.MatchString(positional[1]) {
			return cliRequest{}, fmt.Errorf("build requires a dotted numeric version selector")
		}
		request.Selector = positional[1]
	}
	return request, nil
}

func reportWorkflowFailure(stderr io.Writer, err error) bool {
	var f *build.WorkflowFailure
	if !errors.As(err, &f) {
		return false
	}
	r := f.Result
	load := r.DockerLoad
	if load == "loaded" && !r.ReadableConfirmed {
		load = "loaded; readable tag unconfirmed"
	}
	p := r.Publication
	fmt.Fprintf(stderr, "lupetto: build: %s; Docker load: %s; publication: %s; signing: %s; attestation: %s\n", r.Build, load, p.Status, r.Signing, r.Attestation)
	if p.Reference != "" {
		fmt.Fprintf(stderr, "lupetto: publication reference: %s\n", p.Reference)
	}
	if p.PushedDigest != "" {
		fmt.Fprintf(stderr, "lupetto: captured pushed digest: %s; immutable reference: %s; identity verified: %t\n", p.PushedDigest, p.ImmutableReference, p.Verified)
	}
	fmt.Fprintf(stderr, "lupetto: %s\n", build.PlainText(f.Error()))
	if f.SideEffects {
		fmt.Fprintln(stderr, "lupetto: Docker, registry, or Cosign operations were attempted and may have changed local/remote tags, uploaded or published an image, signature, or attestation, or imported content; cancellation cannot undo completed side effects; no rollback attempted")
	}
	if f.RecordErr != nil && r.Workspace != "" {
		fmt.Fprintln(stderr, "lupetto: failure record could not be retained")
	}
	return true
}
