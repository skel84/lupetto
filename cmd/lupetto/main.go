package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"
)

const usage = "Usage:\n  lupetto doctor\n  lupetto discover <package-or-provider>\n  lupetto build <package-or-provider> <major[.minor[.patch]]> [--no-load] [--registry <authority> --repository <prefix>] [--cosign-key <key> [--cosign-signing-config <file>] [--cosign-allow-http[=true|false]]]\n  lupetto build <package-or-provider> --apk-version <exact-version> [--no-load] [--registry <authority> --repository <prefix>] [--cosign-key <key> [--cosign-signing-config <file>] [--cosign-allow-http[=true|false]]]\n  lupetto sbom <package-or-provider> --apk-version <exact-version>\n\nDiscover lists exact versions from the current signed Wolfi APKINDEX for the host architecture.\nListed versions are not guaranteed buildable; builds validate apko dependencies and installed packages.\nA numeric selector chooses the highest matching APK version/revision; an exact version includes -rN.\nThe package name must match an APK name or a version-matched provider; ambiguous build matches fail.\nBuild and sbom compose a local OCI layout and validate apko SPDX against the lock.\nBuild and sbom log stages and live tool diagnostics to stderr, with an ASCII spinner on interactive terminals.\nBuild loads Docker by default; --no-load skips loading. SBOM always skips loading.\nBuild optionally publishes with --registry / LUPETTO_REGISTRY and --repository / LUPETTO_REPOSITORY.\nEach explicit flag independently overrides its environment input; both publication settings are required, and empty string flags are invalid.\nRegistry is an authority (not a URL); repository is a nested lower-case prefix such as team/lupetto/images.\nPublication requires loading, uses Docker's credential store, and verifies the pushed immutable digest.\nBuild optionally signs and attests the validated architecture SPDX to that same immutable digest using Cosign v3.1.3.\nSigning requires --cosign-key / LUPETTO_COSIGN_KEY, publication, and loading; there is no implicit keyless path.\nAn optional --cosign-signing-config / LUPETTO_COSIGN_SIGNING_CONFIG selects an upstream config file, not a Lupetto key store.\n--cosign-allow-http / LUPETTO_COSIGN_ALLOW_HTTP accepts only true or false; a valueless flag means true.\nExplicit false overrides environment true. HTTP allowance is restricted to literal localhost or loopback IP registries.\nSigning on literal loopback requires explicit effective HTTP consent, including when HTTPS might be available.\nProduction defaults preserve upstream HTTPS/TUF/transparency-log services; custom signing configs can change services.\nFor a local/offline exception, generate a no-service config with cosign signing-config create --out <file> (without --with-default-services).\nInherit COSIGN_PASSWORD only from the process environment; never pass or retain passwords, key/config contents, or Cosign diagnostics.\nPublication and Cosign tool diagnostics are discarded. Publication, image signing, and SPDX attestation are reported separately.\nSBOM rejects publication and signing flags (including false/empty forms) and ignores publication and signing environment inputs."

var (
	packageName     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)
	requestedName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*(?::[A-Za-z0-9][A-Za-z0-9+._-]*)*$`)
	apkVersion      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]*-r[0-9]+$`)
	numericSelector = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)*$`)
)

type buildRequest struct {
	packageName      string
	selector         string
	version          string
	noLoad           bool
	publicationFlags publicationFlags
	publication      publicationOptions
	signingFlags     signingFlags
	signing          signingOptions
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithBuild(ctx, args, stdout, stderr, buildLocal)
}

func runWithBuild(ctx context.Context, args []string, stdout, stderr io.Writer, build func(context.Context, buildRequest) (buildResult, error)) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "doctor":
		return runDoctor(stdout, stderr, args[1:])
	case "discover":
		return runDiscover(ctx, args[1:], stdout, stderr)
	case "build", "sbom":
		request, err := parseBuild(args[1:])
		if err == nil && args[0] == "sbom" && request.noLoad {
			err = fmt.Errorf("sbom does not accept --no-load")
		}
		if err == nil && args[0] == "sbom" && (request.publicationFlags.registry.set || request.publicationFlags.repository.set) {
			err = fmt.Errorf("sbom does not accept --registry or --repository")
		}
		if err == nil && args[0] == "sbom" && (request.signingFlags.key.set || request.signingFlags.config.set || request.signingFlags.allowHTTP.set) {
			err = fmt.Errorf("sbom does not accept --cosign-key, --cosign-signing-config, or --cosign-allow-http")
		}
		if err == nil && args[0] == "sbom" && request.version == "" {
			err = fmt.Errorf("sbom requires --apk-version with an exact APK revision")
		}
		if err == nil && args[0] == "build" {
			request.publication, err = resolvePublication(request.publicationFlags, os.LookupEnv)
			if err == nil && request.noLoad && request.publication.enabled() {
				err = fmt.Errorf("publication cannot be used with --no-load")
			}
			if err == nil {
				request.signing, err = resolveSigning(request.signingFlags, request.publication, request.noLoad, os.LookupEnv)
			}
		}
		if err != nil {
			fmt.Fprintf(stderr, "lupetto: %v\n", err)
			return 2
		}
		if args[0] == "sbom" {
			request.noLoad = true
		}
		progress := newBuildProgress(ctx, stderr, progressTerminal(stderr))
		defer progress.Close()
		buildCtx := context.WithValue(ctx, buildProgressKey{}, progress)
		result, err := build(buildCtx, request)
		progress.Close()
		if err != nil {
			if !reportWorkflowFailure(stderr, err) {
				fmt.Fprintf(stderr, "lupetto: %s\n", plainProgressText(err.Error()))
			}
			return 1
		}
		fmt.Fprintln(stdout, "Build completed")
		fmt.Fprintf(stdout, "Selected %s@%s (APKINDEX sha256:%s)\nOCI image: %s\nValidated SPDX: %s (sha256:%s)\nBuild evidence: %s\n", result.packageName, result.version, result.indexSHA256, result.imageDir, result.spdxPath, result.spdxSHA256, result.workspace)
		fmt.Fprintf(stdout, "Image reference: %s\nBuild reference: %s\n", result.imageReference, result.buildReference)
		if result.dockerLoad == "loaded" {
			fmt.Fprintf(stdout, "Docker loaded: %s (image ID: %s)\n", result.imageReference, result.dockerImageID)
		} else {
			fmt.Fprintln(stdout, "Docker loading: skipped")
		}
		if result.publication.status == "published" && result.publication.verified {
			fmt.Fprintf(stdout, "Registry published: %s\nImmutable reference: %s\n", result.publication.reference, result.publication.immutableReference)
		} else {
			fmt.Fprintln(stdout, "Registry publication: skipped")
		}
		if result.signing == "signed" {
			fmt.Fprintf(stdout, "Image signing: signed (%s)\n", result.publication.immutableReference)
		} else {
			fmt.Fprintln(stdout, "Image signing: skipped")
		}
		if result.attestation == "attested" {
			fmt.Fprintf(stdout, "SPDX attestation: attested (%s)\n", result.publication.immutableReference)
		} else {
			fmt.Fprintln(stdout, "SPDX attestation: skipped")
		}
		return 0
	default:
		fmt.Fprintf(stderr, "lupetto: unknown command %q\n", args[0])
		return 2
	}
}

func parseBuild(args []string) (buildRequest, error) {
	var request buildRequest
	var positional []string
	seenVersion := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--no-load":
			if request.noLoad {
				return buildRequest{}, fmt.Errorf("--no-load may be specified only once")
			}
			request.noLoad = true
		case arg == "--apk-version" || strings.HasPrefix(arg, "--apk-version="):
			if seenVersion {
				return buildRequest{}, fmt.Errorf("--apk-version may be specified only once")
			}
			seenVersion = true
			if arg == "--apk-version" {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return buildRequest{}, fmt.Errorf("--apk-version requires an exact APK version")
				}
				request.version = args[i]
			} else {
				request.version = strings.TrimPrefix(arg, "--apk-version=")
			}
		case arg == "--registry" || strings.HasPrefix(arg, "--registry=") || arg == "--repository" || strings.HasPrefix(arg, "--repository="):
			flagName, value, inline := strings.Cut(arg, "=")
			target := &request.publicationFlags.registry
			if flagName == "--repository" {
				target = &request.publicationFlags.repository
			}
			if target.set {
				return buildRequest{}, fmt.Errorf("%s may be specified only once", flagName)
			}
			if !inline {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return buildRequest{}, fmt.Errorf("%s requires a value", flagName)
				}
				value = args[i]
			}
			*target = optionalString{value: value, set: true}
		case arg == "--cosign-key" || strings.HasPrefix(arg, "--cosign-key=") || arg == "--cosign-signing-config" || strings.HasPrefix(arg, "--cosign-signing-config="):
			flagName, value, inline := strings.Cut(arg, "=")
			target := &request.signingFlags.key
			if flagName == "--cosign-signing-config" {
				target = &request.signingFlags.config
			}
			if target.set {
				return buildRequest{}, fmt.Errorf("%s may be specified only once", flagName)
			}
			if !inline {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return buildRequest{}, fmt.Errorf("%s requires a value", flagName)
				}
				value = args[i]
			}
			*target = optionalString{value: value, set: true}
		case arg == "--cosign-allow-http" || strings.HasPrefix(arg, "--cosign-allow-http="):
			if request.signingFlags.allowHTTP.set {
				return buildRequest{}, fmt.Errorf("--cosign-allow-http may be specified only once")
			}
			_, value, inline := strings.Cut(arg, "=")
			if !inline {
				value = "true"
			}
			if value != "true" && value != "false" {
				return buildRequest{}, fmt.Errorf("--cosign-allow-http must be true or false")
			}
			request.signingFlags.allowHTTP = optionalBool{value: value == "true", set: true}
		case strings.HasPrefix(arg, "-"):
			return buildRequest{}, fmt.Errorf("unknown flag %q", arg)
		default:
			positional = append(positional, arg)
		}
	}

	if len(positional) < 1 || len(positional) > 2 {
		return buildRequest{}, fmt.Errorf("build requires a package name and numeric version selector, or --apk-version")
	}
	request.packageName = positional[0]
	if !requestedName.MatchString(request.packageName) {
		return buildRequest{}, fmt.Errorf("invalid package or provider name")
	}
	if seenVersion {
		if len(positional) != 1 {
			return buildRequest{}, fmt.Errorf("cannot combine a selector with --apk-version")
		}
		if !apkVersion.MatchString(request.version) {
			return buildRequest{}, fmt.Errorf("--apk-version must include an exact APK revision (-rN)")
		}
	} else {
		if len(positional) != 2 || !numericSelector.MatchString(positional[1]) {
			return buildRequest{}, fmt.Errorf("build requires a dotted numeric version selector")
		}
		request.selector = positional[1]
	}
	return request, nil
}
