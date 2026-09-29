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

const usage = "Usage:\n  lupetto doctor\n  lupetto build postgresql 17[.minor]\n  lupetto build postgresql --apk-version <exact-version>\n\nPostgreSQL 17 builds use the current signed Wolfi APKINDEX for the host architecture.\nA major selects the latest available minor/revision; a minor selects its latest available revision.\nAn unavailable version fails without substitution. Builds create a local OCI layout only.\nDoctor checks apko, Docker, and optional Cosign on PATH and suggests installation steps."

var packageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)

type buildRequest struct {
	packageName string
	selector    string
	version     string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
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
	case "build":
		request, err := parseBuild(args[1:])
		if err != nil {
			fmt.Fprintf(stderr, "lupetto: %v\n", err)
			return 2
		}
		result, err := buildLocal(ctx, request)
		if err != nil {
			fmt.Fprintf(stderr, "lupetto: %v\n", err)
			return 1
		}
		fmt.Fprintf(stdout, "Selected %s@%s (APKINDEX sha256:%s)\nOCI image: %s\nBuild evidence: %s\n", result.packageName, result.version, result.indexSHA256, result.imageDir, result.workspace)
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
		case strings.HasPrefix(arg, "-"):
			return buildRequest{}, fmt.Errorf("unknown flag %q", arg)
		default:
			positional = append(positional, arg)
		}
	}

	if len(positional) < 1 || len(positional) > 2 {
		return buildRequest{}, fmt.Errorf("build requires a package and a major/minor selector, or --apk-version")
	}
	request.packageName = positional[0]
	if !packageName.MatchString(request.packageName) {
		return buildRequest{}, fmt.Errorf("invalid package name")
	}
	if request.packageName != "postgresql" {
		return buildRequest{}, fmt.Errorf("only the postgresql 17 family is supported for local images")
	}
	if seenVersion {
		if len(positional) != 1 {
			return buildRequest{}, fmt.Errorf("cannot combine a selector with --apk-version")
		}
		if !pgVersion.MatchString(request.version) {
			return buildRequest{}, fmt.Errorf("--apk-version must be an exact PostgreSQL 17 APK revision (17.N-rM)")
		}
	} else {
		if len(positional) != 2 || !pgSelector.MatchString(positional[1]) {
			return buildRequest{}, fmt.Errorf("postgresql requires a major/minor selector (17 or 17.N)")
		}
		request.selector = positional[1]
	}
	return request, nil
}
