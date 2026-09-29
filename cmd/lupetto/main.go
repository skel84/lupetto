package main

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const usage = "Usage: lupetto build <package> --apk-version <exact-version>\n\nAn exact version includes its APK revision (for example, 1.2.3-r0).\nImage builds are not implemented yet."

var (
	packageName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9+._-]*$`)
	apkVersion  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]*-r[0-9]+$`)
)

type exactRequest struct {
	packageName string
	version     string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}

	switch args[0] {
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return 0
	case "build":
		_, err := parseBuild(args[1:])
		if err != nil {
			fmt.Fprintf(stderr, "lupetto: %v\n", err)
			return 2
		}
		fmt.Fprintln(stderr, "lupetto: image builds are not implemented; no image or SBOM was created")
		return 1
	default:
		fmt.Fprintf(stderr, "lupetto: unknown command %q\n", args[0])
		return 2
	}
}

func parseBuild(args []string) (exactRequest, error) {
	var request exactRequest
	var positional []string
	seenVersion := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--apk-version" || strings.HasPrefix(arg, "--apk-version="):
			if seenVersion {
				return exactRequest{}, fmt.Errorf("--apk-version may be specified only once")
			}
			seenVersion = true
			if arg == "--apk-version" {
				i++
				if i == len(args) || strings.HasPrefix(args[i], "-") {
					return exactRequest{}, fmt.Errorf("--apk-version requires an exact APK version")
				}
				request.version = args[i]
			} else {
				request.version = strings.TrimPrefix(arg, "--apk-version=")
			}
		case strings.HasPrefix(arg, "-"):
			return exactRequest{}, fmt.Errorf("unknown flag %q", arg)
		default:
			positional = append(positional, arg)
		}
	}

	if len(positional) != 1 {
		return exactRequest{}, fmt.Errorf("build requires exactly one package; major selectors are not implemented")
	}
	request.packageName = positional[0]
	if !packageName.MatchString(request.packageName) {
		return exactRequest{}, fmt.Errorf("invalid package name")
	}
	if !seenVersion {
		return exactRequest{}, fmt.Errorf("--apk-version is required; major selectors are not implemented")
	}
	if !apkVersion.MatchString(request.version) {
		return exactRequest{}, fmt.Errorf("--apk-version must include an exact APK revision (-rN)")
	}
	return request, nil
}
