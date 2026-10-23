package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"

	"lupetto/internal/explorer"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	config := explorer.DefaultConfig()
	flags := flag.NewFlagSet("lupetto-explorer", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.StringVar(&config.Listen, "listen", config.Listen, "HTTP listen address (no login; protect non-loopback access)")
	flags.Func("allowed-host", "allowed HTTP host or host:port (repeatable; replaces defaults localhost, 127.0.0.1, [::1] at any port)", func(value string) error {
		config.AllowedHosts = append(config.AllowedHosts, value)
		return nil
	})
	flags.StringVar(&config.Products, "products", "", "required CLI products YAML file")
	flags.StringVar(&config.LupettoBinary, "lupetto-binary", config.LupettoBinary, "configured CLI executable (resolved on PATH)")
	flags.BoolVar(&config.EnableBuilds, "enable-builds", false, "enable one-at-a-time CLI build execution")
	flags.DurationVar(&config.RefreshInterval, "refresh-interval", config.RefreshInterval, "background status/discovery refresh interval")
	flags.DurationVar(&config.ScanInterval, "scan-interval", config.ScanInterval, "Grype vulnerability rescan interval; 0 turns scanning, its pages and metrics off")
	flags.Func("scan-max-image-size", "largest image to scan, as compressed layer bytes with an optional KiB, MiB or GiB suffix (default 2GiB)", func(value string) error {
		size, err := parseSize(value)
		if err != nil {
			return err
		}
		config.ScanMaxImageSize = size
		return nil
	})
	flags.Usage = func() {
		_, _ = fmt.Fprintln(flags.Output(), "Usage: lupetto-explorer --products <file> [options]\n\nOptional CLI-only dashboard server. No login; builds are disabled by default.\nRegistry, repository, Docker credentials and Cosign settings are inherited only\nfrom the process environment, never supplied as CLI arguments by Explorer.\nPublish builds inherit LUPETTO_REQUIRE_SIGNING; without LUPETTO_COSIGN_KEY or\nLUPETTO_COSIGN_IDENTITY_TOKEN_FILE (keyless) the build controls say publishes\nwill be unsigned (or refused when it is true).\nSet LUPETTO_COSIGN_PUBLIC_KEY to a trusted public key, or\nLUPETTO_COSIGN_CERTIFICATE_IDENTITY[_REGEXP] with\nLUPETTO_COSIGN_CERTIFICATE_OIDC_ISSUER for keyless signers, to show registry\nsignature and SBOM attestation status.\nVulnerability scanning (on by default) downloads Grype's database from\ngrype.anchore.io and pulls each track's newest image and the upstream image\nnamed in the products file; --scan-interval 0 turns it off.")
		flags.PrintDefaults()
	}
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		_, _ = fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		config.Version = info.Main.Version
	}
	config.Log = stderr
	server, err := explorer.New(config)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "Explorer listening on %s (builds enabled: %t)\n", config.Listen, config.EnableBuilds)
	if err := server.Run(ctx); err != nil {
		_, _ = fmt.Fprintf(stderr, "Explorer stopped: %v\n", err)
		return 1
	}
	return 0
}

// parseSize reads a positive byte count with an optional KiB, MiB or GiB
// suffix.
func parseSize(value string) (int64, error) {
	number, unit := value, int64(1)
	for suffix, size := range map[string]int64{"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30} {
		if strings.HasSuffix(value, suffix) {
			number, unit = strings.TrimSuffix(value, suffix), size
		}
	}
	n, err := strconv.ParseInt(number, 10, 64)
	if err != nil || n <= 0 || n > (1<<62)/unit {
		return 0, fmt.Errorf("invalid size %q: want a positive number of bytes, KiB, MiB or GiB", value)
	}
	return n * unit, nil
}
