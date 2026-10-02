package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
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
	flags.Usage = func() {
		_, _ = fmt.Fprintln(flags.Output(), "Usage: lupetto-explorer --products <file> [options]\n\nOptional CLI-only dashboard server. No login; builds are disabled by default.\nRegistry, repository, Docker credentials and Cosign settings are inherited only\nfrom the process environment, never supplied as CLI arguments by Explorer.\nSet LUPETTO_COSIGN_PUBLIC_KEY to a trusted public key to show registry\nsignature and SBOM attestation status.")
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
