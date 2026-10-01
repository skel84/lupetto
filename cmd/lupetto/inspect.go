package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"lupetto/internal/status"
)

const inspectUsage = "\n\nRead-only installed packages:\n  lupetto inspect --json <registry-repository@sha256:digest>\nInspect accepts only explicit digest references, never tags; uses Docker credentials and the shared loopback-only HTTP guard.\nInspect prints kind=inspect, version=1 with annotation identity (or unidentified), created time when present, and digest-cached installed APKs."

func parseInspect(args []string) (string, error) {
	reference := ""
	jsonOutput := false
	for _, arg := range args {
		if arg == "--json" {
			if jsonOutput {
				return "", fmt.Errorf("--json may be specified only once")
			}
			jsonOutput = true
		} else if strings.HasPrefix(arg, "-") {
			return "", fmt.Errorf("unknown inspect option")
		} else if reference != "" {
			return "", fmt.Errorf("inspect requires exactly one digest reference")
		} else {
			reference = arg
		}
	}
	if !jsonOutput || reference == "" {
		return "", fmt.Errorf("inspect requires --json and one registry digest reference")
	}
	if _, err := status.ParseInspectReference(reference); err != nil {
		return "", err
	}
	return reference, nil
}

func runInspect(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runInspectWith(ctx, args, stdout, stderr, status.Inspect)
}

func runInspectWith(ctx context.Context, args []string, stdout, stderr io.Writer, inspect func(context.Context, string) (status.InspectDocument, error)) int {
	reference, err := parseInspect(args)
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %v\n", err)
		return 2
	}
	document, err := inspect(ctx, reference)
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: %v\n", err)
		return 1
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(document); err != nil {
		fmt.Fprintln(stderr, "lupetto: could not write inspect JSON")
		return 1
	}
	return 0
}
