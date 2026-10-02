package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"lupetto/internal/images"
)

const imagesUsage = "\n\nRead-only local inventory:\n  lupetto images [--json]\nImages lists retained version-6 build/failure records and local lupetto/ Docker images, newest first.\nRecords are read from <data>/lupetto/builds (LUPETTO_DATA_DIR or the OS user data directory) and, read-only, the legacy <user cache>/lupetto/builds.\nImages --json prints kind=images, version=1; unsupported record versions are listed without parsing them.\nDocker is optional: unreachable/missing Docker is reported as unavailable, never as an empty available inventory.\nImages does not build, load, tag, publish, or change Docker state."

func runImages(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runImagesWith(ctx, args, stdout, stderr, images.Run)
}
func runImagesWith(ctx context.Context, args []string, stdout, stderr io.Writer, compute func(context.Context) (images.Document, error)) int {
	jsonOutput := false
	for _, arg := range args {
		if arg != "--json" || jsonOutput {
			fmt.Fprintln(stderr, "lupetto: images accepts only one optional --json flag")
			return 2
		}
		jsonOutput = true
	}
	document, err := compute(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "lupetto: images: %v\n", err)
		return 1
	}
	if jsonOutput {
		data, err := json.MarshalIndent(document, "", "  ")
		if err == nil {
			_, err = stdout.Write(append(data, '\n'))
		}
		if err != nil {
			fmt.Fprintf(stderr, "lupetto: write images output: %v\n", err)
			return 1
		}
	} else if err := writeImagesTable(stdout, document); err != nil {
		fmt.Fprintf(stderr, "lupetto: write images output: %v\n", err)
		return 1
	}
	return 0
}

func writeImagesTable(out io.Writer, document images.Document) error {
	table := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "BUILD HISTORY\nTIME\tCOMMAND\tOUTCOME\tAPK\tLOAD\tPUBLISH\tSPDX\tWORKSPACE")
	for _, entry := range document.Builds {
		when := entry.BuildTime
		if when == "" {
			when = entry.RecordedAt
		}
		if entry.Record == nil {
			fmt.Fprintf(table, "%s\t-\t%s (v%d)\t-\t-\t-\t-\t%s\n", when, entry.Status, entry.RecordVersion, entry.Workspace)
			continue
		}
		record := entry.Record
		apk := "-"
		if record.Selection != nil {
			apk = record.Selection.Package + "@" + record.Selection.Version + "/" + record.Selection.Architecture
		}
		outcome := record.Outcome
		if record.Failure != nil {
			outcome += " (" + record.Failure.Stage + ")"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%s\t%s\t%s\t%t\t%s\n", when, record.Command, outcome, apk, record.Stages.Load.Status, record.Stages.Publication.Status, entry.SPDX.Present, entry.Workspace)
	}
	if err := table.Flush(); err != nil {
		return err
	}
	if !document.Docker.Available {
		_, err := fmt.Fprintf(out, "\nDocker unavailable: %s\n", document.Docker.Reason)
		return err
	}
	table = tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "\nDOCKER IMAGES\nID\tTAGS\tCREATED\tBYTES\tAPK")
	for _, image := range document.Docker.Images {
		apk := "unknown"
		if image.Identity != nil {
			apk = image.Identity.Name + "@" + image.Identity.Version + "/" + image.Identity.Architecture
		}
		id := image.ID
		if len(id) > 19 {
			id = id[:19]
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%d\t%s\n", id, strings.Join(image.Tags, ", "), image.Created, image.Size, apk)
	}
	return table.Flush()
}
