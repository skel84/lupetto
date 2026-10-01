package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// recordVersion identifies the one result schema shared by result.json,
// failure.json, and --json output. Changing its meaning requires a new version.
const recordVersion = 6

const maxRecordErrorBytes = 8 << 10

type buildRecord struct {
	Version   int              `json:"version"`
	Command   string           `json:"command"`
	Outcome   string           `json:"outcome"`
	Failure   *recordFailure   `json:"failure,omitempty"`
	Workspace string           `json:"workspace,omitempty"`
	Request   recordRequest    `json:"request"`
	Selection *recordSelection `json:"selection,omitempty"`
	Evidence  *recordEvidence  `json:"evidence,omitempty"`
	Stages    recordStages     `json:"stages"`
}

type recordFailure struct {
	Stage               string `json:"stage"`
	Error               string `json:"error"`
	SideEffectsPossible bool   `json:"sideEffectsPossible"`
}

type recordRequest struct {
	Package    string `json:"package"`
	Selector   string `json:"selector"`
	APKVersion string `json:"apkVersion"`
	Load       bool   `json:"load"`
	Publish    bool   `json:"publish"`
	Sign       bool   `json:"sign"`
}

type recordSelection struct {
	Package      string `json:"package"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	IndexSHA256  string `json:"indexSHA256"`
}

type recordEvidence struct {
	ApkoVersion    string `json:"apkoVersion"`
	ImageDirectory string `json:"imageDirectory"`
	ImageDigest    string `json:"imageDigest"`
	LockPath       string `json:"lockPath"`
	SPDXPath       string `json:"spdxPath"`
	SPDXSHA256     string `json:"spdxSHA256"`
	SPDXValidated  bool   `json:"spdxValidated"`
}

type recordStatus struct {
	Status string `json:"status"`
}

type recordLoad struct {
	Status                     string `json:"status"`
	ImageReference             string `json:"imageReference,omitempty"`
	BuildReference             string `json:"buildReference,omitempty"`
	DockerImageID              string `json:"dockerImageID,omitempty"`
	ReadableReferenceConfirmed bool   `json:"readableReferenceConfirmed"`
}

type recordPublication struct {
	Status             string `json:"status"`
	Reference          string `json:"reference,omitempty"`
	Digest             string `json:"digest,omitempty"`
	ImmutableReference string `json:"immutableReference,omitempty"`
	Verified           bool   `json:"verified"`
}

type recordStages struct {
	Build       recordStatus      `json:"build"`
	Load        recordLoad        `json:"load"`
	Publication recordPublication `json:"publication"`
	Signing     recordStatus      `json:"signing"`
	Attestation recordStatus      `json:"attestation"`
}

func requestedStatus(requested bool) string {
	if requested {
		return "not-attempted"
	}
	return "skipped"
}

// initialBuildResult fixes the requested-versus-unrequested distinction once:
// later code changes only the status of the stage it runs.
func initialBuildResult(request buildRequest) buildResult {
	command := request.command
	if command == "" {
		command = "build"
	}
	return buildResult{
		command: command,
		request: recordRequest{
			Package: request.packageName, Selector: request.selector, APKVersion: request.version,
			Load: !request.noLoad, Publish: request.publication.enabled(), Sign: request.signing.enabled(),
		},
		build:       "not-attempted",
		dockerLoad:  requestedStatus(!request.noLoad),
		publication: publicationOutcome{status: requestedStatus(request.publication.enabled())},
		signing:     requestedStatus(request.signing.enabled()),
		attestation: requestedStatus(request.signing.enabled()),
	}
}

func (r buildResult) recordDocument(failure *recordFailure) buildRecord {
	command := r.command
	if command == "" {
		command = "build"
	}
	record := buildRecord{
		Version: recordVersion, Command: command, Outcome: "succeeded", Failure: failure,
		Workspace: r.workspace, Request: r.request,
		Stages: recordStages{
			Build: recordStatus{r.build},
			Load: recordLoad{Status: r.dockerLoad, ImageReference: r.imageReference, BuildReference: r.buildReference,
				DockerImageID: r.dockerImageID, ReadableReferenceConfirmed: r.readableConfirmed},
			Publication: recordPublication{Status: r.publication.status, Reference: r.publication.reference,
				Digest: r.publication.pushedDigest, ImmutableReference: r.publication.immutableReference, Verified: r.publication.verified},
			Signing:     recordStatus{r.signing},
			Attestation: recordStatus{r.attestation},
		},
	}
	if failure != nil {
		record.Outcome = "failed"
	}
	if r.selected {
		record.Selection = &recordSelection{Package: r.packageName, Version: r.version, Architecture: r.arch, IndexSHA256: r.indexSHA256}
	}
	if r.validated {
		record.Evidence = &recordEvidence{ApkoVersion: apkoBuildVersion, ImageDirectory: r.imageDir, ImageDigest: r.imageDigest,
			LockPath: r.lockPath, SPDXPath: r.spdxPath, SPDXSHA256: r.spdxSHA256, SPDXValidated: true}
	}
	return record
}

func encodeRecord(record buildRecord) ([]byte, error) {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// retainBuildResult writes result.json last and returns the exact bytes. A
// partial or canceled record is removed so it cannot look like success.
func retainBuildResult(ctx context.Context, result buildResult) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("finalize build result: %w", err)
	}
	data, err := encodeRecord(result.recordDocument(nil))
	if err != nil {
		return nil, fmt.Errorf("encode build result: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("finalize build result: %w", err)
	}
	path := filepath.Join(result.workspace, "result.json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("retain build result: %w", err)
	}
	_, writeErr := contextWriter{ctx: ctx, writer: file}.Write(data)
	closeErr := file.Close()
	if writeErr == nil {
		writeErr = closeErr
	}
	if writeErr == nil {
		writeErr = ctx.Err()
	}
	if writeErr != nil {
		if removeErr := os.Remove(path); removeErr != nil {
			return nil, fmt.Errorf("retain build result: %w (remove incomplete result: %v)", writeErr, removeErr)
		}
		return nil, fmt.Errorf("retain build result: %w", writeErr)
	}
	return data, nil
}

// workflowFailure carries every post-validation failure with its stage
// outcomes and the exact failure record bytes. For publication workflows the
// cause is a sanitized stage error; local-only workflows keep the detailed
// local message the CLI has always printed.
type workflowFailure struct {
	result      buildResult
	stage       string
	cause       error
	sideEffects bool
	record      []byte
	recordErr   error
}

func (f *workflowFailure) Error() string {
	if f.result.workspace == "" {
		return fmt.Sprintf("%s stage failed: %v", f.stage, f.cause)
	}
	return fmt.Sprintf("%s stage failed (workspace: %s): %v", f.stage, f.result.workspace, f.cause)
}
func (f *workflowFailure) Unwrap() error { return f.cause }

func stageEntered(status string) bool {
	return status != "" && status != "skipped" && status != "not-attempted"
}

func newWorkflowFailure(result buildResult, stage string, cause error, sanitize bool) *workflowFailure {
	f := &workflowFailure{result: result, stage: stage, cause: cause,
		sideEffects: stageEntered(result.dockerLoad) || stageEntered(result.publication.status) || stageEntered(result.signing) || stageEntered(result.attestation)}
	if sanitize {
		f.cause = safeStageError(nil, stage, cause)
		var safe *publicationStageError
		if errors.As(cause, &safe) {
			f.cause = safe
		}
	}
	message := plainProgressText(f.cause.Error())
	if len(message) > maxRecordErrorBytes {
		message = message[:maxRecordErrorBytes]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
	}
	data, err := encodeRecord(result.recordDocument(&recordFailure{Stage: stage, Error: message, SideEffectsPossible: f.sideEffects}))
	if err != nil {
		f.recordErr = err
		return f
	}
	f.record = data
	if result.workspace != "" {
		f.recordErr = writeExclusiveFile(filepath.Join(result.workspace, "failure.json"), data)
	}
	return f
}

func reportWorkflowFailure(stderr io.Writer, err error) bool {
	var f *workflowFailure
	if !errors.As(err, &f) {
		return false
	}
	r := f.result
	load := r.dockerLoad
	if load == "loaded" && !r.readableConfirmed {
		load = "loaded; readable tag unconfirmed"
	}
	p := r.publication
	fmt.Fprintf(stderr, "lupetto: build: %s; Docker load: %s; publication: %s; signing: %s; attestation: %s\n", r.build, load, p.status, r.signing, r.attestation)
	if p.reference != "" {
		fmt.Fprintf(stderr, "lupetto: publication reference: %s\n", p.reference)
	}
	if p.pushedDigest != "" {
		fmt.Fprintf(stderr, "lupetto: captured pushed digest: %s; immutable reference: %s; identity verified: %t\n", p.pushedDigest, p.immutableReference, p.verified)
	}
	fmt.Fprintf(stderr, "lupetto: %s\n", plainProgressText(f.Error()))
	if f.sideEffects {
		fmt.Fprintln(stderr, "lupetto: Docker, registry, or Cosign operations were attempted and may have changed local/remote tags, uploaded or published an image, signature, or attestation, or imported content; cancellation cannot undo completed side effects; no rollback attempted")
	}
	if f.recordErr != nil && r.workspace != "" {
		fmt.Fprintln(stderr, "lupetto: failure record could not be retained")
	}
	return true
}
