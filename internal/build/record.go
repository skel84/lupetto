package build

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unicode/utf8"
)

// recordVersion identifies the one result schema shared by result.json,
// failure.json, and --json output. Changing its meaning requires a new version.
const recordVersion = 6

const maxRecordErrorBytes = 8 << 10

type Record struct {
	Version   int              `json:"version"`
	Command   string           `json:"command"`
	Outcome   string           `json:"outcome"`
	Failure   *RecordFailure   `json:"failure,omitempty"`
	Workspace string           `json:"workspace,omitempty"`
	Request   RecordRequest    `json:"request"`
	Selection *RecordSelection `json:"selection,omitempty"`
	Evidence  *RecordEvidence  `json:"evidence,omitempty"`
	Stages    RecordStages     `json:"stages"`
}

type RecordFailure struct {
	Stage               string `json:"stage"`
	Error               string `json:"error"`
	SideEffectsPossible bool   `json:"sideEffectsPossible"`
}

type RecordRequest struct {
	Package    string `json:"package"`
	Selector   string `json:"selector"`
	APKVersion string `json:"apkVersion"`
	Load       bool   `json:"load"`
	Publish    bool   `json:"publish"`
	Sign       bool   `json:"sign"`
}

type RecordSelection struct {
	Package      string `json:"package"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
	IndexSHA256  string `json:"indexSHA256"`
}

type RecordEvidence struct {
	ApkoVersion    string `json:"apkoVersion"`
	ImageDirectory string `json:"imageDirectory"`
	ImageDigest    string `json:"imageDigest"`
	LockPath       string `json:"lockPath"`
	SPDXPath       string `json:"spdxPath"`
	SPDXSHA256     string `json:"spdxSHA256"`
	SPDXValidated  bool   `json:"spdxValidated"`
}

type RecordStatus struct {
	Status string `json:"status"`
}

type RecordLoad struct {
	Status                     string `json:"status"`
	ImageReference             string `json:"imageReference,omitempty"`
	BuildReference             string `json:"buildReference,omitempty"`
	DockerImageID              string `json:"dockerImageID,omitempty"`
	ReadableReferenceConfirmed bool   `json:"readableReferenceConfirmed"`
}

type RecordPublication struct {
	Status             string `json:"status"`
	Reference          string `json:"reference,omitempty"`
	Digest             string `json:"digest,omitempty"`
	ImmutableReference string `json:"immutableReference,omitempty"`
	Verified           bool   `json:"verified"`
}

type RecordStages struct {
	Build       RecordStatus      `json:"build"`
	Load        RecordLoad        `json:"load"`
	Publication RecordPublication `json:"publication"`
	Signing     RecordStatus      `json:"signing"`
	Attestation RecordStatus      `json:"attestation"`
}

func requestedStatus(requested bool) string {
	if requested {
		return "not-attempted"
	}
	return "skipped"
}

// InitialResult fixes the requested-versus-unrequested distinction once:
// later code changes only the status of the stage it runs.
func InitialResult(request Request) Result {
	command := request.Command
	if command == "" {
		command = "build"
	}
	return Result{
		Command: command,
		Request: RecordRequest{
			Package: request.PackageName, Selector: request.Selector, APKVersion: request.Version,
			Load: !request.NoLoad, Publish: request.Publication.Enabled(), Sign: request.Signing.Enabled(),
		},
		Build:       "not-attempted",
		DockerLoad:  requestedStatus(!request.NoLoad),
		Publication: PublicationOutcome{Status: requestedStatus(request.Publication.Enabled())},
		Signing:     requestedStatus(request.Signing.Enabled()),
		Attestation: requestedStatus(request.Signing.Enabled()),
	}
}

func (r Result) RecordDocument(failure *RecordFailure) Record {
	command := r.Command
	if command == "" {
		command = "build"
	}
	record := Record{
		Version: recordVersion, Command: command, Outcome: "succeeded", Failure: failure,
		Workspace: r.Workspace, Request: r.Request,
		Stages: RecordStages{
			Build: RecordStatus{r.Build},
			Load: RecordLoad{Status: r.DockerLoad, ImageReference: r.ImageReference, BuildReference: r.BuildReference,
				DockerImageID: r.DockerImageID, ReadableReferenceConfirmed: r.ReadableConfirmed},
			Publication: RecordPublication{Status: r.Publication.Status, Reference: r.Publication.Reference,
				Digest: r.Publication.PushedDigest, ImmutableReference: r.Publication.ImmutableReference, Verified: r.Publication.Verified},
			Signing:     RecordStatus{r.Signing},
			Attestation: RecordStatus{r.Attestation},
		},
	}
	if failure != nil {
		record.Outcome = "failed"
	}
	if r.Selected {
		record.Selection = &RecordSelection{Package: r.PackageName, Version: r.Version, Architecture: r.Arch, IndexSHA256: r.IndexSHA256}
	}
	if r.Validated {
		record.Evidence = &RecordEvidence{ApkoVersion: ApkoVersion, ImageDirectory: r.ImageDir, ImageDigest: r.ImageDigest,
			LockPath: r.LockPath, SPDXPath: r.SPDXPath, SPDXSHA256: r.SPDXSHA256, SPDXValidated: true}
	}
	return record
}

func EncodeRecord(record Record) ([]byte, error) {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// retainBuildResult writes result.json last and returns the exact bytes. A
// partial or canceled record is removed so it cannot look like success.
func retainBuildResult(ctx context.Context, result Result) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("finalize build result: %w", err)
	}
	data, err := EncodeRecord(result.RecordDocument(nil))
	if err != nil {
		return nil, fmt.Errorf("encode build result: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("finalize build result: %w", err)
	}
	path := filepath.Join(result.Workspace, "result.json")
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

// WorkflowFailure carries every post-validation failure with its stage
// outcomes and the exact failure record bytes. For publication workflows the
// cause is a sanitized stage error; local-only workflows keep the detailed
// local message the CLI has always printed.
type WorkflowFailure struct {
	Result      Result
	Stage       string
	Cause       error
	SideEffects bool
	Record      []byte
	RecordErr   error
}

func (f *WorkflowFailure) Error() string {
	if f.Result.Workspace == "" {
		return fmt.Sprintf("%s stage failed: %v", f.Stage, f.Cause)
	}
	return fmt.Sprintf("%s stage failed (workspace: %s): %v", f.Stage, f.Result.Workspace, f.Cause)
}

func (f *WorkflowFailure) Unwrap() error { return f.Cause }

func stageEntered(status string) bool {
	return status != "" && status != "skipped" && status != "not-attempted"
}

func NewWorkflowFailure(result Result, stage string, cause error, sanitize bool) *WorkflowFailure {
	f := &WorkflowFailure{Result: result, Stage: stage, Cause: cause,
		SideEffects: stageEntered(result.DockerLoad) || stageEntered(result.Publication.Status) || stageEntered(result.Signing) || stageEntered(result.Attestation)}
	if sanitize {
		f.Cause = safeStageError(nil, stage, cause)
		var safe *publicationStageError
		if errors.As(cause, &safe) {
			f.Cause = safe
		}
	}
	message := PlainText(f.Cause.Error())
	if len(message) > maxRecordErrorBytes {
		message = message[:maxRecordErrorBytes]
		for !utf8.ValidString(message) {
			message = message[:len(message)-1]
		}
	}
	data, err := EncodeRecord(result.RecordDocument(&RecordFailure{Stage: stage, Error: message, SideEffectsPossible: f.SideEffects}))
	if err != nil {
		f.RecordErr = err
		return f
	}
	f.Record = data
	if result.Workspace != "" {
		f.RecordErr = writeExclusiveFile(filepath.Join(result.Workspace, "failure.json"), data)
	}
	return f
}
