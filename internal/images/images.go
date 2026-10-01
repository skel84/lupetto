// Package images exposes read-only local build history and Docker inventory.
package images

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
	"lupetto/internal/build"
	"lupetto/internal/wolfi"
)

const (
	MaxWorkspaces   = 10000
	MaxRecords      = 1000
	MaxRecordBytes  = 1 << 20
	MaxSPDXBytes    = 32 << 20
	MaxDockerImages = 1000
	maxDockerOutput = 4 << 20
)

type Document struct {
	Kind       string    `json:"kind"`
	Version    int       `json:"version"`
	ComputedAt string    `json:"computedAt"`
	Builds     []History `json:"builds"`
	Docker     Docker    `json:"docker"`
}
type History struct {
	Workspace     string        `json:"workspace"`
	RecordPath    string        `json:"recordPath"`
	RecordVersion int           `json:"recordVersion"`
	Status        string        `json:"status"`
	Error         string        `json:"error,omitempty"`
	RecordedAt    string        `json:"recordedAt"`
	BuildTime     string        `json:"buildTime,omitempty"`
	Record        *build.Record `json:"record,omitempty"`
	SPDX          SPDX          `json:"spdx"`
}
type SPDX struct {
	Present bool   `json:"present"`
	Path    string `json:"path,omitempty"`
	SHA256  string `json:"sha256,omitempty"`
	Reason  string `json:"reason,omitempty"`
}
type Docker struct {
	Available bool    `json:"available"`
	Reason    string  `json:"reason,omitempty"`
	Images    []Image `json:"images"`
}
type Identity struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture"`
}
type Image struct {
	ID             string    `json:"id"`
	Tags           []string  `json:"tags"`
	Created        string    `json:"created"`
	Size           int64     `json:"size"`
	IdentityKnown  bool      `json:"identityKnown"`
	IdentitySource string    `json:"identitySource"`
	Identity       *Identity `json:"identity,omitempty"`
}

func Run(ctx context.Context) (Document, error) {
	cache, err := os.UserCacheDir()
	if err != nil {
		return Document{}, fmt.Errorf("find user cache: %w", err)
	}
	return RunAt(ctx, filepath.Join(cache, "lupetto", "builds"))
}

// RunAt scans an explicit builds root, used by hermetic fixture tests.
func RunAt(ctx context.Context, root string) (Document, error) {
	history, err := scanHistory(ctx, root)
	if err != nil {
		return Document{}, err
	}
	docker := scanDocker(ctx, history)
	if err := ctx.Err(); err != nil {
		return Document{}, err
	}
	return Document{Kind: "images", Version: 1, ComputedAt: time.Now().UTC().Format(time.RFC3339Nano), Builds: history, Docker: docker}, nil
}

func scanHistory(ctx context.Context, root string) ([]History, error) {
	history := []History{}
	directory, err := os.Open(root)
	if errors.Is(err, os.ErrNotExist) {
		return history, nil
	}
	if err != nil {
		return nil, fmt.Errorf("open build history: %w", err)
	}
	defer directory.Close()
	entries, err := directory.ReadDir(MaxWorkspaces + 1)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("read build history: %w", err)
	}
	if len(entries) > MaxWorkspaces {
		return nil, fmt.Errorf("build history exceeds %d workspace entries", MaxWorkspaces)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !entry.IsDir() {
			continue
		}
		workspace := filepath.Join(root, entry.Name())
		for _, filename := range []string{"result.json", "failure.json"} {
			path := filepath.Join(workspace, filename)
			info, err := os.Lstat(path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if len(history) >= MaxRecords {
				return nil, fmt.Errorf("build history exceeds %d retained records", MaxRecords)
			}
			item := History{Workspace: workspace, RecordPath: path, Status: "unreadable", SPDX: SPDX{Reason: "record unavailable"}}
			if err != nil {
				item.Error = "cannot stat record"
				history = append(history, item)
				continue
			}
			item.RecordedAt = info.ModTime().UTC().Format(time.RFC3339Nano)
			if !info.Mode().IsRegular() {
				item.Error = "record is not a regular file"
				history = append(history, item)
				continue
			}
			data, err := readBounded(path, MaxRecordBytes)
			if err != nil {
				item.Error = "cannot read record or record exceeds 1 MiB"
				history = append(history, item)
				continue
			}
			var header struct {
				Version int `json:"version"`
			}
			if err := json.Unmarshal(data, &header); err != nil {
				item.Status = "invalid"
				item.Error = "invalid record JSON"
				history = append(history, item)
				continue
			}
			item.RecordVersion = header.Version
			if header.Version != 6 {
				item.Status = "unsupported"
				item.SPDX.Reason = "unsupported record version"
				history = append(history, item)
				continue
			}
			var record build.Record
			if err := json.Unmarshal(data, &record); err != nil || (record.Outcome != "succeeded" && record.Outcome != "failed") || (record.Command != "build" && record.Command != "sbom") {
				item.Status = "invalid"
				item.Error = "invalid version-6 record"
				history = append(history, item)
				continue
			}
			item.Status = "supported"
			item.Record = &record
			item.BuildTime = readBuildTime(workspace)
			item.SPDX = checkSPDX(workspace, record.Evidence)
			history = append(history, item)
		}
	}
	sort.Slice(history, func(i, j int) bool {
		left, _ := time.Parse(time.RFC3339Nano, history[i].RecordedAt)
		right, _ := time.Parse(time.RFC3339Nano, history[j].RecordedAt)
		if !left.Equal(right) {
			return left.After(right)
		}
		return history[i].RecordPath < history[j].RecordPath
	})
	return history, nil
}

func readBounded(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("file exceeds bound")
	}
	return data, nil
}

func readBuildTime(workspace string) string {
	// Build records intentionally remain version 6. The retained apko input owns
	// the actual build timestamp pinned by the build pipeline.
	data, err := readBounded(filepath.Join(workspace, "apko.yaml"), MaxRecordBytes)
	if err != nil {
		return ""
	}
	var config struct {
		Annotations map[string]string `yaml:"annotations"`
	}
	if yaml.Unmarshal(data, &config) != nil {
		return ""
	}
	timestamp, err := time.Parse(time.RFC3339, config.Annotations["org.opencontainers.image.created"])
	if err != nil {
		return ""
	}
	return timestamp.UTC().Format(time.RFC3339)
}

func checkSPDX(workspace string, evidence *build.RecordEvidence) SPDX {
	result := SPDX{Reason: "no validated SPDX evidence"}
	if evidence == nil || !evidence.SPDXValidated {
		return result
	}
	result.Path = evidence.SPDXPath
	result.SHA256 = evidence.SPDXSHA256
	// Do not read an arbitrary path supplied by an edited private record. Resolve
	// symlinks and require the file to stay within this retained workspace.
	resolved, err := filepath.EvalSymlinks(evidence.SPDXPath)
	resolvedWorkspace, workspaceErr := filepath.EvalSymlinks(workspace)
	if err != nil || workspaceErr != nil {
		result.Reason = "validated SPDX file is unavailable"
		return result
	}
	relative, err := filepath.Rel(resolvedWorkspace, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) || filepath.IsAbs(relative) {
		result.Reason = "SPDX path is outside workspace"
		return result
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		result.Reason = "validated SPDX file is unavailable"
		return result
	}
	data, err := readBounded(resolved, MaxSPDXBytes)
	if err != nil {
		result.Reason = "validated SPDX file is unreadable or exceeds 32 MiB"
		return result
	}
	checksum := sha256.Sum256(data)
	if hex.EncodeToString(checksum[:]) != evidence.SPDXSHA256 {
		result.Reason = "validated SPDX checksum does not match"
		return result
	}
	result.Present = true
	result.Reason = ""
	return result
}

type boundedOutput struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > b.limit-b.buffer.Len() {
		return 0, fmt.Errorf("Docker output exceeds bound")
	}
	return b.buffer.Write(data)
}

func dockerCommand(ctx context.Context, args ...string) ([]byte, error) {
	// Match build/load's subprocess conventions: argv arrays, inherited Docker
	// configuration/environment, cancellation, no shell or daemon/context changes.
	output := &boundedOutput{limit: maxDockerOutput}
	command := exec.CommandContext(ctx, "docker", args...)
	command.Stdout = output
	command.Stderr = io.Discard // Never expose daemon errors/environment credentials.
	err := command.Run()
	return output.buffer.Bytes(), err
}

var imageIDPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var readablePattern = regexp.MustCompile(`^lupetto/([^/:]+):(.+)-(amd64|arm64)$`)
var exactVersionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:-]*-r[0-9]+$`)

func scanDocker(ctx context.Context, history []History) Docker {
	result := Docker{Images: []Image{}}
	if _, err := exec.LookPath("docker"); err != nil {
		result.Reason = "Docker CLI is not available on PATH"
		return result
	}
	dockerCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := dockerCommand(dockerCtx, "image", "ls", "--filter", "reference=lupetto/*", "--quiet", "--no-trunc")
	if err != nil {
		result.Reason = "Docker is unreachable or image listing failed"
		return result
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, id := range strings.Fields(string(output)) {
		if !imageIDPattern.MatchString(id) {
			result.Reason = "Docker returned an invalid image ID"
			return result
		}
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	if len(ids) > MaxDockerImages {
		result.Reason = "Docker inventory exceeds 1000 images"
		return result
	}
	for start := 0; start < len(ids); start += 100 {
		end := start + 100
		if end > len(ids) {
			end = len(ids)
		}
		expected := map[string]bool{}
		for _, id := range ids[start:end] {
			expected[id] = true
		}
		args := append([]string{"image", "inspect"}, ids[start:end]...)
		output, err = dockerCommand(dockerCtx, args...)
		if err != nil {
			result.Images = []Image{}
			result.Reason = "Docker image inspection failed"
			return result
		}
		var inspected []struct {
			ID       string   `json:"Id"`
			RepoTags []string `json:"RepoTags"`
			Created  string   `json:"Created"`
			Size     int64    `json:"Size"`
		}
		if json.Unmarshal(output, &inspected) != nil || len(inspected) != end-start {
			result.Images = []Image{}
			result.Reason = "Docker returned invalid image metadata"
			return result
		}
		batchSeen := map[string]bool{}
		for _, item := range inspected {
			created, createdErr := time.Parse(time.RFC3339Nano, item.Created)
			if !expected[item.ID] || batchSeen[item.ID] || !imageIDPattern.MatchString(item.ID) || item.Size < 0 || createdErr != nil {
				result.Images = []Image{}
				result.Reason = "Docker returned invalid image metadata"
				return result
			}
			batchSeen[item.ID] = true
			tags := []string{}
			for _, tag := range item.RepoTags {
				if strings.HasPrefix(tag, "lupetto/") {
					tags = append(tags, tag)
				}
			}
			if len(tags) == 0 {
				continue
			} // A tag can disappear between list and inspect.
			sort.Strings(tags)
			identity, source := identify(item.ID, tags, history)
			result.Images = append(result.Images, Image{ID: item.ID, Tags: tags, Created: created.UTC().Format(time.RFC3339Nano), Size: item.Size, IdentityKnown: identity != nil, IdentitySource: source, Identity: identity})
		}
	}
	sort.Slice(result.Images, func(i, j int) bool {
		left, _ := time.Parse(time.RFC3339Nano, result.Images[i].Created)
		right, _ := time.Parse(time.RFC3339Nano, result.Images[j].Created)
		if !left.Equal(right) {
			return left.After(right)
		}
		return result.Images[i].ID < result.Images[j].ID
	})
	result.Available = true
	return result
}

func identify(id string, tags []string, history []History) (*Identity, string) {
	var match *Identity
	matchedRecord := false
	for _, entry := range history {
		record := entry.Record
		if record == nil || record.Stages.Load.DockerImageID != id {
			continue
		}
		matchedRecord = true
		if record.Selection == nil {
			return nil, "unknown"
		}
		candidate := Identity{Name: record.Selection.Package, Version: record.Selection.Version, Architecture: record.Selection.Architecture}
		if !validIdentity(candidate) || (match != nil && *match != candidate) {
			return nil, "unknown"
		}
		match = &candidate
	}
	if matchedRecord {
		return match, "build-record"
	}
	for _, tag := range tags {
		parts := readablePattern.FindStringSubmatch(tag)
		if parts == nil || parts[1] == "local" || strings.HasPrefix(parts[1], "apk-sha256-") || strings.HasPrefix(parts[2], "_apk-sha256-") {
			continue
		}
		arch := "x86_64"
		if parts[3] == "arm64" {
			arch = "aarch64"
		}
		candidate := Identity{Name: parts[1], Version: parts[2], Architecture: arch}
		if !validIdentity(candidate) {
			continue
		}
		if match != nil && *match != candidate {
			return nil, "unknown"
		}
		match = &candidate
	}
	if match != nil {
		return match, "readable-tag"
	}
	return nil, "unknown"
}
func validIdentity(identity Identity) bool {
	return wolfi.PackageNamePattern.MatchString(identity.Name) && exactVersionPattern.MatchString(identity.Version) && (identity.Architecture == "x86_64" || identity.Architecture == "aarch64")
}
