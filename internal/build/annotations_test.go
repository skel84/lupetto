package build

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
	"lupetto/internal/wolfi"
	"lupetto/internal/wolfi/wolfitest"
)

func TestBuildIdentityAnnotationsAndScopedEpoch(t *testing.T) {
	arch, err := wolfi.TargetArch()
	if err != nil {
		t.Fatal(err)
	}
	index, key := wolfitest.MakeSignedIndexFor(t, fmt.Sprintf("P:nginx-stable\nV:1.30.2-r0\nA:%s\nC:exact\np:nginx=1.30.2-r0\n\n", arch))
	for _, noLoad := range []bool{false, true} {
		t.Run(fmt.Sprintf("no-load=%v", noLoad), func(t *testing.T) {
			before := time.Now().UTC().Truncate(time.Second)
			stopped := errors.New("stop before real composition")
			buildCalled := false
			services := Services{
				DataDir:    func() (string, error) { return t.TempDir(), nil },
				PublicFile: func(context.Context, string, int64) ([]byte, error) { return index, nil },
				SigningKey: func(context.Context) ([]byte, error) { return key, nil },
				Command: func(ctx context.Context, executable string, args ...string) ([]byte, error) {
					if executable != "apko" {
						t.Fatalf("unexpected executable %q", executable)
					}
					if args[0] != "build" && ctx.Value(sourceDateEpochContextKey{}) != nil {
						t.Fatal("epoch leaked to preflight or lock")
					}
					switch args[0] {
					case "version":
						return []byte("GitVersion:    " + ApkoVersion + "\n"), nil
					case "lock":
						data, _ := json.Marshal(map[string]any{"contents": map[string]any{"packages": []any{map[string]string{"name": "nginx-stable", "version": "1.30.2-r0", "architecture": arch, "checksum": "exact"}}}})
						return nil, os.WriteFile(args[4], data, 0600)
					case "build":
						buildCalled = true
						data, err := os.ReadFile(args[len(args)-3])
						if err != nil {
							t.Fatal(err)
						}
						var config struct {
							Annotations map[string]string `yaml:"annotations"`
						}
						if err := yaml.Unmarshal(data, &config); err != nil {
							t.Fatal(err)
						}
						want := map[string]string{"org.opencontainers.image.version": "1.30.2-r0", "lupetto.apk.name": "nginx-stable", "lupetto.apk.version": "1.30.2-r0", "lupetto.apk.architecture": arch, "lupetto.index.sha256": wolfi.SHA256Hex(index)}
						if len(config.Annotations) != 6 {
							t.Fatalf("annotations=%v", config.Annotations)
						}
						for name, value := range want {
							if config.Annotations[name] != value {
								t.Fatalf("%s=%q want=%q", name, config.Annotations[name], value)
							}
						}
						created, err := time.Parse(time.RFC3339, config.Annotations["org.opencontainers.image.created"])
						if err != nil || created.Before(before) || created.After(time.Now().UTC()) || !strings.HasSuffix(config.Annotations["org.opencontainers.image.created"], "Z") {
							t.Fatalf("created=%v err=%v", created, err)
						}
						if args[1] != "--build-date" || args[2] != created.Format(time.RFC3339) || ctx.Value(sourceDateEpochContextKey{}) != strconv.FormatInt(created.Unix(), 10) {
							t.Fatalf("timestamp not pinned: args=%v epoch=%v", args, ctx.Value(sourceDateEpochContextKey{}))
						}
						return nil, stopped
					default:
						t.Fatalf("unexpected command %v", args)
						return nil, nil
					}
				},
			}
			result, err := RunWith(context.Background(), Request{PackageName: "nginx", Version: "1.30.2-r0", NoLoad: noLoad}, services)
			if !buildCalled || !errors.Is(err, stopped) || result.Build != "failed" {
				t.Fatalf("called=%v result=%+v err=%v", buildCalled, result, err)
			}
		})
	}
}

func TestExecuteLocalCommandScopedEpochEnvironment(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "123")
	t.Setenv("LUPETTO_EPOCH_TEST_KEEP", "preserved")
	ctx := context.WithValue(context.Background(), sourceDateEpochContextKey{}, "456")
	data, err := ExecuteLocalCommand(ctx, "/usr/bin/env")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "SOURCE_DATE_EPOCH=456\n") || strings.Contains(string(data), "SOURCE_DATE_EPOCH=123\n") || !strings.Contains(string(data), "LUPETTO_EPOCH_TEST_KEEP=preserved\n") {
		t.Fatal("scoped environment did not replace epoch and preserve other variables")
	}
	data, err = ExecuteLocalCommand(context.Background(), "/usr/bin/env")
	if err != nil || !strings.Contains(string(data), "SOURCE_DATE_EPOCH=123\n") || os.Getenv("SOURCE_DATE_EPOCH") != "123" {
		t.Fatalf("unscoped environment mutated: err=%v", err)
	}
}
