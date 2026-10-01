package build

import (
	"context"
	"errors"
	"testing"
)

func TestRequireApkoVersionExactReleaseSpellings(t *testing.T) {
	for _, tt := range []struct {
		version string
		wantOK  bool
	}{
		{"1.4.5", true},
		{"v1.4.5", true},
		{"1.4.50", false},
		{"v1.4.50", false},
		{"1.4.5-dev", false},
		{"v1.4.5-dev", false},
		{"1.4.4", false},
		{"v1.4.6", false},
		{"vv1.4.5", false},
		{"", false},
	} {
		t.Run(tt.version, func(t *testing.T) {
			command := func(_ context.Context, name string, args ...string) ([]byte, error) {
				if name != "apko" || len(args) != 1 || args[0] != "version" {
					t.Fatalf("unexpected probe: %s %v", name, args)
				}
				return []byte("apko\n\nGitVersion:    " + tt.version + "\nGitCommit:     example\n"), nil
			}
			err := RequireApkoVersion(context.Background(), command)
			if (err == nil) != tt.wantOK {
				t.Fatalf("version %q: error = %v, want success %t", tt.version, err, tt.wantOK)
			}
		})
	}
	probeError := errors.New("probe failed")
	err := RequireApkoVersion(context.Background(), func(context.Context, string, ...string) ([]byte, error) {
		return []byte("GitVersion:    v1.4.5\n"), probeError
	})
	if !errors.Is(err, probeError) {
		t.Fatalf("probe failure must not accept output: %v", err)
	}
}
