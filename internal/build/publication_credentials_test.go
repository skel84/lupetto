package build

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"lupetto/internal/build/buildtest"
)

const credentialHelperCanary = "credential-helper-secret-canary-never-retain"

func isolateCredentialHelper(t *testing.T) string {
	t.Helper()
	configDir := buildtest.IsolateRegistryAuth(t)
	t.Setenv("DOCKER_AUTH_CONFIG", "")
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("PATH", t.TempDir())
	return configDir
}

func writeCredentialConfig(t *testing.T, configDir string, cfg map[string]any) {
	t.Helper()
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func writeCredentialHelper(t *testing.T, helper, body string) {
	t.Helper()
	script := "#!/bin/sh\n[ \"$1\" = get ] || exit 99\nkey=$(/bin/cat)\n" + body
	if err := os.WriteFile(filepath.Join(os.Getenv("PATH"), "docker-credential-"+helper), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
}

func credentialResource(t *testing.T, reference string) name.Repository {
	t.Helper()
	repo, err := name.NewRepository(reference, name.StrictValidation)
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

// Re-execution captures the real process stderr, not a substituted os.Stderr.
// The registry remains in the parent and the child uses only synthetic config.
func TestPublishOCIImageCredentialHelperDiagnostics(t *testing.T) {
	for _, store := range []string{"credsStore", "credHelpers"} {
		for _, mode := range []string{"success", "not-found", "failure"} {
			t.Run(store+"/"+mode, func(t *testing.T) {
				configDir := isolateCredentialHelper(t)
				registry := buildtest.NewRegistry(t, "auth", nil)
				cfg := map[string]any{"credsStore": "fixture"}
				if store == "credHelpers" {
					// An invalid default proves the registry-specific helper wins.
					cfg = map[string]any{"credsStore": "invalid/default", "credHelpers": map[string]string{registry.Host + "/team/images/fixture": "fixture", registry.Host: "fixture"}}
				}
				writeCredentialConfig(t, configDir, cfg)
				calls := filepath.Join(t.TempDir(), "calls")
				t.Setenv("LUPETTO_HELPER_CALLS", calls)
				body := "printf '%s\\n' \"$key\" >> \"$LUPETTO_HELPER_CALLS\"\nprintf '%s\\n' '" + credentialHelperCanary + "' >&2\n"
				switch mode {
				case "success":
					body += fmt.Sprintf("printf '%%s\\n' '{\"ServerURL\":\"ignored\",\"Username\":%q,\"Secret\":%q}'\n", buildtest.RegistryUser, buildtest.RegistryPassword)
				case "not-found":
					body += "printf '%s\\n' 'credentials not found in native keychain'\nexit 1\n"
				case "failure":
					body += "printf '%s\\n' '" + credentialHelperCanary + "'\nexit 1\n"
				}
				writeCredentialHelper(t, "fixture", body)
				result, _ := publicationTestResult(t, "x86_64")
				resultJSON, err := json.Marshal(result)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCredentialHelperPublicationSubprocess$", "-test.count=1")
				cmd.Env = append(os.Environ(), "LUPETTO_CREDENTIAL_SUBPROCESS="+mode, "LUPETTO_CREDENTIAL_RESULT="+string(resultJSON), "LUPETTO_CREDENTIAL_HOST="+registry.Host)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				runErr := cmd.Run()
				for _, output := range []string{stdout.String(), stderr.String()} {
					if strings.Contains(output, credentialHelperCanary) || strings.Contains(output, buildtest.RegistryPassword) || strings.Contains(output, buildtest.PublicationCanary) {
						t.Fatal("credential helper diagnostics escaped into process output")
					}
				}
				if runErr != nil {
					t.Fatalf("lookup subprocess failed: %v; stdout=%s stderr=%s", runErr, stdout.String(), stderr.String())
				}
				if mode == "success" && !strings.Contains(stdout.String(), "published and verified") {
					t.Fatal("subprocess did not confirm authenticated publication")
				}
				if data, err := os.ReadFile(calls); err != nil || len(data) == 0 {
					t.Fatal("helper was not executed")
				}
			})
		}
	}
}

func TestCredentialHelperPublicationSubprocess(t *testing.T) {
	mode := os.Getenv("LUPETTO_CREDENTIAL_SUBPROCESS")
	if mode == "" {
		return
	}
	var result Result
	if err := json.Unmarshal([]byte(os.Getenv("LUPETTO_CREDENTIAL_RESULT")), &result); err != nil {
		t.Fatal("invalid subprocess fixture")
	}
	outcome, err := publishOCIImage(context.Background(), Services{}, result, PublicationOptions{Registry: os.Getenv("LUPETTO_CREDENTIAL_HOST"), Repository: "team/images"})
	if mode == "success" {
		if err != nil || outcome.Status != "published" || !outcome.Verified {
			t.Fatal("helper authentication did not publish and verify")
		}
		fmt.Println("published and verified")
		return
	}
	want := "publication push failed"
	if mode == "not-found" {
		want += " (HTTP 401; UNAUTHORIZED)"
	}
	if err == nil || err.Error() != want || outcome.Status != "failed" || outcome.Verified {
		t.Fatal("helper error did not produce the expected sanitized publication failure")
	}
	result.Publication = outcome
	result.Build, result.DockerLoad, result.Signing, result.Attestation = "completed", "skipped", "skipped", "skipped"
	failure := NewWorkflowFailure(result, "publication", err, true)
	data, readErr := os.ReadFile(filepath.Join(result.Workspace, "failure.json"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, text := range []string{err.Error(), failure.Error(), string(failure.Record), string(data)} {
		if strings.Contains(text, credentialHelperCanary) || strings.Contains(text, buildtest.RegistryPassword) || strings.Contains(text, buildtest.PublicationCanary) {
			t.Fatal("helper diagnostics escaped into returned error or failure record")
		}
	}
	fmt.Println(failure.Error())
	fmt.Println(string(failure.Record))
}

func TestDockerConfigKeychainCredentialHelperResponses(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"not found", "printf '%s\\n' 'credentials not found in native keychain'\nexit 1\n", ""},
		{"exit failure", "printf '%s\\n' '" + credentialHelperCanary + "'\nprintf '%s\\n' '" + credentialHelperCanary + "' >&2\nexit 1\n", "Docker credential helper failed"},
		{"malformed response", "printf '%s\\n' '" + credentialHelperCanary + "'\n", "Docker credential helper response is invalid"},
		{"oversized stdout", "i=0\nwhile [ $i -lt 2049 ]; do printf '0123456789abcdef0123456789abcdef'; i=$((i+1)); done\n", "Docker credential helper output exceeded limit"},
		{"oversized not found", "i=0\nwhile [ $i -lt 65536 ]; do printf ' '; i=$((i+1)); done\nprintf '%s' 'credentials not found in native keychain'\nexit 1\n", "Docker credential helper output exceeded limit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			configDir := isolateCredentialHelper(t)
			writeCredentialConfig(t, configDir, map[string]any{"credsStore": "fixture"})
			writeCredentialHelper(t, "fixture", tc.body)
			auth, err := (dockerConfigKeychain{}).Resolve(credentialResource(t, "registry.example.invalid/team/image"))
			if tc.want == "" {
				if err != nil || auth != authn.Anonymous {
					t.Fatal("not-found helper should resolve anonymously")
				}
				return
			}
			if err == nil || err.Error() != tc.want || strings.Contains(err.Error(), credentialHelperCanary) {
				t.Fatal("helper failure was not the fixed sanitized error")
			}
		})
	}
}

func TestDockerConfigKeychainRejectsInvalidHelperWithoutExec(t *testing.T) {
	for _, helper := range []string{"../fixture", "fixture/unsafe", "-fixture", "fixture;echo", "fixture secret", "fixture\nsecret"} {
		t.Run(strconv.Quote(helper), func(t *testing.T) {
			configDir := isolateCredentialHelper(t)
			marker := filepath.Join(t.TempDir(), "executed")
			t.Setenv("LUPETTO_HELPER_MARKER", marker)
			// This executable would be found without name validation.
			if !strings.Contains(helper, "/") {
				writeCredentialHelper(t, helper, ": > \"$LUPETTO_HELPER_MARKER\"\n")
			}
			writeCredentialConfig(t, configDir, map[string]any{"credsStore": helper})
			_, err := (dockerConfigKeychain{}).Resolve(credentialResource(t, "registry.example.invalid/team/image"))
			if err == nil || err.Error() != "Docker credential helper name is invalid" {
				t.Fatal("invalid helper name was not rejected")
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid helper was executed")
			}
		})
	}
}

func TestDockerConfigKeychainCredentialHelperIdentityToken(t *testing.T) {
	configDir := isolateCredentialHelper(t)
	writeCredentialConfig(t, configDir, map[string]any{"credsStore": "fixture"})
	writeCredentialHelper(t, "fixture", "printf '%s\\n' '{\"ServerURL\":\"ignored\",\"Username\":\"<token>\",\"Secret\":\"synthetic-identity-token\"}'\n")
	auth, err := (dockerConfigKeychain{}).Resolve(credentialResource(t, "registry.example.invalid/team/image"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := auth.Authorization()
	if err != nil || cfg.IdentityToken != "synthetic-identity-token" || cfg.Username != "" || cfg.Password != "" {
		t.Fatal("token helper credentials did not map to IdentityToken")
	}
}

func TestDockerConfigKeychainCredentialHelperCancellation(t *testing.T) {
	for _, mode := range []string{"resolve", "publication"} {
		t.Run(mode, func(t *testing.T) {
			configDir := isolateCredentialHelper(t)
			writeCredentialConfig(t, configDir, map[string]any{"credsStore": "fixture"})
			marker := filepath.Join(t.TempDir(), "started")
			t.Setenv("LUPETTO_HELPER_MARKER", marker)
			writeCredentialHelper(t, "fixture", "printf '%s' \"$$\" > \"$LUPETTO_HELPER_MARKER\"\nexec /bin/sleep 30\n")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			resource := credentialResource(t, "registry.example.invalid/team/image")
			var result Result
			var host string
			if mode == "publication" {
				host = buildtest.NewRegistry(t, "auth", nil).Host
				result, _ = publicationTestResult(t, "x86_64")
			}
			done := make(chan error, 1)
			go func() {
				var err error
				if mode == "publication" {
					_, err = publishOCIImage(ctx, Services{}, result, PublicationOptions{Registry: host, Repository: "team/images"})
				} else {
					_, err = authn.Resolve(ctx, dockerConfigKeychain{}, resource)
				}
				done <- err
			}()
			deadline := time.Now().Add(5 * time.Second)
			var pid int
			for time.Now().Before(deadline) {
				data, err := os.ReadFile(marker)
				if err == nil {
					pid, _ = strconv.Atoi(string(data))
					if pid > 0 {
						break
					}
				}
				time.Sleep(5 * time.Millisecond)
			}
			cancel()
			select {
			case err := <-done:
				if pid <= 0 || !errors.Is(err, context.Canceled) {
					t.Fatal("helper was not started and canceled through ContextKeychain")
				}
				if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
					t.Fatal("canceled helper process is still alive")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("context cancellation did not promptly stop the helper")
			}
		})
	}
}

func TestDockerConfigKeychainCredentialHelperLookupOrderAndFileStore(t *testing.T) {
	configDir := isolateCredentialHelper(t)
	resource := credentialResource(t, "registry.example.invalid/team/image")
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("LUPETTO_HELPER_CALLS", calls)
	writeCredentialHelper(t, "fixture-1.0_safe", "printf '%s\\n' \"$key\" >> \"$LUPETTO_HELPER_CALLS\"\nif [ \"$key\" = registry.example.invalid/team/image ]; then printf '%s\\n' 'credentials not found in native keychain'; exit 1; fi\nprintf '%s\\n' '{\"Username\":\"helper-user\",\"Secret\":\"helper-password\"}'\n")
	writeCredentialConfig(t, configDir, map[string]any{"credsStore": "fixture-1.0_safe", "auths": map[string]any{resource.RegistryStr(): map[string]string{"username": "file-user", "password": "file-password", "registrytoken": "file-registry-token"}}})
	auth, err := (dockerConfigKeychain{}).Resolve(resource)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := auth.Authorization()
	if err != nil || cfg.Username != "helper-user" || cfg.Password != "helper-password" || cfg.RegistryToken != "file-registry-token" {
		t.Fatal("helper fields did not replace file credentials while preserving RegistryToken")
	}
	data, err := os.ReadFile(calls)
	if err != nil || string(data) != resource.String()+"\n"+resource.RegistryStr()+"\n" {
		t.Fatal("lookup did not try repository before registry")
	}
	if err := os.Remove(calls); err != nil {
		t.Fatal(err)
	}
	// Explicit empty entries override the default helper; the file-store path
	// cannot execute a helper even with a default configured for other keys.
	writeCredentialConfig(t, configDir, map[string]any{"credsStore": "fixture-1.0_safe", "credHelpers": map[string]string{resource.String(): "", resource.RegistryStr(): ""}, "auths": map[string]any{resource.RegistryStr(): map[string]string{"username": "file-user", "password": "file-password"}}})
	auth, err = (dockerConfigKeychain{}).Resolve(resource)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err = auth.Authorization()
	if err != nil || cfg.Username != "file-user" || cfg.Password != "file-password" {
		t.Fatal("explicit empty helper did not use the file store")
	}
	if _, err := os.Stat(calls); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("file-store lookup executed a helper")
	}
}

func TestDockerConfigKeychainCredentialHelperDockerHubKey(t *testing.T) {
	configDir := isolateCredentialHelper(t)
	writeCredentialConfig(t, configDir, map[string]any{"credsStore": "invalid/default", "credHelpers": map[string]string{"index.docker.io/team/image": "", authn.DefaultAuthKey: "fixture"}})
	writeCredentialHelper(t, "fixture", "[ \"$key\" = 'https://index.docker.io/v1/' ] || exit 1\nprintf '%s\\n' '{\"Username\":\"hub-user\",\"Secret\":\"hub-password\"}'\n")
	auth, err := (dockerConfigKeychain{}).Resolve(credentialResource(t, "index.docker.io/team/image"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := auth.Authorization()
	if err != nil || cfg.Username != "hub-user" || cfg.Password != "hub-password" {
		t.Fatal("Docker Hub registry lookup did not use DefaultAuthKey")
	}
}
