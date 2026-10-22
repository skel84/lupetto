package imageconfig

import (
	"strings"
	"testing"
)

func TestValidateEntrypoint(t *testing.T) {
	for _, valid := range [][]string{
		{"/usr/bin/kyverno"},
		{"/usr/bin/memcached", "-u", "memcached"},
		{"/usr/bin/tool", "--flag=a value with spaces", "#not-a-comment"},
	} {
		if err := ValidateEntrypoint(valid); err != nil {
			t.Errorf("%q rejected: %v", valid, err)
		}
	}
	tooMany := make([]string, maxEntrypointElements+1)
	for i := range tooMany {
		tooMany[i] = "/x"
	}
	for _, invalid := range [][]string{
		nil,
		{},
		{"kyverno"},
		{"usr/bin/kyverno"},
		{"/"},
		{"/usr/bin/../bin/kyverno"},
		{"/usr/bin/kyverno/"},
		{"/usr//bin/kyverno"},
		{"/usr/bin/kyverno", ""},
		{"/usr/bin/kyverno", "it's"},
		{"/usr/bin/kyverno", "line\nbreak"},
		{"/usr/bin/kyverno", "\x00"},
		{"/usr/bin/kyverno", string([]byte{0xff})},
		{"/usr/bin/kyverno", strings.Repeat("a", maxElementBytes+1)},
		tooMany,
	} {
		if err := ValidateEntrypoint(invalid); err == nil {
			t.Errorf("%q accepted", invalid)
		}
	}
}

func TestAnnotationsRoundTrip(t *testing.T) {
	if annotations := (Options{}).Annotations(); len(annotations) != 0 {
		t.Fatalf("empty options produced annotations %v", annotations)
	}
	options := Options{Entrypoint: []string{"/usr/bin/tool", "--name=<a&b>", "two words"}}
	annotations := options.Annotations()
	if len(annotations) != 1 || annotations[EntrypointAnnotation] == "" {
		t.Fatalf("annotations=%v", annotations)
	}
	parsed, err := FromAnnotations(annotations)
	if err != nil || !parsed.Equal(options) {
		t.Fatalf("round trip=%+v err=%v", parsed, err)
	}
	none, err := FromAnnotations(map[string]string{"lupetto.apk.name": "tool"})
	if err != nil || !none.Equal(Options{}) || none.Entrypoint != nil {
		t.Fatalf("absent annotation=%+v err=%v", none, err)
	}
	for _, malformed := range []string{"", "/usr/bin/tool", `"/usr/bin/tool"`, `[]`, `["tool"]`, `[1]`, `["/usr/bin/tool"] x`} {
		if _, err := FromAnnotations(map[string]string{EntrypointAnnotation: malformed}); err == nil {
			t.Errorf("malformed annotation %q accepted", malformed)
		}
	}
}

func TestEqual(t *testing.T) {
	a := Options{Entrypoint: []string{"/usr/bin/a"}}
	for _, different := range []Options{{}, {Entrypoint: []string{"/usr/bin/b"}}, {Entrypoint: []string{"/usr/bin/a", "x"}}} {
		if a.Equal(different) || different.Equal(a) {
			t.Errorf("%+v equals %+v", a, different)
		}
	}
	if !(Options{}).Equal(Options{Entrypoint: []string{}}) {
		t.Error("nil and empty entrypoints must compare equal")
	}
}

func TestApkoCommandQuotesEachElement(t *testing.T) {
	got := ApkoCommand([]string{"/usr/bin/tool", "two words", "--x=#y"})
	if want := `'/usr/bin/tool' 'two words' '--x=#y'`; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestCABundleOption(t *testing.T) {
	options := Options{CABundle: true}
	annotations := options.Annotations()
	if len(annotations) != 1 || annotations[CABundleAnnotation] != "true" {
		t.Fatalf("annotations=%v", annotations)
	}
	parsed, err := FromAnnotations(annotations)
	if err != nil || !parsed.Equal(options) || parsed.Equal(Options{}) {
		t.Fatalf("round trip=%+v err=%v", parsed, err)
	}
	both := Options{Entrypoint: []string{"/usr/bin/a"}, CABundle: true}
	if parsed, err := FromAnnotations(both.Annotations()); err != nil || !parsed.Equal(both) || parsed.Equal(Options{Entrypoint: both.Entrypoint}) {
		t.Fatalf("combined round trip=%+v err=%v", parsed, err)
	}
	for _, malformed := range []string{"", "false", "TRUE", "yes", "1"} {
		if _, err := FromAnnotations(map[string]string{CABundleAnnotation: malformed}); err == nil {
			t.Errorf("malformed annotation %q accepted", malformed)
		}
	}
}
