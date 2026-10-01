package wolfi

import (
	"strings"
	"testing"

	"lupetto/internal/wolfi/wolfitest"
)

func makeSignedIndex(t *testing.T) ([]byte, []byte) {
	return wolfitest.MakeSignedIndexFor(t, "P:postgresql-17\nV:17.10-r1\nA:x86_64\nC:Q1checksum\n\n")
}

func TestVerifyAPKINDEXAuthenticatesSelectedSnapshot(t *testing.T) {
	signed, key := makeSignedIndex(t)
	verified, err := VerifyAPKINDEX(signed, key)
	if err != nil {
		t.Fatalf("valid index rejected: %v", err)
	}
	packages, err := ParseAPKINDEX(verified, "postgresql-17")
	if err != nil || len(packages) != 1 || packages[0].Version != "17.10-r1" {
		t.Fatalf("parse verified index: %+v, %v", packages, err)
	}
	signed[len(signed)-16] ^= 1
	if _, err := VerifyAPKINDEX(signed, key); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("altered signed index accepted: %v", err)
	}
	if _, err := VerifyAPKINDEX(wolfitest.MakeIndex(t, "P:postgresql-17\n"), key); err == nil {
		t.Fatal("unsigned index accepted")
	}
}
