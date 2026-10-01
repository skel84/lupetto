// Package wolfitest builds synthetic (optionally signed) APKINDEX archives
// for wolfi, build, and CLI tests. It must not import internal/wolfi.
package wolfitest

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func MakeSignedIndexFor(t *testing.T, records string) ([]byte, []byte) {
	t.Helper()
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&private.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	indexData := MakeIndex(t, records)
	digest := sha256.Sum256(indexData)
	sig, err := rsa.SignPKCS1v15(rand.Reader, private, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	var prefix bytes.Buffer
	gz := gzip.NewWriter(&prefix)
	archive := tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{Name: ".SIGN.RSA256.wolfi-signing.rsa.pub", Mode: 0600, Size: int64(len(sig))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write(sig); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return append(prefix.Bytes(), indexData...), publicPEM
}

func MakeIndex(t *testing.T, records string) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	archive := tar.NewWriter(gz)
	if err := archive.WriteHeader(&tar.Header{Name: "APKINDEX", Mode: 0600, Size: int64(len(records))}); err != nil {
		t.Fatal(err)
	}
	if _, err := archive.Write([]byte(records)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}
