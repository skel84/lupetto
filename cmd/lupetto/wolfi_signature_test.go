package main

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
	"strings"
	"testing"
)

func makeSignedIndex(t *testing.T) ([]byte, []byte) {
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
	indexData := makeIndex(t, "P:postgresql-17\nV:17.10-r1\nA:x86_64\nC:Q1checksum\n\n")
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

func TestVerifyAPKINDEXAuthenticatesSelectedSnapshot(t *testing.T) {
	signed, key := makeSignedIndex(t)
	verified, err := verifyAPKINDEX(signed, key)
	if err != nil {
		t.Fatalf("valid index rejected: %v", err)
	}
	packages, err := parseAPKINDEX(verified)
	if err != nil || len(packages) != 1 || packages[0].version != "17.10-r1" {
		t.Fatalf("parse verified index: %+v, %v", packages, err)
	}
	signed[len(signed)-16] ^= 1
	if _, err := verifyAPKINDEX(signed, key); err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("altered signed index accepted: %v", err)
	}
	if _, err := verifyAPKINDEX(makeIndex(t, "P:postgresql-17\n"), key); err == nil {
		t.Fatal("unsigned index accepted")
	}
}
