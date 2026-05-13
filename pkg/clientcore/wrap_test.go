package clientcore

import (
	"bytes"
	"strings"
	"testing"
)

func TestWrapPacketRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, wrapKeyLen)
	payload := []byte("dtls record bytes")

	wire, err := wrapPacket(key, payload)
	if err != nil {
		t.Fatalf("wrapPacket returned error: %v", err)
	}
	if len(wire) != len(payload)+wrapNonceLen {
		t.Fatalf("wire len = %d, want %d", len(wire), len(payload)+wrapNonceLen)
	}
	if bytes.Contains(wire, payload) {
		t.Fatalf("wrapped packet contains plaintext payload")
	}

	dst := make([]byte, len(payload))
	n, err := unwrapPacket(key, wire, dst)
	if err != nil {
		t.Fatalf("unwrapPacket returned error: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("unwrapped len = %d, want %d", n, len(payload))
	}
	if !bytes.Equal(dst[:n], payload) {
		t.Fatalf("round trip mismatch: got %q want %q", dst[:n], payload)
	}
}

func TestDecodeWrapKeyRequiresValidKeyWhenEnabled(t *testing.T) {
	if key, err := decodeWrapKey(false, ""); err != nil || key != nil {
		t.Fatalf("disabled decodeWrapKey = (%v, %v), want (nil, nil)", key, err)
	}

	if _, err := decodeWrapKey(true, ""); err == nil {
		t.Fatalf("decodeWrapKey accepted empty key")
	}

	shortHex := strings.Repeat("ab", wrapKeyLen-1)
	if _, err := decodeWrapKey(true, shortHex); err == nil {
		t.Fatalf("decodeWrapKey accepted short key")
	}

	fullHex := strings.Repeat("ab", wrapKeyLen)
	key, err := decodeWrapKey(true, fullHex)
	if err != nil {
		t.Fatalf("decodeWrapKey returned error: %v", err)
	}
	if len(key) != wrapKeyLen {
		t.Fatalf("decoded key len = %d, want %d", len(key), wrapKeyLen)
	}
}

func TestUnwrapPacketRejectsShortPacket(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, wrapKeyLen)
	if _, err := unwrapPacket(key, []byte("short"), make([]byte, 16)); err == nil {
		t.Fatalf("unwrapPacket accepted short packet")
	}
}
