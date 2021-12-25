//go:build fuzz

package ascon

import (
	"bytes"
	"math/rand"
	"os"
	"testing"
	"time"

	ascon2 "lukechampine.com/ascon"
)

func TestFuzz(t *testing.T) {
	d := 2 * time.Second
	if s := os.Getenv("ASCON_FUZZ_TIMEOUT"); s != "" {
		var err error
		d, err = time.ParseDuration(s)
		if err != nil {
			t.Fatal(err)
		}
	} else if testing.Short() {
		d = 10 * time.Millisecond
	}
	tm := time.NewTimer(d)

	key := make([]byte, KeySize)
	nonce := make([]byte, NonceSize)
	plaintext := make([]byte, (BlockSize128*3)+BlockSize128-3)
	for {
		select {
		case <-tm.C:
			return
		default:
		}
		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		wantAead, err := ascon2.New(key)
		if err != nil {
			t.Fatal(err)
		}
		gotAead, err := New128(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(plaintext); err != nil {
			t.Fatal(err)
		}
		want := wantAead.Seal(nil, nonce, plaintext, nil)
		got := gotAead.Seal(nil, nonce, plaintext, nil)
		if !bytes.Equal(want, got) {
			t.Fatalf("expected %#x, got %#x", want, got)
		}
		ciphertext := want
		want, err = wantAead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err = gotAead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("expected %#x, got %#x", want, got)
		}
	}
}
