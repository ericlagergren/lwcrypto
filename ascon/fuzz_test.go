//go:build fuzz

package ascon_test

import (
	"bytes"
	"crypto/cipher"
	"os"
	"testing"
	"time"

	"github.com/ericlagergren/lwcrypto/ascon"
	ref "github.com/ericlagergren/lwcrypto/ascon/internal/asconc/ref"
	refa "github.com/ericlagergren/lwcrypto/ascon/internal/asconc/refa"
	rand "github.com/ericlagergren/saferand"
)

func TestFuzz(t *testing.T) {
	t.Run("128", func(t *testing.T) {
		t.Parallel()

		testFuzz(t, ref.New, ascon.New128)
	})
	t.Run("128a", func(t *testing.T) {
		t.Parallel()

		testFuzz(t, refa.New, ascon.New128a)
	})
}

func testFuzz(t *testing.T, ref, test func([]byte) (cipher.AEAD, error)) {
	d := 2 * time.Second
	if testing.Short() {
		d = 10 * time.Millisecond
	}
	if s := os.Getenv("ASCON_FUZZ_TIMEOUT"); s != "" {
		var err error
		d, err = time.ParseDuration(s)
		if err != nil {
			t.Fatal(err)
		}
	}
	tm := time.NewTimer(d)

	key := make([]byte, ascon.KeySize)
	nonce := make([]byte, ascon.NonceSize)
	plaintext := make([]byte, 1*1024*1024) // 1 MB
	for i := 0; ; i++ {
		select {
		case <-tm.C:
			t.Logf("iters: %d", i)
			return
		default:
		}

		if _, err := rand.Read(key); err != nil {
			t.Fatal(err)
		}
		if _, err := rand.Read(nonce); err != nil {
			t.Fatal(err)
		}
		n := rand.Intn(len(plaintext))
		if _, err := rand.Read(plaintext[:n]); err != nil {
			t.Fatal(err)
		}
		plaintext := plaintext[:n]

		refAead, err := ref(key)
		if err != nil {
			t.Fatal(err)
		}
		gotAead, err := test(key)
		if err != nil {
			t.Fatal(err)
		}

		wantCt := refAead.Seal(nil, nonce, plaintext, nil)
		gotCt := gotAead.Seal(nil, nonce, plaintext, nil)
		if !bytes.Equal(wantCt, gotCt) {
			t.Fatalf("expected %#x, got %#x", wantCt, gotCt)
		}

		wantPt, err := refAead.Open(nil, nonce, wantCt, nil)
		if err != nil {
			t.Fatal(err)
		}
		gotPt, err := gotAead.Open(nil, nonce, wantCt, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(wantPt, gotPt) {
			t.Fatalf("expected %#x, got %#x", wantPt, gotPt)
		}
	}
}
