# lwcrypto
<p align="center">
<a href="https://pkg.go.dev/github.com/ericlagergren/lwcrypto"><img src="https://pkg.go.dev/badge/github.com/ericlagergren/lwcrypto.svg" alt="Go Reference"></a>
</p>

<p align="center">NIST Lightweight Cryptography</p>

This module implements NIST Lightweight Cryptography finalists.

## Installation

Each implementation can be installed using Go modules. For
example:

```bash
go get github.com/ericlagergren/lwcrypto@latest
```

## Usage

The APIs conform to Go's `crypto/cipher` package. Note that the
following example is not a substitute for reading the package's
documentation.

```go
package main

import (
	"crypto/rand"

	"github.com/ericlagergren/lwcrypto/ascon"
)

func main() {
	// Keys must be KeySize bytes long. Anything else is an
	// error.
	key := make([]byte, ascon.KeySize)
	if _, err := rand.Read(key); err != nil {
		// rand.Read failing is almost always catastrophic.
		panic(err)
	}

	// Nonces must be NonceSize bytes long. Anything else is an
	// error.
	nonce := make([]byte, ascon.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		// rand.Read failing is almost always catastrophic.
		panic(err)
	}

	aead, err := ascon.New128(key)
	if err != nil {
		// New128 (and New128a) should only return an error if
		// the key is not KeySize bytes long.
		panic(err)
	}

	// Plaintext is encrypted and authenticated.
	plaintext := []byte("example plaintext")

	// Additional data is authenticated alongside the plaintext,
	// but not included in the ciphertext.
	additionalData := []byte("example additional authenticated data")

	// Encrypt and authenticate |plaintext| and authenticate
	// |additionalData|.
	ciphertext := aead.Seal(nil, nonce, plaintext, additionalData)

	// Decrypt and authentiate |ciphertext| and authenticate
	// |additionalData|.
	plaintext, err = aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		// Authentication failed. Either the ciphertext or
		// additionalData (or both) were invalid for the 
		// (key, nonce) pair.
		[...]
	}
}
```

## Security

### Disclosure

This project uses full disclosure. If you find a security bug in
an implementation, please e-mail me or create a GitHub issue.

### Disclaimer

You should only use cryptography libraries that have been
reviewed by cryptographers or cryptography engineers. While I am
a cryptography engineer, I'm not your cryptography engineer, and
I have not had this project reviewed by any other cryptographers.
