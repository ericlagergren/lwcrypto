//go:build gc && !purego
// +build gc,!purego

package ascon

//go:noescape
func p12(s *state)

//go:noescape
func p8(s *state)

//go:noescape
func p6(s *state)

//go:noescape
func round(s *state, C uint64)

//go:noescape
func additionalData128a(s *state, ad []byte)

//go:noescape
func encryptBlocks128a(s *state, dst, src []byte)

//go:noescape
func decryptBlocks128a(s *state, dst, src []byte)
