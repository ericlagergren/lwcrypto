// +build !amd64 !gc purego

package grain

func next(s *state) uint32 {
	return nextGeneric(s)
}

func accumulate(s *state, ms, pt uint16) {
	accumulateGeneric(s, ms, pt)
}
