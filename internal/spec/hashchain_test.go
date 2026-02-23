package spec

import (
	"crypto/sha256"
	"testing"
)

func TestHashChainRoot_Empty(t *testing.T) {
	// arrange
	seed := []byte("session-attested:session-1")

	// act
	got := HashChainRoot(seed, nil)

	// assert
	want := sha256.Sum256(seed)
	if got.Root != want {
		t.Fatalf("root mismatch: got=%s want=%s", Hex32(got.Root), Hex32(want))
	}
	if got.Count != 0 {
		t.Fatalf("count mismatch: got=%d want=0", got.Count)
	}
}

func TestHashChainRoot_SingleEvent(t *testing.T) {
	seed := []byte("session-attested:session-1")
	ev := []byte(`{"a":1}`) // assume canonical already

	h0 := sha256.Sum256(seed)
	x1 := sha256.Sum256(ev)

	var in [64]byte
	copy(in[0:32], h0[:])
	copy(in[32:64], x1[:])
	want := sha256.Sum256(in[:])

	got := HashChainRoot(seed, [][]byte{ev})
	if got.Root != want {
		t.Fatalf("root mismatch: got=%s want=%s", Hex32(got.Root), Hex32(want))
	}
	if got.Count != 1 {
		t.Fatalf("count mismatch: got=%d want=1", got.Count)
	}
}
