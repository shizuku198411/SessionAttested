package spec

import (
	"crypto/sha256"
	"encoding/hex"
)

type HashChainResult struct {
	Root  [32]byte
	Count uint64
}

// HashChainRoot computes:
// h0 = sha256(seed)
// hi+1 = sha256(hi || sha256(event_i))
// event_i must already be canonical bytes.
// Events are processed in ascending seq order by caller.
func HashChainRoot(seed []byte, canonicalEvents [][]byte) HashChainResult {
	h := sha256.Sum256(seed)
	var count uint64

	for _, ev := range canonicalEvents {
		x := sha256.Sum256(ev)
		var in [64]byte
		copy(in[0:32], h[:])
		copy(in[32:64], x[:])
		h = sha256.Sum256(in[:])
		count++
	}
	return HashChainResult{Root: h, Count: count}
}

func Hex32(b [32]byte) string {
	return hex.EncodeToString(b[:])
}
