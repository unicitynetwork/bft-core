package rsmt

// bitReverseTable reverses the bits within a single byte.
// bitReverseTable[0b0000_0001] == 0b1000_0000, etc.
var bitReverseTable [256]byte

func init() {
	for i := 0; i < 256; i++ {
		var r byte
		for bit := 0; bit < 8; bit++ {
			if (i>>bit)&1 != 0 {
				r |= 1 << (7 - bit)
			}
		}
		bitReverseTable[i] = r
	}
}

// SortKey converts a 256-bit SMT key into its LSB-first lexicographic sort
// order by bit-reversing each byte in place (no byte-order reversal).
// Matches `get_sort_key` in crates/rsmt/src/path.rs.
func SortKey(key [32]byte) [32]byte {
	var out [32]byte
	for i := 0; i < 32; i++ {
		out[i] = bitReverseTable[key[i]]
	}
	return out
}

// sortKeyLess reports whether SortKey(a) < SortKey(b).
func sortKeyLess(a, b [32]byte) bool {
	sa := SortKey(a)
	sb := SortKey(b)
	for i := 0; i < 32; i++ {
		if sa[i] != sb[i] {
			return sa[i] < sb[i]
		}
	}
	return false
}
