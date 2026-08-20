package rsmt

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestCrossLanguageFixtures loads envelope fixtures produced by the Rust
// side (crates/rsmt/examples/dump_envelope_fixtures.rs) and verifies that
// the Go implementation accepts each one. This is the authoritative check
// that the two implementations stay wire-compatible.
//
// Regenerate with:
//
//	cargo run --example dump_envelope_fixtures -- \
//	    bft-core/rootchain/consensus/zkverifier/rsmt/testdata
func TestCrossLanguageFixtures(t *testing.T) {
	path := filepath.Join("testdata", "fixtures.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var doc struct {
		// ReferenceTime is the round reference time the fixtures build their
		// new leaves under; the verifier derives each stored leaf value from
		// the declared transaction hash and this value.
		ReferenceTime uint64 `json:"reference_time"`
		Fixtures      []struct {
			Name     string `json:"name"`
			PrevRoot string `json:"prev_root"`
			NewRoot  string `json:"new_root"`
			Envelope string `json:"envelope"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse fixtures.json: %v", err)
	}
	if len(doc.Fixtures) == 0 {
		t.Fatal("no fixtures loaded")
	}
	if doc.ReferenceTime == 0 {
		t.Fatal("fixtures carry no reference time")
	}

	decodeRoot := func(s string) (Root, error) {
		if s == "" {
			return Root{}, nil
		}
		b, err := hex.DecodeString(s)
		if err != nil {
			return Root{}, err
		}
		return RootFromBytes(b)
	}

	for _, f := range doc.Fixtures {
		t.Run(f.Name, func(t *testing.T) {
			envBytes, err := hex.DecodeString(f.Envelope)
			if err != nil {
				t.Fatalf("decode envelope: %v", err)
			}
			env, err := DecodeEnvelope(envBytes)
			if err != nil {
				t.Fatalf("DecodeEnvelope: %v", err)
			}
			prev, err := decodeRoot(f.PrevRoot)
			if err != nil {
				t.Fatalf("prev_root: %v", err)
			}
			newR, err := decodeRoot(f.NewRoot)
			if err != nil {
				t.Fatalf("new_root: %v", err)
			}
			if err := Verify(env, prev, newR, doc.ReferenceTime); err != nil {
				t.Fatalf("Verify(%s): %v", f.Name, err)
			}

			// A different reference time derives different leaf values, so the
			// same envelope must no longer reproduce the claimed root. This is
			// what makes a wrong reference time unrepresentable.
			if len(env.Leaves) > 0 {
				if err := Verify(env, prev, newR, doc.ReferenceTime+1); err == nil {
					t.Fatalf("Verify(%s): accepted a wrong reference time", f.Name)
				}
			}

			// Round-trip: re-encode the decoded envelope and confirm it
			// matches the original bytes exactly, locking the wire format.
			reenc, err := EncodeEnvelope(env.Leaves, env.Proof)
			if err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			if string(reenc) != string(envBytes) {
				t.Fatalf("envelope re-encode mismatch for %s", f.Name)
			}
		})
	}
}
