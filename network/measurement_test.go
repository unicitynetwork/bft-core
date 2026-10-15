package network

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// Receiver fan-out of one certification response: the framed bytes are produced
// once per dispatch and shared between recipients, so serialization work is flat
// in the number of recipients while outgoing bytes are linear in it.
// Opt in with UC_MEASURE=1; see docs/uc-consolidation-measurements.md.
func Test_ScalingRecipientFanout(t *testing.T) {
	if os.Getenv("UC_MEASURE") == "" {
		t.Skip("set UC_MEASURE=1 to run the scaling measurements")
	}
	view := make([]byte, 1544) // typical 8-shard view
	cr := testCertResponse(t, view)
	build := testing.AllocsPerRun(20, func() {
		frames := &certificationFrames{cr: cr}
		_, _ = frames.v2Frame()
		_, _ = frames.legacy()
	})
	frames := &certificationFrames{cr: cr}
	v2, err := frames.v2Frame()
	require.NoError(t, err)
	_, err = frames.legacy()
	require.NoError(t, err)
	cached := testing.AllocsPerRun(1000, func() {
		_, _ = frames.v2Frame()
		_, _ = frames.legacy()
	})
	require.Zero(t, cached, "serving a further recipient from the dispatch's frames allocates nothing")

	var sb strings.Builder
	sb.WriteString("| recipients f | allocations to build both frames (once) | allocations for the other f-1 recipients | outgoing B (V2) |\n|---|---|---|---|\n")
	for f := 1; f <= 256; f *= 2 {
		sb.WriteString(fmtRow(f, uint64(build), uint64(cached)*uint64(f-1), len(v2)*f))
	}
	t.Logf("one V2 frame is %d B; the V1 and V2 frames are each serialized once per dispatch\n%s", len(v2), sb.String())
}

func fmtRow(f int, build, others uint64, out int) string {
	return "| " + itoa(f) + " | " + itoa(int(build)) + " | " + itoa(int(others)) + " | " + itoa(out) + " |\n"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

var _ = certification.MaxPartitionViewSize
