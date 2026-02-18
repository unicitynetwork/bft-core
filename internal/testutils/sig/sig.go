package testsig

import (
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

func CreateSignerAndVerifier(t *testing.T) (abcrypto.Signer, abcrypto.Verifier) {
	t.Helper()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)

	verifier, err := signer.Verifier()
	require.NoError(t, err)
	return signer, verifier
}
