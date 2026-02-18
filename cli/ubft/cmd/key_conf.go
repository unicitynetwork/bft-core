package cmd

import (
	"fmt"

	p2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/network"
)

const (
	KeyAlgorithmSecp256k1 = "secp256k1"
)

type (
	KeyConf struct {
		SigKey  Key `json:"sigKey"`
		AuthKey Key `json:"authKey"`
	}

	Key struct {
		Algorithm  string    `json:"algorithm"`
		PrivateKey hex.Bytes `json:"privateKey"`
	}
)

func (c *KeyConf) NodeID() (peer.ID, error) {
	authPrivKey, err := p2pcrypto.UnmarshalSecp256k1PrivateKey(c.AuthKey.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("invalid authentication key: %w", err)
	}
	return peer.IDFromPrivateKey(authPrivKey)
}

func (c *KeyConf) Signer() (abcrypto.Signer, error) {
	signer, err := abcrypto.NewInMemorySecp256K1SignerFromKey(c.SigKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("invalid signing key: %w", err)
	}
	return signer, nil
}

func (c *KeyConf) AuthKeyPair() (*network.PeerKeyPair, error) {
	if c.AuthKey.Algorithm != KeyAlgorithmSecp256k1 {
		return nil, fmt.Errorf("unsupported authentication key algorithm %v", c.AuthKey.Algorithm)
	}
	authPrivKey, err := p2pcrypto.UnmarshalSecp256k1PrivateKey(c.AuthKey.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal authentication key: %w", err)
	}
	authPrivKeyBytes, err := authPrivKey.Raw()
	if err != nil {
		return nil, err
	}
	authPubKeyBytes, err := authPrivKey.GetPublic().Raw()
	if err != nil {
		return nil, err
	}
	return &network.PeerKeyPair{
		PublicKey:  authPubKeyBytes,
		PrivateKey: authPrivKeyBytes,
	}, nil
}
