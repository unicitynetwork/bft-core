package cmd

import (
	"fmt"
	"strconv"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-core/txsystem"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

const (
	moneyInitialBillValue          = "initialBillValue"
	moneyInitialBillOwnerPredicate = "initialBillOwnerPredicate"
	moneyDCMoneySupplyValue        = "dcMoneySupplyValue"

	tokensAdminOwnerPredicate = "adminOwnerPredicate"
	tokensFeelessMode         = "feeless-mode"

	orchestrationOwnerPredicate = "ownerPredicate"
)

type MoneyPartitionParams struct {
	InitialBillValue          uint64
	InitialBillOwnerPredicate types.PredicateBytes
	DCMoneySupplyValue        uint64 // The initial value for Dust Collector money supply. Total money supply is initial bill + DC money supply.
}

type OrchestrationPartitionParams struct {
	OwnerPredicate types.PredicateBytes // the Proof-of-Authority owner predicate
}

type TokensPartitionParams struct {
	AdminOwnerPredicate types.PredicateBytes // the admin owner predicate for permissioned mode
	FeelessMode         bool                 // if true then fees are not charged (applies only in permissioned mode)
}

func ParseMoneyPartitionParams(shardConf *types.PartitionDescriptionRecord) (*MoneyPartitionParams, error) {
	var params MoneyPartitionParams
	for key, valueStr := range shardConf.PartitionParams {
		switch key {
		case moneyInitialBillValue:
			parsedValue, err := parseUint64(key, valueStr)
			if err != nil {
				return nil, err
			}
			params.InitialBillValue = parsedValue
		case moneyInitialBillOwnerPredicate:
			value, err := hex.Decode([]byte(valueStr))
			if err != nil {
				return nil, fmt.Errorf("failed to parse param %q value: %w", key, err)
			}
			params.InitialBillOwnerPredicate = value
		case moneyDCMoneySupplyValue:
			parsedValue, err := parseUint64(key, valueStr)
			if err != nil {
				return nil, err
			}
			params.DCMoneySupplyValue = parsedValue
		default:
			return nil, fmt.Errorf("unexpected partition param: %s", key)
		}
	}
	return &params, nil
}

func ParseOrchestrationPartitionParams(shardConf txsystem.ShardConf) (*OrchestrationPartitionParams, error) {
	var params OrchestrationPartitionParams
	for key, valueStr := range shardConf.GetPartitionParams() {
		switch key {
		case orchestrationOwnerPredicate:
			value, err := hex.Decode([]byte(valueStr))
			if err != nil {
				return nil, fmt.Errorf("failed to parse param %q value: %w", key, err)
			}
			params.OwnerPredicate = value
		default:
			return nil, fmt.Errorf("unexpected partition param: %s", key)
		}
	}
	return &params, nil
}

func ParseTokensPartitionParams(shardConf txsystem.ShardConf) (*TokensPartitionParams, error) {
	var params TokensPartitionParams
	for key, valueStr := range shardConf.GetPartitionParams() {
		switch key {
		case tokensAdminOwnerPredicate:
			{
				value, err := hex.Decode([]byte(valueStr))
				if err != nil {
					return nil, fmt.Errorf("failed to parse param %q value: %w", key, err)
				}
				params.AdminOwnerPredicate = value
			}
		case tokensFeelessMode:
			{
				value, err := strconv.ParseBool(valueStr)
				if err != nil {
					return nil, fmt.Errorf("failed to parse param %q value: %w", key, err)
				}
				params.FeelessMode = value
			}
		default:
			return nil, fmt.Errorf("unexpected partition param: %s", key)
		}
	}
	return &params, nil
}

func parseUint64(key, value string) (uint64, error) {
	ret, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse param %q value: %w", key, err)
	}
	return ret, nil
}

// ProofPartitionParams holds parsed proof configuration from partition params.
type ProofPartitionParams struct {
	// ProofType specifies the proof type for the partition.
	// Empty/none means m-of-n signature verification only.
	ProofType zkverifier.ProofType

	// VerificationKeyPath is the path to the verification key file.
	// Required for SP1 proof type.
	VerificationKeyPath string
}

// ParseProofPartitionParams extracts proof configuration from partition params.
// Returns error if the configuration is invalid.
func ParseProofPartitionParams(params map[string]string) (*ProofPartitionParams, error) {
	result := &ProofPartitionParams{
		ProofType:           zkverifier.ParseProofTypeFromParams(params),
		VerificationKeyPath: zkverifier.ParseVKeyPathFromParams(params),
	}

	// Validate the configuration
	if result.ProofType != zkverifier.ProofTypeNone && result.ProofType != "" {
		if !zkverifier.IsProofTypeAvailable(result.ProofType) {
			return nil, fmt.Errorf("proof type %q not available (build with -tags zkverifier_ffi to enable)", result.ProofType)
		}

		if result.ProofType == zkverifier.ProofTypeSP1 && result.VerificationKeyPath == "" {
			return nil, fmt.Errorf("vkey_path required for SP1 proof type")
		}
	}

	return result, nil
}

// IsEnabled returns true if ZK proof verification is enabled for this configuration.
func (p *ProofPartitionParams) IsEnabled() bool {
	switch p.ProofType {
	case zkverifier.ProofTypeNone, zkverifier.ProofTypeExec, "":
		return false
	default:
		return true
	}
}

// ToPartitionParams converts the proof configuration to a partition params map.
func (p *ProofPartitionParams) ToPartitionParams() map[string]string {
	if p.ProofType == zkverifier.ProofTypeNone || p.ProofType == "" {
		return nil
	}

	params := map[string]string{
		zkverifier.ParamProofType: string(p.ProofType),
	}

	if p.VerificationKeyPath != "" {
		params[zkverifier.ParamVerificationKeyPath] = p.VerificationKeyPath
	}

	return params
}
