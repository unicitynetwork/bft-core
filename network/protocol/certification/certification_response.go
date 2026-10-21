package certification

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// Status codes for CertificationResponse.Status. Status is a transport-level
// field on the outer response wrapper — it is NEVER hashed into the UC — and
// it only describes why *this particular response message* was generated.
// The wrapped UC is still the last-good certificate regardless of status.
const (
	// CertStatusOK — request was accepted and UC is the newly certified one.
	CertStatusOK uint32 = 0
	// CertStatusTransient — root-side transient error (consensus manager unavailable,
	// send failure, etc). Submitter SHOULD retry with the same batch.
	CertStatusTransient uint32 = 1
	// CertStatusRequestInvalid — ValidRequest failed (stale round/epoch, timestamp
	// drift, bad signature, bad prev-hash). Submitter SHOULD resync from the
	// attached UC and retry.
	CertStatusRequestInvalid uint32 = 2
	// CertStatusProofInvalid — ZK proof verification failed. The batch and its
	// proof are inconsistent. Submitter SHOULD drop this batch; a new batch may succeed.
	CertStatusProofInvalid uint32 = 3
	// CertStatusFatal — unrecoverable (unknown proof type, mandatory verifier not
	// configured, schema mismatch). Submitter SHOULD stop retrying and alert.
	CertStatusFatal uint32 = 255
)

// MaxStatusMessageLen caps the free-form diagnostic string on the wire so a
// misbehaving or malicious root cannot blast unbounded strings at partitions.
const MaxStatusMessageLen = 512

/*
Certification response is sent by the root partition to validators of a shard of a partition
as a response to a certification request message.

Status and Message are outer transport-level fields. Status == CertStatusOK means
the request was accepted and UC is the newly certified one. A non-zero Status means
the request was rejected for the reason encoded in Status/Message; the wrapped UC
in that case is the last-good certificate so the submitter can resync its state.
*/
type CertificationResponse struct {
	_         struct{} `cbor:",toarray"`
	Partition types.PartitionID
	Shard     types.ShardID
	Technical TechnicalRecord
	UC        types.UnicityCertificate
	Status    uint32
	Message   string
}

// IsAccepted reports whether the wrapped UC represents acceptance of the
// request that triggered this response.
func (cr *CertificationResponse) IsAccepted() bool {
	return cr != nil && cr.Status == CertStatusOK
}

// IsValid validates the structural integrity of the wrapped UC and technical
// record. It intentionally does NOT reject non-OK Status values: the wrapped
// UC is still the last-good certificate even on a rejection.
func (cr *CertificationResponse) IsValid() error {
	if cr == nil {
		return errors.New("nil CertificationResponse")
	}
	if cr.Partition == 0 {
		return errors.New("partition ID is unassigned")
	}
	if cr.UC.UnicityTreeCertificate == nil {
		return errors.New("UnicityTreeCertificate is unassigned")
	}
	if utcP := cr.UC.UnicityTreeCertificate.Partition; utcP != cr.Partition {
		return fmt.Errorf("partition %s doesn't match UnicityTreeCertificate partition %s", cr.Partition, utcP)
	}

	if err := cr.Technical.IsValid(); err != nil {
		return fmt.Errorf("invalid TechnicalRecord: %w", err)
	}
	if err := cr.Technical.HashMatches(cr.UC.TRHash); err != nil {
		return fmt.Errorf("comparing TechnicalRecord hash to UC.TRHash: %w", err)
	}

	return nil
}

func (cr *CertificationResponse) SetTechnicalRecord(tr TechnicalRecord) error {
	h, err := tr.Hash()
	if err != nil {
		return fmt.Errorf("calculating TR hash: %w", err)
	}
	cr.UC.TRHash = h
	cr.Technical = tr
	return nil
}

// UnmarshalCBOR provides backward compatibility for the pre-status wire format
// (4 array elements, before Status/Message were added). Existing rootchain.db
// snapshots and older peers encode the old shape; we decode either and fill
// Status/Message with zero values when they're absent.
// TODO: remove eventually.
func (cr *CertificationResponse) UnmarshalCBOR(data []byte) error {
	// Try the new 6-element format first.
	type newFormat struct {
		_         struct{} `cbor:",toarray"`
		Partition types.PartitionID
		Shard     types.ShardID
		Technical TechnicalRecord
		UC        types.UnicityCertificate
		Status    uint32
		Message   string
	}
	var nf newFormat
	if err := types.Cbor.Unmarshal(data, &nf); err == nil {
		cr.Partition = nf.Partition
		cr.Shard = nf.Shard
		cr.Technical = nf.Technical
		cr.UC = nf.UC
		cr.Status = nf.Status
		cr.Message = nf.Message
		return nil
	}

	// Fall back to the old 4-element format.
	type oldFormat struct {
		_         struct{} `cbor:",toarray"`
		Partition types.PartitionID
		Shard     types.ShardID
		Technical TechnicalRecord
		UC        types.UnicityCertificate
	}
	var of oldFormat
	if err := types.Cbor.Unmarshal(data, &of); err != nil {
		return err
	}
	cr.Partition = of.Partition
	cr.Shard = of.Shard
	cr.Technical = of.Technical
	cr.UC = of.UC
	cr.Status = CertStatusOK
	cr.Message = ""
	return nil
}
