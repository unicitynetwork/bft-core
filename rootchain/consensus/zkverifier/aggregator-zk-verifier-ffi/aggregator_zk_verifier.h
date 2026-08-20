/**
 * Aggregator ZK Verifier FFI
 *
 * C header for FFI interface to aggregator SP1 ZK proof verification.
 * Uses SP1 6.0.2; independent of sp1_verifier.h which uses SP1 5.0.8.
 */

#ifndef AGGREGATOR_ZK_VERIFIER_H
#define AGGREGATOR_ZK_VERIFIER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Result codes for aggregator ZK verification.
 *
 * The AGGZK_ prefix distinguishes these from SP1_VERIFY_* constants so that
 * both libraries can be linked into the same binary without symbol conflicts.
 */
typedef enum {
    AGGZK_VERIFY_SUCCESS              = 0,
    AGGZK_VERIFY_INVALID_PROOF        = 1,
    AGGZK_VERIFY_INVALID_VKEY         = 2,
    AGGZK_VERIFY_INVALID_PUBLIC_INPUTS = 3,
    AGGZK_VERIFY_VERIFICATION_FAILED  = 4,
    AGGZK_VERIFY_INTERNAL_ERROR       = 5,
} AggZkVerifyResult;

/**
 * Verify an aggregator SP1 ZK consistency proof.
 *
 * The proof was produced by rugregator's zk-host crate (SP1 6.0.2).
 * Public values layout:
 *   prev_root[32] || new_root[32] || reference_time (big-endian u64)
 * 72 bytes total.
 *
 * @param vkey_bytes  Bincode-serialized SP1VerifyingKey
 * @param vkey_len    Length of vkey_bytes
 * @param proof_bytes Bincode-serialized SP1ProofWithPublicValues
 * @param proof_len   Length of proof_bytes
 * @param prev_root   Pointer to 32-byte previous SMT root
 * @param new_root    Pointer to 32-byte new SMT root
 * @param reference_time Round reference time (CR.IR.t) the circuit derived its leaf values from
 * @param error_out   On error, set to a malloc'd C string (free with aggzk_free_string)
 * @return AggZkVerifyResult status code
 */
AggZkVerifyResult aggzk_verify_proof(
    const uint8_t* vkey_bytes,
    size_t         vkey_len,
    const uint8_t* proof_bytes,
    size_t         proof_len,
    const uint8_t* prev_root,
    const uint8_t* new_root,
    uint64_t       reference_time,
    char**         error_out
);

/**
 * Validate a bincode-serialized SP1VerifyingKey without running a proof.
 *
 * @param vkey_bytes Pointer to vkey bytes
 * @param vkey_len   Length of vkey_bytes
 * @param error_out  On error, set to a malloc'd C string (free with aggzk_free_string)
 * @return AGGZK_VERIFY_SUCCESS or AGGZK_VERIFY_INVALID_VKEY
 */
AggZkVerifyResult aggzk_validate_vkey(
    const uint8_t* vkey_bytes,
    size_t         vkey_len,
    char**         error_out
);

/**
 * Free a string allocated by this library.
 *
 * @param s Pointer to string to free (may be NULL)
 */
void aggzk_free_string(char* s);

/**
 * Return the version of this FFI library.
 *
 * @return Pointer to a static null-terminated version string (do not free)
 */
const char* aggzk_ffi_version(void);

#ifdef __cplusplus
}
#endif

#endif /* AGGREGATOR_ZK_VERIFIER_H */
