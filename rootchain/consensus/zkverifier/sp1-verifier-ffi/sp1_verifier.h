/**
 * SP1 Proof Verifier FFI
 *
 * C header for FFI interface to SP1 proof verification
 */

#ifndef SP1_VERIFIER_H
#define SP1_VERIFIER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Result codes for SP1 verification
 */
typedef enum {
    SP1_VERIFY_SUCCESS = 0,
    SP1_VERIFY_INVALID_PROOF = 1,
    SP1_VERIFY_INVALID_VKEY = 2,
    SP1_VERIFY_INVALID_PUBLIC_INPUTS = 3,
    SP1_VERIFY_VERIFICATION_FAILED = 4,
    SP1_VERIFY_INTERNAL_ERROR = 5,
} SP1VerifyResult;

/**
 * Verify an SP1 compressed proof
 *
 * @param vkey_bytes Pointer to verification key bytes
 * @param vkey_len Length of verification key in bytes
 * @param proof_bytes Pointer to proof bytes
 * @param proof_len Length of proof in bytes
 * @param prev_state_root Pointer to 32-byte previous state root
 * @param new_state_root Pointer to 32-byte new state root
 * @param block_hash Pointer to 32-byte block hash
 * @param chain_id EVM Chain ID from partition config
 * @param error_out Output pointer for error message (must be freed with sp1_free_string)
 * @return SP1VerifyResult status code
 */
SP1VerifyResult sp1_verify_proof(
    const uint8_t* vkey_bytes,
    size_t vkey_len,
    const uint8_t* proof_bytes,
    size_t proof_len,
    const uint8_t* prev_state_root,
    const uint8_t* new_state_root,
    const uint8_t* block_hash,
    uint64_t chain_id,
    char** error_out
);

/**
 * Free a string allocated by sp1_verify_proof
 *
 * @param s Pointer to string to free
 */
void sp1_free_string(char* s);

/**
 * Get the version of the FFI library
 *
 * @return Version string (do not free)
 */
const char* sp1_ffi_version(void);

/**
 * Validate a verification key
 *
 * @param vkey_bytes Pointer to verification key bytes
 * @param vkey_len Length of verification key in bytes
 * @param error_out Output pointer for error message (must be freed with sp1_free_string)
 * @return SP1VerifyResult status code (SUCCESS or INVALID_VKEY)
 */
SP1VerifyResult sp1_validate_vkey(
    const uint8_t* vkey_bytes,
    size_t vkey_len,
    char** error_out
);

#ifdef __cplusplus
}
#endif

#endif /* SP1_VERIFIER_H */
