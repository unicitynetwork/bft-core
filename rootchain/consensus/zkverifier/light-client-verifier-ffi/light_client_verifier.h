/**
 * Light Client Verifier FFI
 *
 * C header for FFI interface to light client proof verification
 */

#ifndef LIGHT_CLIENT_VERIFIER_H
#define LIGHT_CLIENT_VERIFIER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Result codes for light client verification
 */
typedef enum {
    LIGHT_CLIENT_VERIFY_SUCCESS = 0,
    LIGHT_CLIENT_VERIFY_INVALID_PROOF = 1,
    LIGHT_CLIENT_VERIFY_INVALID_MAGIC_HEADER = 2,
    LIGHT_CLIENT_VERIFY_INVALID_PUBLIC_INPUTS = 3,
    LIGHT_CLIENT_VERIFY_VERIFICATION_FAILED = 4,
    LIGHT_CLIENT_VERIFY_INTERNAL_ERROR = 5,
} LightClientVerifyResult;

/**
 * Verify a light client proof payload
 *
 * The payload should contain:
 * - Magic header: "LCPROOF\0" (8 bytes)
 * - Serialized ProgramInput (rkyv format)
 *
 * @param payload_bytes Pointer to payload bytes
 * @param payload_len Length of payload in bytes
 * @param prev_state_root Pointer to 32-byte previous state root
 * @param new_state_root Pointer to 32-byte new state root
 * @param block_hash Pointer to 32-byte block hash
 * @param chain_id Chain ID of EVM instance from partition config
 * @param error_out Output pointer for error message (must be freed with light_client_free_string)
 * @return LightClientVerifyResult status code
 */
LightClientVerifyResult light_client_verify_proof(
    const uint8_t* payload_bytes,
    size_t payload_len,
    const uint8_t* prev_state_root,
    const uint8_t* new_state_root,
    const uint8_t* block_hash,
    uint64_t chain_id,
    char** error_out
);

/**
 * Free a string allocated by light_client_verify_proof
 *
 * @param s Pointer to string to free
 */
void light_client_free_string(char* s);

/**
 * Get the version of the FFI library
 *
 * @return Version string (do not free)
 */
const char* light_client_ffi_version(void);

/**
 * Validate a light client payload format
 *
 * Checks magic header and ProgramInput deserialization without executing validation.
 *
 * @param payload_bytes Pointer to payload bytes
 * @param payload_len Length of payload in bytes
 * @param error_out Output pointer for error message (must be freed with light_client_free_string)
 * @return LightClientVerifyResult status code (SUCCESS or error)
 */
LightClientVerifyResult light_client_validate_payload(
    const uint8_t* payload_bytes,
    size_t payload_len,
    char** error_out
);

#ifdef __cplusplus
}
#endif

#endif /* LIGHT_CLIENT_VERIFIER_H */
