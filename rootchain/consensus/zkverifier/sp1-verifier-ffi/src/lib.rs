use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use sp1_sdk::{ProverClient, SP1ProofWithPublicValues};

/// Error codes for FFI interface
#[repr(C)]
pub enum SP1VerifyResult {
    Success = 0,
    InvalidProof = 1,
    InvalidVKey = 2,
    InvalidPublicInputs = 3,
    VerificationFailed = 4,
    InternalError = 5,
}

/// Verify an SP1 compressed proof
///
/// # Arguments
/// * `vkey_bytes` - Pointer to verification key bytes
/// * `vkey_len` - Length of verification key
/// * `proof_bytes` - Pointer to proof bytes
/// * `proof_len` - Length of proof
/// * `prev_state_root` - Pointer to 32-byte previous state root
/// * `new_state_root` - Pointer to 32-byte new state root
/// * `block_hash` - Pointer to 32-byte block hash
/// * `error_out` - Output pointer for error message (caller must free with sp1_free_string)
///
/// # Returns
/// SP1VerifyResult code
#[no_mangle]
pub extern "C" fn sp1_verify_proof(
    vkey_bytes: *const u8,
    vkey_len: usize,
    proof_bytes: *const u8,
    proof_len: usize,
    prev_state_root: *const u8,
    new_state_root: *const u8,
    block_hash: *const u8,
    error_out: *mut *mut c_char,
) -> SP1VerifyResult {
    // Safety checks
    if vkey_bytes.is_null() || proof_bytes.is_null() {
        set_error(error_out, "null pointer passed to sp1_verify_proof");
        return SP1VerifyResult::InternalError;
    }

    if prev_state_root.is_null() || new_state_root.is_null() || block_hash.is_null() {
        set_error(error_out, "null state root or block hash pointer");
        return SP1VerifyResult::InvalidPublicInputs;
    }

    // Convert C pointers to Rust slices
    let vkey_data = unsafe { std::slice::from_raw_parts(vkey_bytes, vkey_len) };
    let proof_data = unsafe { std::slice::from_raw_parts(proof_bytes, proof_len) };
    let prev_root = unsafe { std::slice::from_raw_parts(prev_state_root, 32) };
    let new_root = unsafe { std::slice::from_raw_parts(new_state_root, 32) };
    let blk_hash = unsafe { std::slice::from_raw_parts(block_hash, 32) };

    // Perform verification
    match verify_proof_internal(vkey_data, proof_data, prev_root, new_root, blk_hash) {
        Ok(()) => SP1VerifyResult::Success,
        Err(e) => {
            set_error(error_out, &e.to_string());
            match classify_error(&e) {
                ErrorType::InvalidVKey => SP1VerifyResult::InvalidVKey,
                ErrorType::InvalidProof => SP1VerifyResult::InvalidProof,
                ErrorType::InvalidPublicInputs => SP1VerifyResult::InvalidPublicInputs,
                ErrorType::VerificationFailed => SP1VerifyResult::VerificationFailed,
                ErrorType::Internal => SP1VerifyResult::InternalError,
            }
        }
    }
}

/// Internal verification logic
fn verify_proof_internal(
    vkey_data: &[u8],
    proof_data: &[u8],
    prev_state_root: &[u8],
    new_state_root: &[u8],
    block_hash: &[u8],
) -> anyhow::Result<()> {
    // Deserialize verification key
    let vkey: sp1_sdk::SP1VerifyingKey = bincode::deserialize(vkey_data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize verification key: {}", e))?;

    // Deserialize proof
    let proof: SP1ProofWithPublicValues = bincode::deserialize(proof_data)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize proof: {}", e))?;

    // Create prover client (used for verification)
    let client = ProverClient::from_env();

    // Verify the proof
    client.verify(&proof, &vkey)
        .map_err(|e| anyhow::anyhow!("Proof verification failed: {}", e))?;

    // Extract public values from proof
    let public_values = proof.public_values.as_slice();

    // Validate that public values contain expected data
    // Expected format (from ProgramOutput::encode() with l2 feature):
    // - 0-31: initial_state_hash (prev_state_root)
    // - 32-63: final_state_hash (new_state_root)
    // - 64-95: l1_out_messages_merkle_root (L2 feature)
    // - 96-127: l1_in_messages_rolling_hash (L2 feature)
    // - 128-159: blob_versioned_hash (L2 feature)
    // - 160-191: last_block_hash (block_hash)
    // - 192+: chain_id, non_privileged_count, etc.
    //
    // Note: ethrex's guest program has the 'l2' feature enabled by default,
    // which adds 3 H256 fields (96 bytes) before the block hash.
    if public_values.len() < 192 {
        return Err(anyhow::anyhow!(
            "Public values too short: expected at least 192 bytes for ethrex l2 format, got {}",
            public_values.len()
        ));
    }

    // Check previous state root matches
    if &public_values[0..32] != prev_state_root {
        return Err(anyhow::anyhow!(
            "Previous state root mismatch: expected {:?}, got {:?}",
            prev_state_root,
            &public_values[0..32]
        ));
    }

    // Check new state root matches
    if &public_values[32..64] != new_state_root {
        return Err(anyhow::anyhow!(
            "New state root mismatch: expected {:?}, got {:?}",
            new_state_root,
            &public_values[32..64]
        ));
    }

    // Check block hash matches (at offset 160 due to l2 feature fields)
    if &public_values[160..192] != block_hash {
        return Err(anyhow::anyhow!(
            "Block hash mismatch: expected {:?}, got {:?}",
            block_hash,
            &public_values[160..192]
        ));
    }

    Ok(())
}

/// Free a string allocated by this library
#[no_mangle]
pub extern "C" fn sp1_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Get the version of this FFI library
#[no_mangle]
pub extern "C" fn sp1_ffi_version() -> *const c_char {
    const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

/// Validate a verification key
///
/// # Arguments
/// * `vkey_bytes` - Pointer to verification key bytes
/// * `vkey_len` - Length of verification key
/// * `error_out` - Output pointer for error message (caller must free with sp1_free_string)
///
/// # Returns
/// SP1VerifyResult code (Success or InvalidVKey)
#[no_mangle]
pub extern "C" fn sp1_validate_vkey(
    vkey_bytes: *const u8,
    vkey_len: usize,
    error_out: *mut *mut c_char,
) -> SP1VerifyResult {
    // Safety checks
    if vkey_bytes.is_null() {
        set_error(error_out, "null pointer passed to sp1_validate_vkey");
        return SP1VerifyResult::InternalError;
    }

    if vkey_len == 0 {
        set_error(error_out, "verification key is empty");
        return SP1VerifyResult::InvalidVKey;
    }

    // Convert C pointer to Rust slice
    let vkey_data = unsafe { std::slice::from_raw_parts(vkey_bytes, vkey_len) };

    // Try to deserialize verification key
    match bincode::deserialize::<sp1_sdk::SP1VerifyingKey>(vkey_data) {
        Ok(_) => SP1VerifyResult::Success,
        Err(e) => {
            set_error(error_out, &format!("Failed to deserialize verification key: {}", e));
            SP1VerifyResult::InvalidVKey
        }
    }
}

// Helper functions

enum ErrorType {
    InvalidVKey,
    InvalidProof,
    InvalidPublicInputs,
    VerificationFailed,
    Internal,
}

fn classify_error(err: &anyhow::Error) -> ErrorType {
    let msg = err.to_string().to_lowercase();
    if msg.contains("verification key") || msg.contains("vkey") {
        ErrorType::InvalidVKey
    } else if msg.contains("deserialize proof") {
        ErrorType::InvalidProof
    } else if msg.contains("state root") || msg.contains("public values") {
        ErrorType::InvalidPublicInputs
    } else if msg.contains("verification failed") {
        ErrorType::VerificationFailed
    } else {
        ErrorType::Internal
    }
}

fn set_error(error_out: *mut *mut c_char, message: &str) {
    if !error_out.is_null() {
        if let Ok(c_string) = CString::new(message) {
            unsafe {
                *error_out = c_string.into_raw();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;
    use std::ptr;

    #[test]
    fn test_null_pointers() {
        let mut error: *mut c_char = ptr::null_mut();
        let result = sp1_verify_proof(
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &mut error,
        );
        assert_eq!(result as i32, SP1VerifyResult::InternalError as i32);

        if !error.is_null() {
            sp1_free_string(error);
        }
    }

    #[test]
    fn test_version() {
        let version = sp1_ffi_version();
        assert!(!version.is_null());
        let version_str = unsafe { CStr::from_ptr(version) };
        assert!(version_str.to_str().unwrap().starts_with("0.1.0"));
    }
}
