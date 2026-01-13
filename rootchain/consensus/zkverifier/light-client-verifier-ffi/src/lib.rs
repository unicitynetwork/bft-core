use std::ffi::CString;
use std::os::raw::c_char;

// Magic header for light client proofs: "LCPROOF\0"
const LIGHT_CLIENT_MAGIC: &[u8; 8] = b"LCPROOF\0";

/// Error codes for FFI interface
#[repr(C)]
pub enum LightClientVerifyResult {
    Success = 0,
    InvalidProof = 1,
    InvalidMagicHeader = 2,
    InvalidPublicInputs = 3,
    VerificationFailed = 4,
    InternalError = 5,
}

/// Verify a light client proof payload
///
/// # Arguments
/// * `payload_bytes` - Pointer to payload bytes (magic header + serialized ProgramInput)
/// * `payload_len` - Length of payload
/// * `prev_state_root` - Pointer to 32-byte previous state root
/// * `new_state_root` - Pointer to 32-byte new state root
/// * `block_hash` - Pointer to 32-byte block hash
/// * `error_out` - Output pointer for error message (caller must free with light_client_free_string)
///
/// # Returns
/// LightClientVerifyResult code
#[no_mangle]
pub extern "C" fn light_client_verify_proof(
    payload_bytes: *const u8,
    payload_len: usize,
    prev_state_root: *const u8,
    new_state_root: *const u8,
    block_hash: *const u8,
    error_out: *mut *mut c_char,
) -> LightClientVerifyResult {
    // Safety checks
    if payload_bytes.is_null() {
        set_error(error_out, "null pointer passed to light_client_verify_proof");
        return LightClientVerifyResult::InternalError;
    }

    if prev_state_root.is_null() || new_state_root.is_null() || block_hash.is_null() {
        set_error(error_out, "null state root or block hash pointer");
        return LightClientVerifyResult::InvalidPublicInputs;
    }

    // Convert C pointers to Rust slices
    let payload_data = unsafe { std::slice::from_raw_parts(payload_bytes, payload_len) };
    let prev_root = unsafe { std::slice::from_raw_parts(prev_state_root, 32) };
    let new_root = unsafe { std::slice::from_raw_parts(new_state_root, 32) };
    let blk_hash = unsafe { std::slice::from_raw_parts(block_hash, 32) };

    // Perform verification
    match verify_light_client_proof_internal(payload_data, prev_root, new_root, blk_hash) {
        Ok(()) => LightClientVerifyResult::Success,
        Err(e) => {
            set_error(error_out, &e.to_string());
            match classify_error(&e) {
                ErrorType::InvalidMagicHeader => LightClientVerifyResult::InvalidMagicHeader,
                ErrorType::InvalidProof => LightClientVerifyResult::InvalidProof,
                ErrorType::InvalidPublicInputs => LightClientVerifyResult::InvalidPublicInputs,
                ErrorType::VerificationFailed => LightClientVerifyResult::VerificationFailed,
                ErrorType::Internal => LightClientVerifyResult::InternalError,
            }
        }
    }
}

/// Internal verification logic
fn verify_light_client_proof_internal(
    payload_data: &[u8],
    prev_state_root: &[u8],
    new_state_root: &[u8],
    block_hash: &[u8],
) -> anyhow::Result<()> {
    // 1. Check magic header
    if payload_data.len() < 8 {
        return Err(anyhow::anyhow!(
            "Payload too short: expected at least 8 bytes for magic header, got {}",
            payload_data.len()
        ));
    }

    if &payload_data[0..8] != LIGHT_CLIENT_MAGIC.as_slice() {
        return Err(anyhow::anyhow!(
            "Invalid magic header: expected {:?}, got {:?}",
            LIGHT_CLIENT_MAGIC,
            &payload_data[0..8]
        ));
    }

    // 2. Deserialize ProgramInput (skip 8-byte magic header)
    let input_bytes = &payload_data[8..];
    let program_input = rkyv::from_bytes::<guest_program::input::ProgramInput, rkyv::rancor::Error>(input_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize ProgramInput: {}", e))?;

    // 3. Validate that we have blocks
    if program_input.blocks.is_empty() {
        return Err(anyhow::anyhow!("No blocks in ProgramInput"));
    }

    // 4. Use chain_id from blocks[0].header (assuming it's stored in number for now)
    // TODO: Get chain_id from BFT Core configuration instead of hardcoding
    // For now, use the default chain_id from uni-evm config (1)
    let chain_id = 1;

    // 5. Execute stateless validation
    let output = guest_program::execution::stateless_validation_l1(
        program_input.blocks,
        program_input.execution_witness,
        program_input.elasticity_multiplier,
        chain_id,
    )
    .map_err(|e| anyhow::anyhow!("Stateless validation failed: {}", e))?;

    // 6. Convert public inputs to H256
    let prev_root_h256 = ethrex_core::H256::from_slice(prev_state_root);
    let new_root_h256 = ethrex_core::H256::from_slice(new_state_root);
    let block_hash_h256 = ethrex_core::H256::from_slice(block_hash);

    // 7. Verify state roots match
    if output.initial_state_hash != prev_root_h256 {
        return Err(anyhow::anyhow!(
            "Previous state root mismatch: expected {:?}, got {:?}",
            prev_root_h256,
            output.initial_state_hash
        ));
    }

    if output.final_state_hash != new_root_h256 {
        return Err(anyhow::anyhow!(
            "New state root mismatch: expected {:?}, got {:?}",
            new_root_h256,
            output.final_state_hash
        ));
    }

    // 8. Verify block hash matches
    if output.last_block_hash != block_hash_h256 {
        return Err(anyhow::anyhow!(
            "Block hash mismatch: expected {:?}, got {:?}",
            block_hash_h256,
            output.last_block_hash
        ));
    }

    Ok(())
}

/// Free a string allocated by this library
#[no_mangle]
pub extern "C" fn light_client_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

/// Get the version of this FFI library
#[no_mangle]
pub extern "C" fn light_client_ffi_version() -> *const c_char {
    const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

/// Validate a light client payload format
///
/// # Arguments
/// * `payload_bytes` - Pointer to payload bytes
/// * `payload_len` - Length of payload
/// * `error_out` - Output pointer for error message (caller must free with light_client_free_string)
///
/// # Returns
/// LightClientVerifyResult code (Success or InvalidProof)
#[no_mangle]
pub extern "C" fn light_client_validate_payload(
    payload_bytes: *const u8,
    payload_len: usize,
    error_out: *mut *mut c_char,
) -> LightClientVerifyResult {
    // Safety checks
    if payload_bytes.is_null() {
        set_error(error_out, "null pointer passed to light_client_validate_payload");
        return LightClientVerifyResult::InternalError;
    }

    if payload_len < 8 {
        set_error(error_out, "payload too short (need at least 8 bytes for magic)");
        return LightClientVerifyResult::InvalidProof;
    }

    // Convert C pointer to Rust slice
    let payload_data = unsafe { std::slice::from_raw_parts(payload_bytes, payload_len) };

    // Check magic header
    if &payload_data[0..8] != LIGHT_CLIENT_MAGIC.as_slice() {
        set_error(error_out, "invalid magic header");
        return LightClientVerifyResult::InvalidMagicHeader;
    }

    // Try to deserialize ProgramInput
    let input_bytes = &payload_data[8..];
    match rkyv::from_bytes::<guest_program::input::ProgramInput, rkyv::rancor::Error>(input_bytes) {
        Ok(_) => LightClientVerifyResult::Success,
        Err(e) => {
            set_error(error_out, &format!("Failed to deserialize ProgramInput: {}", e));
            LightClientVerifyResult::InvalidProof
        }
    }
}

// Helper functions

enum ErrorType {
    InvalidMagicHeader,
    InvalidProof,
    InvalidPublicInputs,
    VerificationFailed,
    Internal,
}

fn classify_error(err: &anyhow::Error) -> ErrorType {
    let msg = err.to_string().to_lowercase();
    if msg.contains("magic header") {
        ErrorType::InvalidMagicHeader
    } else if msg.contains("deserialize") {
        ErrorType::InvalidProof
    } else if msg.contains("state root mismatch") || msg.contains("public values") {
        ErrorType::InvalidPublicInputs
    } else if msg.contains("validation failed") {
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
        let result = light_client_verify_proof(
            ptr::null(),
            0,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            &mut error,
        );
        assert_eq!(result as i32, LightClientVerifyResult::InternalError as i32);

        if !error.is_null() {
            light_client_free_string(error);
        }
    }

    #[test]
    fn test_version() {
        let version = light_client_ffi_version();
        assert!(!version.is_null());
        let version_str = unsafe { CStr::from_ptr(version) };
        assert!(version_str.to_str().unwrap().starts_with("0.1.0"));
    }

    #[test]
    fn test_invalid_magic_header() {
        let payload = vec![0u8; 100]; // Invalid magic
        let prev_root = [0u8; 32];
        let new_root = [0u8; 32];
        let block_hash = [0u8; 32];
        let mut error: *mut c_char = ptr::null_mut();

        let result = light_client_verify_proof(
            payload.as_ptr(),
            payload.len(),
            prev_root.as_ptr(),
            new_root.as_ptr(),
            block_hash.as_ptr(),
            &mut error,
        );

        assert_eq!(result as i32, LightClientVerifyResult::InvalidMagicHeader as i32);

        if !error.is_null() {
            light_client_free_string(error);
        }
    }

    #[test]
    fn test_payload_too_short() {
        let payload = vec![0u8; 5]; // Too short for magic
        let prev_root = [0u8; 32];
        let new_root = [0u8; 32];
        let block_hash = [0u8; 32];
        let mut error: *mut c_char = ptr::null_mut();

        let result = light_client_verify_proof(
            payload.as_ptr(),
            payload.len(),
            prev_root.as_ptr(),
            new_root.as_ptr(),
            block_hash.as_ptr(),
            &mut error,
        );

        // Payload too short should return InvalidMagicHeader (checked first) or InvalidProof
        // The actual error is InvalidMagicHeader (2) because we check magic header first
        assert_eq!(result as i32, LightClientVerifyResult::InvalidMagicHeader as i32);

        if !error.is_null() {
            light_client_free_string(error);
        }
    }
}
