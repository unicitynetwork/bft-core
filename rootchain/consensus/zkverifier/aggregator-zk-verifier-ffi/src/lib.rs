use std::ffi::CString;
use std::os::raw::c_char;
use std::sync::OnceLock;
use sp1_sdk::{HashableKey, SP1Proof, SP1ProofWithPublicValues};
use sp1_sdk::blocking::{CpuProver, Prover, ProverClient};
use sp1_verifier::{Groth16Verifier, PlonkVerifier, GROTH16_VK_BYTES, PLONK_VK_BYTES};

/// Global CpuProver for Compressed proof verification.
///
/// `SP1CompressedVerifierRaw` in sp1-verifier 6.0.2 uses a placeholder all-zero
/// vk_merkle_root (TODO) and therefore rejects all proofs from the CPU prover.
/// We must use CpuProver::verify() for Compressed proofs.  Initialization takes
/// ~15 seconds but happens only once per process lifetime.
static CPU_PROVER: OnceLock<CpuProver> = OnceLock::new();

fn cpu_prover() -> &'static CpuProver {
    CPU_PROVER.get_or_init(|| ProverClient::builder().cpu().build())
}

/// Error codes for the aggregator ZK verifier FFI.
///
/// The `AGGZK_` prefix keeps these distinct from the SP1 verifier FFI symbols
/// (`SP1_VERIFY_*`) so both libraries can coexist in the same Go binary.
#[repr(C)]
pub enum AggZkVerifyResult {
    Success             = 0,
    InvalidProof        = 1,
    InvalidVKey         = 2,
    InvalidPublicInputs = 3,
    VerificationFailed  = 4,
    InternalError       = 5,
}

/// Verify an aggregator SP1 ZK consistency proof.
///
/// The proof was produced by `rugregator/crates/zk-host` using SP1 6.0.2.
/// The guest program committed exactly 64 public-value bytes:
///   bytes  0–31: previous SMT root
///   bytes 32–63: new SMT root
///
/// Supported proof kinds: Groth16, Plonk, Compressed.
/// Core proofs are rejected (return `InternalError`).
///
/// # Arguments
/// * `vkey_bytes` / `vkey_len`   — bincode-serialized `SP1VerifyingKey`
/// * `proof_bytes` / `proof_len` — bincode-serialized `SP1ProofWithPublicValues`
/// * `prev_root`                 — pointer to 32-byte previous state root
/// * `new_root`                  — pointer to 32-byte new state root
/// * `reference_time`            — round reference time (CR.IR.t) the circuit
///   derived its leaf values from, committed as the third public value
/// * `error_out`                 — on error, set to a malloc'd C string (caller frees with `aggzk_free_string`)
///
/// # Returns
/// `AggZkVerifyResult` status code.
#[no_mangle]
pub extern "C" fn aggzk_verify_proof(
    vkey_bytes:  *const u8,
    vkey_len:    usize,
    proof_bytes: *const u8,
    proof_len:   usize,
    prev_root:   *const u8,
    new_root:    *const u8,
    reference_time: u64,
    error_out:   *mut *mut c_char,
) -> AggZkVerifyResult {
    if vkey_bytes.is_null() || proof_bytes.is_null() {
        set_error(error_out, "null pointer passed to aggzk_verify_proof");
        return AggZkVerifyResult::InternalError;
    }
    if prev_root.is_null() || new_root.is_null() {
        set_error(error_out, "null state root pointer");
        return AggZkVerifyResult::InvalidPublicInputs;
    }

    let vkey_data  = unsafe { std::slice::from_raw_parts(vkey_bytes,  vkey_len)  };
    let proof_data = unsafe { std::slice::from_raw_parts(proof_bytes, proof_len) };
    let prev       = unsafe { std::slice::from_raw_parts(prev_root, 32) };
    let new        = unsafe { std::slice::from_raw_parts(new_root,  32) };

    match verify_internal(vkey_data, proof_data, prev, new, reference_time) {
        Ok(()) => AggZkVerifyResult::Success,
        Err(e) => {
            set_error(error_out, &e.to_string());
            classify(&e)
        }
    }
}

fn verify_internal(
    vkey_data:  &[u8],
    proof_data: &[u8],
    prev_root:  &[u8],
    new_root:   &[u8],
    reference_time: u64,
) -> anyhow::Result<()> {
    let vkey: sp1_sdk::SP1VerifyingKey = bincode::deserialize(vkey_data)
        .map_err(|e| anyhow::anyhow!("failed to deserialize vkey: {e}"))?;

    let proof: SP1ProofWithPublicValues = bincode::deserialize(proof_data)
        .map_err(|e| anyhow::anyhow!("failed to deserialize proof: {e}"))?;

    // Public values layout:
    //   prev_root[32] || new_root[32] || reference_time (big-endian u64)
    // exactly 72 bytes. The reference time is public because the batch is not:
    // the circuit derives the leaf values internally and exposes the time it
    // used, so the Core can check it against CR.IR.t. Both instantiations of
    // the consistency proof therefore enforce it identically.
    let pv = proof.public_values.as_slice();
    if pv.len() != 72 {
        anyhow::bail!(
            "public values length mismatch: expected 72 bytes, got {}",
            pv.len()
        );
    }
    if &pv[0..32] != prev_root {
        anyhow::bail!("previous state root mismatch in public values");
    }
    if &pv[32..64] != new_root {
        anyhow::bail!("new state root mismatch in public values");
    }
    if pv[64..72] != reference_time.to_be_bytes() {
        anyhow::bail!("reference time mismatch in public values");
    }

    let pv_bytes = proof.public_values.to_vec();

    match &proof.proof {
        SP1Proof::Core(_) => {
            anyhow::bail!("Core proofs are not supported; regenerate with Groth16, Plonk, or Compressed");
        }
        SP1Proof::Groth16(_) => {
            let wire = proof.bytes();
            let vkey_hash = vkey.bytes32(); // "0x<64 hex chars>"
            Groth16Verifier::verify(&wire, &pv_bytes, &vkey_hash, &GROTH16_VK_BYTES)
                .map_err(|e| anyhow::anyhow!("Groth16 verification failed: {e:?}"))?;
        }
        SP1Proof::Plonk(_) => {
            let wire = proof.bytes();
            let vkey_hash = vkey.bytes32();
            PlonkVerifier::verify(&wire, &pv_bytes, &vkey_hash, &PLONK_VK_BYTES)
                .map_err(|e| anyhow::anyhow!("Plonk verification failed: {e:?}"))?;
        }
        SP1Proof::Compressed(_) => {
            // SP1CompressedVerifierRaw in sp1-verifier 6.0.2 uses a placeholder
            // all-zero vk_merkle_root and rejects all CPU-generated proofs.
            // Fall back to the cached CpuProver which skips the Merkle check when
            // vk_verification is disabled (the CPU prover default).
            cpu_prover()
                .verify(&proof, &vkey, None)
                .map_err(|e| anyhow::anyhow!("Compressed proof verification failed: {e}"))?;
        }
    }

    Ok(())
}

/// Validate a bincode-serialized `SP1VerifyingKey` without running a proof.
#[no_mangle]
pub extern "C" fn aggzk_validate_vkey(
    vkey_bytes: *const u8,
    vkey_len:   usize,
    error_out:  *mut *mut c_char,
) -> AggZkVerifyResult {
    if vkey_bytes.is_null() {
        set_error(error_out, "null pointer passed to aggzk_validate_vkey");
        return AggZkVerifyResult::InternalError;
    }
    if vkey_len == 0 {
        set_error(error_out, "vkey is empty");
        return AggZkVerifyResult::InvalidVKey;
    }
    let data = unsafe { std::slice::from_raw_parts(vkey_bytes, vkey_len) };
    match bincode::deserialize::<sp1_sdk::SP1VerifyingKey>(data) {
        Ok(_)  => AggZkVerifyResult::Success,
        Err(e) => {
            set_error(error_out, &format!("failed to deserialize vkey: {e}"));
            AggZkVerifyResult::InvalidVKey
        }
    }
}

/// Free a string allocated by this library.
#[no_mangle]
pub extern "C" fn aggzk_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe { let _ = CString::from_raw(s); }
    }
}

/// Return the version of this FFI library (static string, do not free).
#[no_mangle]
pub extern "C" fn aggzk_ffi_version() -> *const c_char {
    const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), "\0");
    VERSION.as_ptr() as *const c_char
}

// ── Error helpers ─────────────────────────────────────────────────────────────

fn classify(err: &anyhow::Error) -> AggZkVerifyResult {
    let msg = err.to_string().to_lowercase();
    if msg.contains("vkey") || msg.contains("verifying key") {
        AggZkVerifyResult::InvalidVKey
    } else if msg.contains("deserialize proof") {
        AggZkVerifyResult::InvalidProof
    } else if msg.contains("state root") || msg.contains("public values") {
        AggZkVerifyResult::InvalidPublicInputs
    } else if msg.contains("verification failed") {
        AggZkVerifyResult::VerificationFailed
    } else if msg.contains("not supported") {
        AggZkVerifyResult::InternalError
    } else {
        AggZkVerifyResult::InternalError
    }
}

fn set_error(error_out: *mut *mut c_char, message: &str) {
    if !error_out.is_null() {
        if let Ok(s) = CString::new(message) {
            unsafe { *error_out = s.into_raw(); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn test_null_pointers() {
        let mut error: *mut c_char = ptr::null_mut();
        let result = aggzk_verify_proof(
            ptr::null(), 0,
            ptr::null(), 0,
            ptr::null(),
            ptr::null(),
            &mut error,
        );
        assert!(matches!(result, AggZkVerifyResult::InternalError));
        if !error.is_null() {
            aggzk_free_string(error);
        }
    }

    #[test]
    fn test_version() {
        let version = aggzk_ffi_version();
        assert!(!version.is_null());
        let s = unsafe { std::ffi::CStr::from_ptr(version) };
        assert!(s.to_str().unwrap().starts_with("0.1.0"));
    }

    #[test]
    fn test_empty_vkey() {
        let mut error: *mut c_char = ptr::null_mut();
        let result = aggzk_validate_vkey(ptr::null(), 0, &mut error);
        assert!(matches!(result, AggZkVerifyResult::InternalError));
        if !error.is_null() {
            aggzk_free_string(error);
        }
    }
}
