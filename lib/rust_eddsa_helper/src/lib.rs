use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

pub mod blake;
pub mod eddsa;
pub mod poseidon_hash;
pub mod babyjub;

pub use eddsa::{sign_eddsa, verify_eddsa};
pub use poseidon_hash::poseidon_hash_bits;

/// FFI function to hash field elements using Poseidon
/// 
/// Input JSON format:
/// {
///   "inputs": ["123", "456", ...]  // Array of field element strings (BigInt as decimal string)
/// }
/// 
/// Output JSON format:
/// {
///   "success": true,
///   "result": "789..."  // Field element as decimal string
/// }
/// 
/// On error, returns JSON with "success": false and "error": "..."
#[no_mangle]
pub extern "C" fn poseidon_hash(
    input_json: *const c_char,
    output_json: *mut *mut c_char,
) -> c_int {
    if input_json.is_null() || output_json.is_null() {
        return -1;
    }

    unsafe {
        let input_str = match CStr::from_ptr(input_json).to_str() {
            Ok(s) => s,
            Err(_) => {
                let error = CString::new(r#"{"success":false,"error":"Invalid UTF-8 input"}"#)
                    .unwrap();
                *output_json = error.into_raw();
                return -1;
            }
        };

        let result = match poseidon_hash_field_elements(input_str) {
            Ok(json_str) => {
                match CString::new(json_str) {
                    Ok(cstr) => {
                        *output_json = cstr.into_raw();
                        0
                    }
                    Err(_) => {
                        let error = CString::new(r#"{"success":false,"error":"Failed to create output string"}"#)
                            .unwrap();
                        *output_json = error.into_raw();
                        -1
                    }
                }
            }
            Err(e) => {
                let error_json = format!(r#"{{"success":false,"error":"{}"}}"#, e.replace('"', "\\\""));
                match CString::new(error_json) {
                    Ok(cstr) => {
                        *output_json = cstr.into_raw();
                        -1
                    }
                    Err(_) => {
                        let error = CString::new(r#"{"success":false,"error":"Unknown error"}"#)
                            .unwrap();
                        *output_json = error.into_raw();
                        -1
                    }
                }
            }
        };

        result
    }
}

/// Free memory allocated by poseidon_hash
#[no_mangle]
pub extern "C" fn poseidon_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

/// FFI function to hash bits using Poseidon (matching circomlibjs behavior)
/// 
/// Input JSON format:
/// {
///   "bits": [0, 1, 0, ...]  // Array of bits (0 or 1)
/// }
/// 
/// Output JSON format:
/// {
///   "success": true,
///   "result": "789..."  // Field element as decimal string
/// }
/// 
/// On error, returns JSON with "success": false and "error": "..."
#[no_mangle]
pub extern "C" fn poseidon_hash_bits_ffi(
    input_json: *const c_char,
    output_json: *mut *mut c_char,
) -> c_int {
    if input_json.is_null() || output_json.is_null() {
        return -1;
    }

    unsafe {
        let input_str = match CStr::from_ptr(input_json).to_str() {
            Ok(s) => s,
            Err(_) => {
                let error = CString::new(r#"{"success":false,"error":"Invalid UTF-8 input"}"#)
                    .unwrap();
                *output_json = error.into_raw();
                return -1;
            }
        };

        let result = match poseidon_hash_bits_from_json(input_str) {
            Ok(json_str) => {
                match CString::new(json_str) {
                    Ok(cstr) => {
                        *output_json = cstr.into_raw();
                        0
                    }
                    Err(_) => {
                        let error = CString::new(r#"{"success":false,"error":"Failed to create output string"}"#)
                            .unwrap();
                        *output_json = error.into_raw();
                        -1
                    }
                }
            }
            Err(e) => {
                let error_json = format!(r#"{{"success":false,"error":"{}"}}"#, e.replace('"', "\\\""));
                match CString::new(error_json) {
                    Ok(cstr) => {
                        *output_json = cstr.into_raw();
                        -1
                    }
                    Err(_) => {
                        let error = CString::new(r#"{"success":false,"error":"Unknown error"}"#)
                            .unwrap();
                        *output_json = error.into_raw();
                        -1
                    }
                }
            }
        };

        result
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoseidonHashBitsRequest {
    bits: Vec<u8>,
}

/// Hash bits using Poseidon (wrapper for poseidon_hash_bits)
fn poseidon_hash_bits_from_json(input_json: &str) -> Result<String, String> {
    let request: PoseidonHashBitsRequest = serde_json::from_str(input_json)
        .map_err(|e| format!("Failed to parse input JSON: {}", e))?;

    // Handle empty input - use a single zero chunk
    if request.bits.is_empty() {
        let zero_bits = vec![0u8; 248];
        let hash = poseidon_hash_bits(&zero_bits)?;
        let hash_str = hash.into_bigint().to_string();
        
        let output = PoseidonHashResult {
            success: true,
            result: Some(hash_str),
            error: None,
        };
        
        return Ok(serde_json::to_string(&output)
            .map_err(|e| format!("Failed to serialize output: {}", e))?);
    }

    let hash = poseidon_hash_bits(&request.bits)?;
    let hash_str = hash.into_bigint().to_string();

    let output = PoseidonHashResult {
        success: true,
        result: Some(hash_str),
        error: None,
    };

    Ok(serde_json::to_string(&output)
        .map_err(|e| format!("Failed to serialize output: {}", e))?)
}

use serde::{Deserialize, Serialize};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoseidonHashRequest {
    inputs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PoseidonHashResult {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Hash an array of field elements using Poseidon
/// This matches the behavior of circomlibjs's Poseidon hash
fn poseidon_hash_field_elements(input_json: &str) -> Result<String, String> {
    let request: PoseidonHashRequest = serde_json::from_str(input_json)
        .map_err(|e| format!("Failed to parse input JSON: {}", e))?;

    if request.inputs.is_empty() {
        return Err("Input array cannot be empty".to_string());
    }

    // Convert string inputs to field elements
    let mut field_elements = Vec::new();
    for input_str in &request.inputs {
        let field_element = Fr::from_str(input_str)
            .map_err(|e| format!("Failed to parse field element '{}': {:?}", input_str, e))?;
        field_elements.push(field_element);
    }

    // Handle single input case (Poseidon needs at least 2 inputs)
    if field_elements.len() == 1 {
        field_elements.push(Fr::from(0u64));
    }

    // Create Poseidon instance with Circom parameters
    let num_inputs = field_elements.len();
    let mut poseidon = Poseidon::<Fr>::new_circom(num_inputs)
        .map_err(|e| format!("Failed to create Poseidon instance: {:?}", e))?;

    // Hash the field elements
    let hash = poseidon.hash(&field_elements)
        .map_err(|e| format!("Poseidon hash failed: {:?}", e))?;

    // Convert field element to string (decimal representation)
    let hash_str = hash.into_bigint().to_string();

    let output = PoseidonHashResult {
        success: true,
        result: Some(hash_str),
        error: None,
    };

    Ok(serde_json::to_string(&output)
        .map_err(|e| format!("Failed to serialize output: {}", e))?)
}

/// FFI function to sign data using EdDSA on Baby Jubjub
/// 
/// Input JSON format:
/// {
///   "bits": [0, 1, 0, ...],  // Array of bits (0 or 1)
///   "privateKeyHex": "00010203..."  // 64 hex characters (32 bytes)
/// }
/// 
/// Output JSON format:
/// {
///   "success": true,
///   "result": {
///     "Ax": "...",
///     "Ay": "...",
///     "R8x": "...",
///     "R8y": "...",
///     "S": "..."
///   }
/// }
/// 
/// On error, returns JSON with "success": false and "error": "..."
#[no_mangle]
pub extern "C" fn eddsa_sign(
    input_json: *const c_char,
    output_json: *mut *mut c_char,
) -> c_int {
    if input_json.is_null() || output_json.is_null() {
        return -1;
    }

    unsafe {
        let input_str = match CStr::from_ptr(input_json).to_str() {
            Ok(s) => s,
            Err(_) => {
                let error = CString::new(r#"{"success":false,"error":"Invalid UTF-8 input"}"#)
                    .unwrap();
                *output_json = error.into_raw();
                return -1;
            }
        };

        let result = match sign_eddsa(input_str) {
            Ok(json_str) => {
                match CString::new(json_str) {
                    Ok(cstr) => {
                        *output_json = cstr.into_raw();
                        0
                    }
                    Err(_) => {
                        let error = CString::new(r#"{"success":false,"error":"Failed to create output string"}"#)
                            .unwrap();
                        *output_json = error.into_raw();
                        -1
                    }
                }
            }
            Err(e) => {
                let error_json = format!(r#"{{"success":false,"error":"{}"}}"#, e.replace('"', "\\\""));
                match CString::new(error_json) {
                    Ok(cstr) => {
                        *output_json = cstr.into_raw();
                        -1
                    }
                    Err(_) => {
                        let error = CString::new(r#"{"success":false,"error":"Unknown error"}"#)
                            .unwrap();
                        *output_json = error.into_raw();
                        -1
                    }
                }
            }
        };

        result
    }
}

/// FFI function to verify EdDSA signature over pre-hashed Poseidon digest.
#[no_mangle]
pub extern "C" fn eddsa_verify(
    input_json: *const c_char,
    output_json: *mut *mut c_char,
) -> c_int {
    if input_json.is_null() || output_json.is_null() {
        return -1;
    }

    unsafe {
        let input_str = match CStr::from_ptr(input_json).to_str() {
            Ok(s) => s,
            Err(_) => {
                let error = CString::new(r#"{"success":false,"error":"Invalid UTF-8 input"}"#)
                    .unwrap();
                *output_json = error.into_raw();
                return -1;
            }
        };

        let result = match verify_eddsa(input_str) {
            Ok(json_str) => {
                match CString::new(json_str) {
                    Ok(cstr) => {
                        *output_json = cstr.into_raw();
                        0
                    }
                    Err(_) => {
                        let error = CString::new(r#"{"success":false,"error":"Failed to create output string"}"#)
                            .unwrap();
                        *output_json = error.into_raw();
                        -1
                    }
                }
            }
            Err(e) => {
                let error_json = format!(r#"{{"success":false,"error":"{}"}}"#, e.replace('"', "\\\""));
                match CString::new(error_json) {
                    Ok(cstr) => {
                        *output_json = cstr.into_raw();
                        -1
                    }
                    Err(_) => {
                        let error = CString::new(r#"{"success":false,"error":"Unknown error"}"#)
                            .unwrap();
                        *output_json = error.into_raw();
                        -1
                    }
                }
            }
        };

        result
    }
}

/// Free memory allocated by eddsa_sign
#[no_mangle]
pub extern "C" fn eddsa_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        unsafe {
            let _ = CString::from_raw(ptr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn test_eddsa_sign() {
        let input = r#"{
            "operation": "sign",
            "data": {
                "bits": [0, 1, 0, 1],
                "privateKeyHex": "0001020304050607080900010203040506070809000102030405060708090001"
            }
        }"#;
        
        let input_cstr = CString::new(input).unwrap();
        let mut output_ptr: *mut c_char = ptr::null_mut();
        
        let result = eddsa_sign(input_cstr.as_ptr(), &mut output_ptr);
        
        assert_eq!(result, 0);
        
        if !output_ptr.is_null() {
            let output_cstr = unsafe { CStr::from_ptr(output_ptr) };
            let output_str = output_cstr.to_str().unwrap();
            println!("Output: {}", output_str);
            
            eddsa_free_string(output_ptr);
        }
    }
}

