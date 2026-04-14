use rust_eddsa_helper::sign_eddsa;
use serde_json::json;
use std::env;
use std::process;

/// Simple CLI wrapper around `sign_eddsa` for testing from JS/Node.
///
/// Usage:
///   # Sign an already-Poseidon-hashed message (field element as decimal string)
///   eddsa_cli <msgHashDecimal> <privateKeyHex>
///
///   # Explicit hash mode (equivalent to above)
///   eddsa_cli hash <msgHashDecimal> <privateKeyHex>
///
///   # Sign raw bits (CLI will hash with Poseidon internally, like circomlibjs)
///   # bitsJson is a JSON array of 0/1, e.g. "[0,1,0,1]"
///   eddsa_cli bits <bitsJson> <privateKeyHex>
///
/// Arguments:
///   - msgHashDecimal: Poseidon field element as decimal string
///   - bitsJson:       JSON array of bits (0 or 1)
///   - privateKeyHex:  64-hex-character BabyJubjub private key
///
/// Output:
///   On success, prints a compact JSON object with the signature fields:
///   { "Ax": "...", "Ay": "...", "R8x": "...", "R8y": "...", "S": "..." }
///
///   On error, prints a JSON error object to stderr and exits with code 1.
fn main() {
    let args: Vec<String> = env::args().collect();

    // Supported invocations:
    // - eddsa_cli <msgHashDecimal> <privateKeyHex>
    // - eddsa_cli hash <msgHashDecimal> <privateKeyHex>
    // - eddsa_cli bits <bitsJson> <privateKeyHex>
    let (request, usage_error): (Option<serde_json::Value>, Option<String>) = match args.len() {
        3 => {
            // Backwards-compatible default: treat as hash mode
            let msg_hash = &args[1];
            let private_key_hex = &args[2];
            (
                Some(json!({
                    "operation": "sign",
                    "data": {
                        "msgHash": msg_hash,
                        "privateKeyHex": private_key_hex,
                    }
                })),
                None,
            )
        }
        4 => {
            let mode = &args[1];
            let arg2 = &args[2];
            let private_key_hex = &args[3];

            match mode.as_str() {
                "hash" => (
                    Some(json!({
                        "operation": "sign",
                        "data": {
                            "msgHash": arg2,
                            "privateKeyHex": private_key_hex,
                        }
                    })),
                    None,
                ),
                "bits" => {
                    // arg2 is JSON array of bits, e.g. "[0,1,0,1]"
                    let bits_res: Result<Vec<u8>, _> = serde_json::from_str(arg2);
                    match bits_res {
                        Ok(bits) => (
                            Some(json!({
                                "operation": "sign",
                                "data": {
                                    "bits": bits,
                                    "privateKeyHex": private_key_hex,
                                }
                            })),
                            None,
                        ),
                        Err(e) => (
                            None,
                            Some(format!("Failed to parse bits JSON: {}", e)),
                        ),
                    }
                }
                _ => (
                    None,
                    Some("First argument must be 'hash' or 'bits' when providing a mode".to_string()),
                ),
            }
        }
        _ => (
            None,
            Some("Usage: eddsa_cli <msgHashDecimal> <privateKeyHex> | eddsa_cli hash <msgHashDecimal> <privateKeyHex> | eddsa_cli bits <bitsJson> <privateKeyHex>".to_string()),
        ),
    };

    if let Some(err) = usage_error {
        eprintln!(
            "{}",
            json!({
                "success": false,
                "error": err
            })
            .to_string()
        );
        process::exit(1);
    }

    let request = request.expect("request must be Some when no usage_error is set");

    let input_json = request.to_string();

    match sign_eddsa(&input_json) {
        Ok(output_json) => {
            // `sign_eddsa` returns SignResult { success, result, error }
            // We unwrap it here and only print the inner `result` object
            // so JS can use it directly as { Ax, Ay, R8x, R8y, S }.
            match serde_json::from_str::<serde_json::Value>(&output_json) {
                Ok(v) => {
                    if v.get("success").and_then(|s| s.as_bool()) == Some(true) {
                        if let Some(result) = v.get("result") {
                            println!("{}", result.to_string());
                        } else {
                            eprintln!(
                                "{}",
                                json!({
                                    "success": false,
                                    "error": "Missing result field in sign_eddsa output"
                                })
                                .to_string()
                            );
                            process::exit(1);
                        }
                    } else {
                        let err_msg = v
                            .get("error")
                            .and_then(|e| e.as_str())
                            .unwrap_or("Unknown sign_eddsa error");
                        eprintln!(
                            "{}",
                            json!({
                                "success": false,
                                "error": err_msg
                            })
                            .to_string()
                        );
                        process::exit(1);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "{}",
                        json!({
                            "success": false,
                            "error": format!("Failed to parse sign_eddsa output: {}", e)
                        })
                        .to_string()
                    );
                    process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!(
                "{}",
                json!({
                    "success": false,
                    "error": e
                })
                .to_string()
            );
            process::exit(1);
        }
    }
}

