use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_poseidon::{Poseidon, PoseidonHasher};
use num_bigint::BigUint;
use std::str::FromStr;

const BITS_PER_CHUNK: usize = 248;

/// Hash bits using Poseidon (matching circomlibjs behavior)
/// 
/// The bits are chunked into 248-bit pieces, converted to field elements,
/// and then hashed using Poseidon with Circom-compatible parameters.
/// 
/// This implementation matches circomlibjs's `buildPoseidon()` behavior.
pub fn poseidon_hash_bits(bits: &[u8]) -> Result<Fr, String> {
    // Validate bits (should be 0 or 1)
    for &bit in bits {
        if bit > 1 {
            return Err("Bits must be 0 or 1".to_string());
        }
    }

    // Chunk bits into 248-bit pieces (matching circomlibjs)
    let mut chunks = Vec::new();
    
    for i in (0..bits.len()).step_by(BITS_PER_CHUNK) {
        let chunk_end = (i + BITS_PER_CHUNK).min(bits.len());
        let mut chunk = bits[i..chunk_end].to_vec();
        
        // Pad the last chunk with zeros if needed
        while chunk.len() < BITS_PER_CHUNK {
            chunk.push(0);
        }
        
        // Convert bits to BigInt (little-endian, matching circomlibjs)
        // circomlibjs does: const reversedChunk = [...chunk].reverse();
        let reversed_chunk: Vec<u8> = chunk.iter().rev().copied().collect();
        let value = bits_to_biguint(&reversed_chunk);
        
        // Convert BigUint to field element (BN254 field)
        // JavaScript's Poseidon accepts BigInt and handles field reduction internally
        // We convert to string and use Fr::from_str which handles the reduction
        // Note: Fr::from_str automatically reduces modulo field modulus
        let field_element = Fr::from_str(&value.to_string())
            .map_err(|_| "Failed to convert chunk to field element".to_string())?;
        
        chunks.push(field_element);
    }

    // Hash using Poseidon with Circom-compatible parameters
    // circomlibjs uses: const poseidon = await circomlibjs.buildPoseidon();
    //                   const msgHash = poseidon(chunks);
    // 
    // light-poseidon's new_circom creates a Poseidon instance with the same
    // parameters as circomlib, matching circomlibjs behavior
    
    let num_inputs = chunks.len();
    if num_inputs == 0 {
        return Err("Cannot hash empty input".to_string());
    }

    // Create Poseidon instance with Circom parameters for the number of inputs
    // Note: light-poseidon supports up to a certain number of inputs
    // For larger inputs, we may need to hash in batches
    let mut poseidon = Poseidon::<Fr>::new_circom(num_inputs)
        .map_err(|e| format!("Failed to create Poseidon instance: {:?}", e))?;

    // Hash the chunks
    let hash = poseidon.hash(&chunks)
        .map_err(|e| format!("Poseidon hash failed: {:?}", e))?;

    Ok(hash)
}

/// Convert bits (big-endian, matching JavaScript BigInt('0b' + bits.join(''))) to BigUint
/// JavaScript treats the binary string as big-endian (most significant bit first)
fn bits_to_biguint(bits: &[u8]) -> BigUint {
    let mut value = BigUint::from(0u32);
    
    // Read bits from left to right (big-endian, matching JavaScript)
    for &bit in bits {
        value <<= 1;
        if bit == 1 {
            value += 1u32;
        }
    }
    
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bits_to_biguint() {
        // Little-endian: [1, 0, 1] = 1*1 + 0*2 + 1*4 = 5
        let bits = vec![1, 0, 1];
        let value = bits_to_biguint(&bits);
        assert_eq!(value, BigUint::from(5u32));
    }

    #[test]
    fn test_poseidon_hash_bits() {
        let bits = vec![0, 1, 0, 1, 1, 0, 1, 0];
        let result = poseidon_hash_bits(&bits);
        assert!(result.is_ok());
    }

    #[test]
    fn test_poseidon_hash_empty() {
        let bits = vec![];
        let result = poseidon_hash_bits(&bits);
        assert!(result.is_err());
    }

    #[test]
    fn test_poseidon_hash_large_input() {
        // Test with more than 248 bits (should create multiple chunks)
        let bits: Vec<u8> = (0..500).map(|_| 1).collect();
        let result = poseidon_hash_bits(&bits);
        assert!(result.is_ok());
    }
}
