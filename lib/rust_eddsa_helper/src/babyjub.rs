// Baby Jubjub curve implementation matching circomlibjs
// Curve parameters: A = 168700, D = 168696
// Note: Use ark_bn254::Fr (not Fq) - it has the correct modulus for Baby Jubjub
use ark_bn254::Fr;
use ark_ff::Field;
use num_bigint::BigUint;
use std::str::FromStr;

pub struct BabyJubPoint {
    pub x: Fr,
    pub y: Fr,
}

// Baby Jubjub curve parameters
const A: &str = "168700";
const D: &str = "168696";

impl BabyJubPoint {
    pub fn new(x: Fr, y: Fr) -> Self {
        BabyJubPoint { x, y }
    }
    
    /// Add two points on Baby Jubjub curve (matching circomlibjs.addPoint)
    /// Formula from circomlibjs:
    /// res[0] = (beta + gamma) / (1 + d*tau)
    /// res[1] = (delta + A*beta - gamma) / (1 - d*tau)
    /// where:
    ///   beta = a[0]*b[1]
    ///   gamma = a[1]*b[0]
    ///   delta = (a[1] - A*a[0]) * (b[0] + b[1])
    ///   tau = beta * gamma
    ///   dtau = D * tau
    pub fn add(&self, other: &BabyJubPoint) -> BabyJubPoint {
        let a = Fr::from_str(A).unwrap();
        let d = Fr::from_str(D).unwrap();
        
        let beta = self.x * other.y;
        let gamma = self.y * other.x;
        let delta = (self.y - a * self.x) * (other.x + other.y);
        let tau = beta * gamma;
        let dtau = d * tau;
        
        let one = Fr::from(1u64);
        let denom_x = one + dtau;
        let denom_y = one - dtau;
        
        // Compute inverses
        let inv_x = denom_x.inverse().unwrap();
        let inv_y = denom_y.inverse().unwrap();
        
        let x = (beta + gamma) * inv_x;
        let y = (delta + a * beta - gamma) * inv_y;
        
        BabyJubPoint::new(x, y)
    }
    
    /// Scalar multiplication using double-and-add (matching circomlibjs.mulPointEscalar)
    pub fn mul_scalar(&self, scalar: &BigUint) -> BabyJubPoint {
        let curve_order = BigUint::from_str("21888242871839275222246405745257275088614511777268538073601725287587578984328")
            .unwrap();
        let mut rem = scalar % &curve_order;
        
        // Identity point (0, 1)
        let mut result = BabyJubPoint::new(
            Fr::from(0u64),
            Fr::from(1u64)
        );
        let mut exp = BabyJubPoint::new(self.x, self.y);
        
        while rem != BigUint::from(0u32) {
            if rem.bit(0) {
                result = result.add(&exp);
            }
            exp = exp.add(&exp); // double
            rem = &rem >> 1;
        }
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_base8_doubling() {
        let base8_x = Fr::from_str("5299619240641551281634865583518297030282874472190772894086521144482721001553").unwrap();
        let base8_y = Fr::from_str("16950150798460657717958625567821834550301663161624707787222815936182638968203").unwrap();
        
        let base8 = BabyJubPoint::new(base8_x, base8_y);
        let base8_2 = base8.add(&base8);
        
        // Expected from JavaScript
        let expected_x = Fr::from_str("10031262171927540148667355526369034398030886437092045105752248699557385197826").unwrap();
        let expected_y = Fr::from_str("633281375905621697187330766174974863687049529291089048651929454608812697683").unwrap();
        
        assert_eq!(base8_2.x, expected_x);
        assert_eq!(base8_2.y, expected_y);
    }
}

