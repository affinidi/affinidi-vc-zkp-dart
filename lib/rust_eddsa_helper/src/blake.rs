// Original BLAKE algorithm implementation (SHA-3 proposal)
// Ported from blake-hash npm package to match circomlibjs exactly

// BLAKE512 constants
const SIGMA: [[usize; 16]; 16] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
];

const U512: [u32; 32] = [
    0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
    0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89,
    0x452821e6, 0x38d01377, 0xbe5466cf, 0x34e90c6c,
    0xc0ac29b7, 0xc97c50dd, 0x3f84d5b5, 0xb5470917,
    0x9216d5d9, 0x8979fb1b, 0xd1310ba6, 0x98dfb5ac,
    0x2ffd72db, 0xd01adfb7, 0xb8e1afed, 0x6a267e96,
    0xba7c9045, 0xf12c7f99, 0x24a19947, 0xb3916cf7,
    0x0801f2e2, 0x858efc16, 0x636920d8, 0x71574e69,
];

// BLAKE padding buffer (starts with 0x80, rest zeros) - 111 bytes total
fn get_padding() -> [u8; 111] {
    let mut padding = [0u8; 111];
    padding[0] = 0x80;
    padding
}

pub struct Blake512 {
    h: [u32; 16],
    s: [u32; 8],
    block: [u8; 128],
    block_offset: usize,
    length: [u32; 4],
    nullt: bool,
}

impl Blake512 {
    pub fn new() -> Self {
        // Initialization vector for BLAKE512 (as 16 u32 values)
        let h = [
            0x6a09e667, 0xf3bcc908, 0xbb67ae85, 0x84caa73b,
            0x3c6ef372, 0xfe94f82b, 0xa54ff53a, 0x5f1d36f1,
            0x510e527f, 0xade682d1, 0x9b05688c, 0x2b3e6c1f,
            0x1f83d9ab, 0xfb41bd6b, 0x5be0cd19, 0x137e2179,
        ];
        
        Self {
            h,
            s: [0; 8],
            block: [0; 128],
            block_offset: 0,
            length: [0; 4],
            nullt: false,
        }
    }
    
    pub fn update(&mut self, data: &[u8]) {
        let mut offset = 0;
        
        while self.block_offset + data.len() - offset >= 128 {
            // Fill buffer
            let to_copy = 128 - self.block_offset;
            self.block[self.block_offset..self.block_offset + to_copy]
                .copy_from_slice(&data[offset..offset + to_copy]);
            offset += to_copy;
            self.block_offset = 128;
            
            // Update length (in bits, little-endian)
            self.length[0] = self.length[0].wrapping_add(128 * 8);
            self.length_carry();
            
            // Compress
            self.compress();
            self.block_offset = 0;
        }
        
        // Copy remaining data to buffer
        let remaining = data.len() - offset;
        if remaining > 0 {
            self.block[self.block_offset..self.block_offset + remaining]
                .copy_from_slice(&data[offset..]);
            self.block_offset += remaining;
        }
    }
    
    fn length_carry(&mut self) {
        let overflow_threshold = 0x0100000000u64;
        for j in 0..self.length.len() {
            if (self.length[j] as u64) < overflow_threshold {
                break;
            }
            self.length[j] = self.length[j].wrapping_sub(overflow_threshold as u32);
            if j + 1 < self.length.len() {
                self.length[j + 1] = self.length[j + 1].wrapping_add(1);
            }
        }
    }
    
    fn rot(v: &mut [u32], i: usize, j: usize, mut n: usize) {
        let mut hi = v[i * 2] ^ v[j * 2];
        let mut lo = v[i * 2 + 1] ^ v[j * 2 + 1];
        
        // If n >= 32, swap hi and lo, then subtract 32
        if n >= 32 {
            let temp = lo;
            lo = hi;
            hi = temp;
            n -= 32;
        }
        
        if n == 0 {
            v[i * 2] = hi;
            v[i * 2 + 1] = lo;
        } else {
            v[i * 2] = ((hi >> n) | (lo << (32 - n)));
            v[i * 2 + 1] = ((lo >> n) | (hi << (32 - n)));
        }
    }
    
    fn g(v: &mut [u32], m: &[u32], i: usize, a: usize, b: usize, c: usize, d: usize, e: usize) {
        let sigma = SIGMA[i];
        let u512 = U512;
        
        // Helper to add with carry detection (matching JavaScript behavior)
        fn add_with_carry(a: u32, b: u32, c: u32) -> (u32, u32) {
            let sum = (a as u64) + (b as u64) + (c as u64);
            ((sum >> 32) as u32, sum as u32)
        }
        
        fn add_two_with_carry(a: u32, b: u32) -> (u32, u32) {
            let sum = (a as u64) + (b as u64);
            ((sum >> 32) as u32, sum as u32)
        }
        
        // v[a] += (m[sigma[i][e]] ^ u512[sigma[i][e+1]]) + v[b];
        let m_e_lo = m[sigma[e] * 2 + 1] ^ u512[sigma[e + 1] * 2 + 1];
        let m_e_hi = m[sigma[e] * 2] ^ u512[sigma[e + 1] * 2];
        let (carry1, lo) = add_with_carry(v[a * 2 + 1], m_e_lo, v[b * 2 + 1]);
        let (carry2, hi) = add_with_carry(v[a * 2], m_e_hi, v[b * 2]);
        v[a * 2] = hi.wrapping_add(carry1);
        v[a * 2 + 1] = lo;
        
        // v[d] = ROT(v[d] ^ v[a], 32);
        Self::rot(v, d, a, 32);
        
        // v[c] += v[d];
        let (carry, lo) = add_two_with_carry(v[c * 2 + 1], v[d * 2 + 1]);
        v[c * 2] = v[c * 2].wrapping_add(v[d * 2]).wrapping_add(carry);
        v[c * 2 + 1] = lo;
        
        // v[b] = ROT(v[b] ^ v[c], 25);
        Self::rot(v, b, c, 25);
        
        // v[a] += (m[sigma[i][e+1]] ^ u512[sigma[i][e]]) + v[b];
        let m_e1_lo = m[sigma[e + 1] * 2 + 1] ^ u512[sigma[e] * 2 + 1];
        let m_e1_hi = m[sigma[e + 1] * 2] ^ u512[sigma[e] * 2];
        let (carry1, lo) = add_with_carry(v[a * 2 + 1], m_e1_lo, v[b * 2 + 1]);
        let (carry2, hi) = add_with_carry(v[a * 2], m_e1_hi, v[b * 2]);
        v[a * 2] = hi.wrapping_add(carry1);
        v[a * 2 + 1] = lo;
        
        // v[d] = ROT(v[d] ^ v[a], 16);
        Self::rot(v, d, a, 16);
        
        // v[c] += v[d];
        let (carry, lo) = add_two_with_carry(v[c * 2 + 1], v[d * 2 + 1]);
        v[c * 2] = v[c * 2].wrapping_add(v[d * 2]).wrapping_add(carry);
        v[c * 2 + 1] = lo;
        
        // v[b] = ROT(v[b] ^ v[c], 11);
        Self::rot(v, b, c, 11);
    }
    
    fn compress(&mut self) {
        // v is 32 u32s (16 pairs of hi/lo)
        let mut v = [0u32; 32];
        // m is 32 u32s (16 pairs of hi/lo) - but we read as 32 single u32s from block
        let mut m = [0u32; 32];
        
        // Read block as big-endian u32s (32 u32s = 128 bytes)
        for i in 0..32 {
            m[i] = u32::from_be_bytes([
                self.block[i * 4],
                self.block[i * 4 + 1],
                self.block[i * 4 + 2],
                self.block[i * 4 + 3],
            ]);
        }
        
        // Initialize v (v is 32 u32s, but represents 16 64-bit values)
        // v[0..16] = h (16 u32s = 8 64-bit values, but h is stored as 16 u32s)
        for i in 0..16 {
            v[i] = self.h[i];
        }
        // v[16..24] = s ^ u512[0..8]
        for i in 16..24 {
            v[i] = self.s[i - 16] ^ U512[i - 16];
        }
        // v[24..32] = u512[8..16]
        for i in 24..32 {
            v[i] = U512[i - 16];
        }
        
        // XOR length if not nullt
        if !self.nullt {
            v[24] ^= self.length[1];
            v[25] ^= self.length[0];
            v[26] ^= self.length[1];
            v[27] ^= self.length[0];
            v[28] ^= self.length[3];
            v[29] ^= self.length[2];
            v[30] ^= self.length[3];
            v[31] ^= self.length[2];
        }
        
        // 16 rounds
        for i in 0..16 {
            // Column step
            Self::g(&mut v, &m, i, 0, 4, 8, 12, 0);
            Self::g(&mut v, &m, i, 1, 5, 9, 13, 2);
            Self::g(&mut v, &m, i, 2, 6, 10, 14, 4);
            Self::g(&mut v, &m, i, 3, 7, 11, 15, 6);
            // Diagonal step
            Self::g(&mut v, &m, i, 0, 5, 10, 15, 8);
            Self::g(&mut v, &m, i, 1, 6, 11, 12, 10);
            Self::g(&mut v, &m, i, 2, 7, 8, 13, 12);
            Self::g(&mut v, &m, i, 3, 4, 9, 14, 14);
        }
        
        // Finalize h - XOR v back into h
        // h is stored as 16 u32s (8 64-bit values)
        // v[0..16] contains the result (16 u32s = 8 64-bit values)
        for i in 0..16 {
            self.h[(i % 8) * 2] ^= v[i * 2];
            self.h[(i % 8) * 2 + 1] ^= v[i * 2 + 1];
        }
        
        // XOR with salt
        for i in 0..8 {
            self.h[i * 2] ^= self.s[(i % 4) * 2];
            self.h[i * 2 + 1] ^= self.s[(i % 4) * 2 + 1];
        }
    }
    
    fn padding(&mut self) {
        // Create a copy of length for msglen calculation
        let mut len = self.length;
        len[0] = len[0].wrapping_add(self.block_offset as u32 * 8);
        // Carry in the copy (matching JavaScript _lengthCarry)
        let overflow_threshold = 0x0100000000u64;
        for j in 0..len.len() {
            if (len[j] as u64) < overflow_threshold {
                break;
            }
            len[j] = len[j].wrapping_sub(overflow_threshold as u32);
            if j + 1 < len.len() {
                len[j + 1] = len[j + 1].wrapping_add(1);
            }
        }
        
        // Create msglen buffer (big-endian, reversed order)
        let mut msglen = [0u8; 16];
        for i in 0..4 {
            let bytes = len[3 - i].to_be_bytes();
            msglen[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        
        let padding = get_padding();
        
        if self.block_offset == 111 {
            self.length[0] = self.length[0].wrapping_sub(8);
            self.update(&[0x81]); // _oo
        } else {
            if self.block_offset < 111 {
                if self.block_offset == 0 {
                    self.nullt = true;
                }
                self.length[0] = self.length[0].wrapping_sub((111 - self.block_offset) as u32 * 8);
                self.update(&padding[0..111 - self.block_offset]);
            } else {
                self.length[0] = self.length[0].wrapping_sub((128 - self.block_offset) as u32 * 8);
                self.update(&padding[0..128 - self.block_offset]);
                self.length[0] = self.length[0].wrapping_sub(111 * 8);
                self.update(&padding[1..112]); // Skip first byte (0x80), take 111 bytes
                self.nullt = true;
            }
            
            self.update(&[0x01]); // _zo
            self.length[0] = self.length[0].wrapping_sub(8);
        }
        
        self.length[0] = self.length[0].wrapping_sub(128);
        self.update(&msglen);
    }
    
    pub fn digest(mut self) -> [u8; 64] {
        self.padding();
        
        let mut result = [0u8; 64];
        for i in 0..16 {
            let bytes = self.h[i].to_be_bytes();
            result[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
        }
        result
    }
}

/// Blake512 hash function matching blake-hash npm package
pub fn blake512(data: &[u8]) -> Vec<u8> {
    let mut hasher = Blake512::new();
    hasher.update(data);
    hasher.digest().to_vec()
}
