//! SHA-256.
//!
//! Written out rather than pulled from a crate, for the reason this
//! project pulls in as little as possible generally: everything linked
//! into the kernel is part of its trusted surface, and this one would be
//! part of the *trust decision* surface specifically - it is what decides
//! whether a package's contents are what its publisher signed.
//!
//! It is also one of the few cryptographic primitives where writing it
//! yourself is defensible. SHA-256 is a fixed, fully specified
//! transformation with no key material, no branches on secret data, and
//! no parameter choices to get wrong. There is exactly one correct output
//! for any input, and the standard's own test vectors say what it is - so
//! "did I implement it right" is a question with a checkable answer,
//! which is emphatically not true of, say, a signature scheme.
//!
//! ## Verified against the standard's vectors
//!
//! `selftest_vectors` below checks the two vectors from FIPS 180-4 plus
//! the empty-input case, at boot, every boot. That matters more than it
//! might seem: a subtly wrong hash function does not fail - it produces
//! consistent, wrong digests, so packages verify against each other and
//! against nothing else. The failure would appear as "signatures from the
//! build server never validate", months later, with no obvious cause.
//!
//! ## What this is not
//!
//! Not constant-time in any deliberate sense, and it does not need to be:
//! there is no secret input. A hash of a package's contents is computed
//! over data the attacker already has.

/// The eight initial hash values: the fractional parts of the square
/// roots of the first eight primes. Constants from the standard, not
/// choices.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants: fractional parts of the cube roots of the first
/// sixty-four primes.
#[rustfmt::skip]
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// A running SHA-256 computation.
///
/// Incremental rather than one-shot, because a package's digest is
/// computed over several separate regions - the manifest, then each
/// file - and buffering them into one contiguous allocation first would
/// mean holding a copy of the entire package in memory to hash it.
pub struct Sha256 {
    state: [u32; 8],
    /// Partial block, for input that does not arrive in 64-byte pieces.
    buffer: [u8; 64],
    buffered: usize,
    /// Total input length in *bits*, which is what the padding encodes.
    /// Counting bits rather than bytes matches the standard directly and
    /// removes a multiply-at-the-end that would be easy to get wrong.
    length_bits: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 {
            state: H0,
            buffer: [0; 64],
            buffered: 0,
            length_bits: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.length_bits = self
            .length_bits
            .wrapping_add((data.len() as u64).wrapping_mul(8));

        // Finish any partial block first, so the main loop below can
        // assume it starts on a block boundary.
        if self.buffered > 0 {
            let want = core::cmp::min(64 - self.buffered, data.len());
            self.buffer[self.buffered..self.buffered + want].copy_from_slice(&data[..want]);
            self.buffered += want;
            data = &data[want..];

            if self.buffered == 64 {
                let block = self.buffer;
                self.compress(&block);
                self.buffered = 0;
            }
        }

        while data.len() >= 64 {
            let (block, rest) = data.split_at(64);
            self.compress(block.try_into().unwrap());
            data = rest;
        }

        if !data.is_empty() {
            self.buffer[..data.len()].copy_from_slice(data);
            self.buffered = data.len();
        }
    }

    /// Finishes and returns the 32-byte digest.
    pub fn finish(mut self) -> [u8; 32] {
        // Padding: a single 1 bit, then zeroes, then the length as a
        // 64-bit big-endian bit count, arranged so the total is a
        // multiple of 64 bytes. The length is captured before padding is
        // appended, since appending would otherwise change it.
        let length_bits = self.length_bits;

        self.update_without_length(&[0x80]);
        while self.buffered != 56 {
            self.update_without_length(&[0x00]);
        }
        self.update_without_length(&length_bits.to_be_bytes());

        let mut digest = [0u8; 32];
        for (index, word) in self.state.iter().enumerate() {
            digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        digest
    }

    /// `update` without counting the bytes towards the length.
    ///
    /// Used only for padding, which by definition must not be included in
    /// the length it encodes. Keeping it a separate function rather than
    /// a flag on `update` means the ordinary path cannot accidentally
    /// take it.
    fn update_without_length(&mut self, data: &[u8]) {
        let before = self.length_bits;
        self.update(data);
        self.length_bits = before;
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for index in 0..16 {
            w[index] = u32::from_be_bytes(block[index * 4..index * 4 + 4].try_into().unwrap());
        }
        for index in 16..64 {
            let s0 = w[index - 15].rotate_right(7)
                ^ w[index - 15].rotate_right(18)
                ^ (w[index - 15] >> 3);
            let s1 = w[index - 2].rotate_right(17)
                ^ w[index - 2].rotate_right(19)
                ^ (w[index - 2] >> 10);
            w[index] = w[index - 16]
                .wrapping_add(s0)
                .wrapping_add(w[index - 7])
                .wrapping_add(s1);
        }

        let mut v = self.state;
        for index in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let temp1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[index])
                .wrapping_add(w[index]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let temp2 = s0.wrapping_add(maj);

            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(temp1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = temp1.wrapping_add(temp2);
        }

        for (slot, value) in self.state.iter_mut().zip(v) {
            *slot = slot.wrapping_add(value);
        }
    }
}

/// One-shot convenience.
pub fn digest(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finish()
}

/// Compares two digests without an early exit.
///
/// Not because timing matters here - a package digest is public - but
/// because this function is the one that will be reached for when
/// something *secret* needs comparing, and a `==` that happens to be
/// there first is how a timing leak gets introduced later. Providing the
/// right primitive now costs nothing.
pub fn digests_equal(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut difference = 0u8;
    for index in 0..32 {
        difference |= a[index] ^ b[index];
    }
    difference == 0
}

/// Checks this implementation against the standard's own test vectors.
///
/// Run at boot, every boot. A subtly wrong hash function does not fail -
/// it produces consistent, wrong digests, so packages verify against each
/// other and against nothing else. That failure surfaces as "signatures
/// from the build server never validate", months later, with no obvious
/// cause.
pub fn selftest_vectors() -> bool {
    // FIPS 180-4, appendix B: "abc".
    let abc = digest(b"abc");
    let expected_abc: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];

    // The empty string - the case that exercises padding with no message
    // at all, which is where an off-by-one in the padding loop shows up.
    let empty = digest(b"");
    let expected_empty: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
    ];

    // A 56-byte message: exactly the length at which the padding no
    // longer fits in the final block and a second block is required. The
    // classic off-by-one lives here.
    let two_block = digest(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    let expected_two_block: [u8; 32] = [
        0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8, 0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60,
        0x39, 0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67, 0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb,
        0x06, 0xc1,
    ];

    digests_equal(&abc, &expected_abc)
        && digests_equal(&empty, &expected_empty)
        && digests_equal(&two_block, &expected_two_block)
}
