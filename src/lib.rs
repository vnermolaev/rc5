extern crate core;

use std::cmp::max;
use std::convert::TryInto;
use std::ops::Shl;

// const P_16: u16 = 0xb7e1;
// const P_64: u64 = 0xb7e151628aed2a6b;
// const Q_16: u16 = 0x9e37;
// const Q_64: u64 = 0x9e3779b97f4a7c15;

#[allow(non_snake_case)]
pub struct RC5_32 {
    /// Key "representation".
    S: Vec<u32>,
    /// Number of rounds.
    r: usize,
}

#[allow(non_snake_case)]
impl RC5_32 {
    const W: u32 = 32;
    const U: usize = 4; // W / 8 = 32 / 8 = 4.
    const P: u32 = 0xb7e15163;
    const Q: u32 = 0x9e3779b9;

    /// Setup the encryption scheme.
    /// r - number of rounds.
    /// K - key byte slice.
    pub fn new(r: usize, key: &[u8]) -> Self {
        let u = Self::U;

        let b = key.len();
        log::debug!("# bytes in key, b = {b}");

        let c = max(
            1usize,
            (8.0 * (b as f64) / (Self::W as f64)).ceil() as usize,
        );
        log::debug!("length of key in words, c = {c}");

        let t = 2 * (r + 1);

        // I chose to declare L as a mutable vector instead of mapping\folding,
        // because its value shall change during mixing.
        log::debug!("Computing L:");
        let mut L = vec![0u32; b / u];
        for i in (0..b).rev() {
            L[i / u] = (L[i / u].shl(8) as u32).wrapping_add(key[i] as u32);
        }

        L.iter().enumerate().for_each(|(i, l)| {
            log::debug!("L[{}] = {:#08x}", i, l);
        });

        // I chose to declare S as a mutable vector instead of mapping\folding,
        // because its value shall change during mixing.
        let mut S = vec![0u32; t];
        S[0] = Self::P;
        for i in 1..t {
            S[i] = S[i - 1].wrapping_add(Self::Q);
        }

        S.iter().enumerate().for_each(|(i, s)| {
            log::debug!("S[{}] = {:#08x}", i, s);
        });

        let (mut A, mut B, mut i, mut j, mut k) = (0, 0, 0, 0, 0);
        while k < 3 * t {
            S[i] = S[i].wrapping_add(A).wrapping_add(B).rotate_left(3);
            A = S[i];

            let rotation = A.wrapping_add(B) % Self::W;
            L[j] = L[j].wrapping_add(A).wrapping_add(B).rotate_left(rotation);
            B = L[j];

            log::debug!("S[{}] = {:#08x}", i, A);
            log::debug!("L[{}] = {:#08x}", j, B);

            i = (i + 1) % t;
            j = (j + 1) % c;

            k += 1;
        }

        log::debug!("Final S:");
        S.iter().enumerate().for_each(|(i, s)| {
            log::debug!("S[{}] = {:#08x}", i, s);
        });

        Self { S, r }
    }

    /// This function should return a cipher text for a given key and plaintext
    pub fn encode(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if plaintext.len() / Self::U != 2 {
            // This condition can be relaxed, as following:
            // say the length of the plaintext is `n`,
            // create a service message = (length of plaintext) + plaintext + padding
            // such that the length of the service message is divisible by 2 * Self::U.
            // Split the service message into blocks of length 2 * Self::U and invoke
            // this encode function on each of them, then concatenate.
            anyhow::bail!("Plaintext length must be as long as 2 * {}", Self::U);
        }

        let (pt_0, pt_1) = plaintext.split_at(Self::U);
        let pt_0 = u32::from_le_bytes(pt_0.try_into()?);
        let pt_1 = u32::from_le_bytes(pt_1.try_into()?);

        let (A, B) = (1..=self.r).fold(
            (self.S[0].wrapping_add(pt_0), self.S[1].wrapping_add(pt_1)),
            |(mut A, mut B), round| {
                let rotation = B % Self::W;
                A = (A ^ B)
                    .rotate_left(rotation)
                    .wrapping_add(self.S[2 * round]);

                let rotation = A % Self::W;
                B = (B ^ A)
                    .rotate_left(rotation)
                    .wrapping_add(self.S[2 * round + 1]);

                log::debug!("A = {:#08x}", A);
                log::debug!("B = {:#08x}", B);
                (A, B)
            },
        );

        // Explicit use of [IntoIterator] is required,
        // see https://doc.rust-lang.org/nightly/edition-guide/rust-2021/IntoIterator-for-arrays.html
        Ok(IntoIterator::into_iter(A.to_le_bytes())
            .chain(IntoIterator::into_iter(B.to_le_bytes()))
            .collect())
    }

    /// This function should return a cipher text for a given key and plaintext
    pub fn decode(&self, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
        if ciphertext.len() / Self::U != 2 {
            anyhow::bail!("Ciphertext length must be as long as 2 * {}", Self::U);
        }

        let (ct_0, ct_1) = ciphertext.split_at(Self::U);
        let ct_0 = u32::from_le_bytes(ct_0.try_into()?);
        let ct_1 = u32::from_le_bytes(ct_1.try_into()?);

        let (A, B) = (1..=self.r)
            .rev()
            .fold((ct_0, ct_1), |(mut A, mut B), round| {
                let rotation = A % Self::W;
                B = B.wrapping_sub(self.S[2 * round + 1]).rotate_right(rotation) ^ A;

                let rotation = B % Self::W;
                A = A.wrapping_sub(self.S[2 * round]).rotate_right(rotation) ^ B;

                log::debug!("A = {:#08x}", A);
                log::debug!("B = {:#08x}", B);

                (A, B)
            });

        // Explicit use of [IntoIterator] is required,
        // see https://doc.rust-lang.org/nightly/edition-guide/rust-2021/IntoIterator-for-arrays.html
        Ok(
            IntoIterator::into_iter(A.wrapping_sub(self.S[0]).to_le_bytes())
                .chain(IntoIterator::into_iter(
                    B.wrapping_sub(self.S[1]).to_le_bytes(),
                ))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_a() -> anyhow::Result<()> {
        let _ = pretty_env_logger::try_init();

        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let rc5 = RC5_32::new(12, &key);

        let pt = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        let ct = vec![0x2D, 0xDC, 0x14, 0x9B, 0xCF, 0x08, 0x8B, 0x9E];

        let res = rc5.encode(&pt)?;

        assert_eq!(&ct[..], &res[..]);

        Ok(())
    }

    #[test]
    fn encode_b() -> anyhow::Result<()> {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];

        let rc5 = RC5_32::new(12, &key);

        let pt = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];
        let ct = vec![0x11, 0xE4, 0x3B, 0x86, 0xD2, 0x31, 0xEA, 0x64];

        let res = rc5.encode(&pt)?;

        assert_eq!(&ct[..], &res[..]);

        Ok(())
    }

    #[test]
    fn decode_a() -> anyhow::Result<()> {
        let key = vec![
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ];

        let rc5 = RC5_32::new(12, &key);

        let pt = vec![0x96, 0x95, 0x0D, 0xDA, 0x65, 0x4A, 0x3D, 0x62];
        let ct = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

        let res = rc5.decode(&ct)?;

        assert_eq!(&pt[..], &res[..]);

        Ok(())
    }

    #[test]
    fn decode_b() -> anyhow::Result<()> {
        let key = vec![
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];

        let rc5 = RC5_32::new(12, &key);

        let pt = vec![0x63, 0x8B, 0x3A, 0x5E, 0xF7, 0x2B, 0x66, 0x3F];
        let ct = vec![0xEA, 0x02, 0x47, 0x14, 0xAD, 0x5C, 0x4D, 0x84];

        let res = rc5.decode(&ct)?;

        assert_eq!(&pt[..], &res[..]);

        Ok(())
    }
}
