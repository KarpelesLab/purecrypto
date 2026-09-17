//! The single-step "Concatenation" KDF of NIST SP 800-56A rev. 1 §5.8.1
//! (also SP 800-56C rev. 2 §4, option 1 with a plain hash).
//!
//! `K = H(1 ‖ Z ‖ OtherInfo) ‖ H(2 ‖ Z ‖ OtherInfo) ‖ …` truncated to the
//! requested length, where the counter is a 32-bit big-endian integer. JOSE
//! (RFC 7518 §4.6.2) uses it with SHA-256 for `ECDH-ES`, with
//! `OtherInfo = AlgorithmID ‖ PartyUInfo ‖ PartyVInfo ‖ SuppPubInfo`, each
//! of the first three a 32-bit big-endian length followed by the data and
//! `SuppPubInfo` the key length in bits.

use crate::hash::Digest;

/// Errors from [`concat_kdf`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// `out.len()` exceeds `hash_len · (2³² − 1)`, the counter's reach.
    OutputTooLong,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::OutputTooLong => f.write_str("Concat KDF output exceeds the counter range"),
        }
    }
}

impl core::error::Error for Error {}

/// Derives `out.len()` bytes from the shared secret `z` and `other_info`
/// with hash `D`, per SP 800-56A §5.8.1.
///
/// `other_info` is passed as parts that are hashed in order, so callers can
/// bind length-prefixed fields without concatenating them first. The
/// intermediate digests are wiped after use.
pub fn concat_kdf<D: Digest>(z: &[u8], other_info: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    let hlen = D::OUTPUT_LEN;
    let reps = out.len().div_ceil(hlen);
    if reps > u32::MAX as usize {
        return Err(Error::OutputTooLong);
    }
    for (i, chunk) in out.chunks_mut(hlen).enumerate() {
        let counter = (i as u32 + 1).to_be_bytes();
        let mut h = D::new();
        h.update(&counter);
        h.update(z);
        for part in other_info {
            h.update(part);
        }
        let mut digest = h.finalize();
        chunk.copy_from_slice(&digest.as_ref()[..chunk.len()]);
        crate::zeroize::Zeroize::zeroize(digest.as_mut());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;

    /// RFC 7518 Appendix C: ECDH-ES with A128GCM, SHA-256 Concat KDF.
    #[test]
    fn rfc7518_appendix_c() {
        let z = [
            158u8, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49,
            110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196,
        ];
        let alg = b"A128GCM";
        let apu = b"Alice";
        let apv = b"Bob";
        let mut out = [0u8; 16];
        concat_kdf::<Sha256>(
            &z,
            &[
                &(alg.len() as u32).to_be_bytes(),
                alg,
                &(apu.len() as u32).to_be_bytes(),
                apu,
                &(apv.len() as u32).to_be_bytes(),
                apv,
                &128u32.to_be_bytes(),
            ],
            &mut out,
        )
        .unwrap();
        assert_eq!(
            out,
            [
                86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26
            ]
        );
    }

    #[test]
    fn multi_block_output_is_counter_chained() {
        let mut long = [0u8; 70];
        concat_kdf::<Sha256>(b"z", &[b"info"], &mut long).unwrap();
        let mut one = Sha256::new();
        one.update(&2u32.to_be_bytes());
        one.update(b"z");
        one.update(b"info");
        assert_eq!(&long[32..64], one.finalize().as_ref());
    }
}
