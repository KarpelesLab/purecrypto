//! Fuzz every public byte decoder of the three pairing-friendly curve
//! modules — `bls` (BLS12-381), `bn254` and `bls12_377`: `G1` / `G2`
//! points (compressed, uncompressed, and the arkworks forms on
//! BLS12-377), `Gt` elements, `Fp` / `Fr` field elements, the BLS
//! signature scheme's secret keys, public keys, signatures and proofs of
//! possession (`min_pk` and `min_sig`), and BN254's EIP-197 `ecPairing`
//! input.
//!
//! These bytes arrive from the network or a chain (aggregate signatures,
//! precompile inputs, proofs), and each decoder does real work on them —
//! canonicity checks, a square root, the curve equation and a subgroup
//! check — so none may panic on any input.
//!
//! Every encoding is canonical (one byte string per value), so a
//! successful decode must re-encode to exactly the input; a mismatch is a
//! malleable encoding and is reported as a crash. For the group elements
//! the compressed and uncompressed forms are also cross-checked against
//! each other.
//!
//! No selector byte: the whole input goes to every decoder. Almost all of
//! them reject on length first, and the handful of lengths (32 / 48 / 64 /
//! 96 / 128 / 192 / 384 / 576) are shared between curves, so one corpus
//! entry exercises several decoders at once.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::{bls, bls12_377, bn254};

/// The largest input any decoder here accepts is EIP-197's: a multiple of
/// 192 bytes, each valid record costing one Miller loop. Four records keep
/// an iteration in the low milliseconds.
const MAX_INPUT: usize = 4 * 192;

/// `$dec(data)` must not panic, and on success `$enc()` must give `data`
/// back.
macro_rules! canonical {
    ($data:expr; $($ty:ty { $($dec:ident => $enc:ident),+ $(,)? })+) => {
        $($(
            if let Ok(v) = <$ty>::$dec($data) {
                assert_eq!(
                    &v.$enc()[..],
                    $data,
                    concat!(stringify!($ty), "::", stringify!($dec), " is not canonical"),
                );
            }
        )+)+
    };
}

/// A group element: both encodings canonical, and each decodes to the same
/// point as the other.
macro_rules! group {
    ($data:expr; $($ty:ty),+ $(,)?) => {
        $(
            canonical!($data; $ty {
                from_compressed => to_compressed,
                from_uncompressed => to_uncompressed,
            });
            if let Ok(p) = <$ty>::from_compressed($data) {
                assert!(
                    <$ty>::from_uncompressed(&p.to_uncompressed()) == Ok(p),
                    concat!(stringify!($ty), ": uncompressed form of a compressed point"),
                );
            }
            if let Ok(p) = <$ty>::from_uncompressed($data) {
                assert!(
                    <$ty>::from_compressed(&p.to_compressed()) == Ok(p),
                    concat!(stringify!($ty), ": compressed form of an uncompressed point"),
                );
            }
        )+
    };
}

/// The decoders that take a fixed-size array: run `$body` when the input
/// has exactly that length.
macro_rules! exact {
    ($data:expr, $n:literal, |$b:ident| $body:block) => {
        if let Ok($b) = <&[u8; $n]>::try_from($data) $body
    };
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }

    // --- Group elements.
    group!(data; bls::G1, bls::G2, bn254::G1, bn254::G2, bls12_377::G1, bls12_377::G2);
    canonical!(data;
        bls12_377::G1 {
            from_compressed_ark => to_compressed_ark,
            from_uncompressed_ark => to_uncompressed_ark,
        }
        bls12_377::G2 {
            from_compressed_ark => to_compressed_ark,
            from_uncompressed_ark => to_uncompressed_ark,
        }
    );
    // The gnark and arkworks forms of one point decode to the same point.
    if let Ok(p) = bls12_377::G1::from_compressed_ark(data) {
        assert!(bls12_377::G1::from_compressed(&p.to_compressed()) == Ok(p));
    }
    if let Ok(p) = bls12_377::G2::from_compressed_ark(data) {
        assert!(bls12_377::G2::from_compressed(&p.to_compressed()) == Ok(p));
    }

    // --- Target-group elements (BLS12-381 has no `Gt` byte codec).
    canonical!(data; bn254::Gt { from_bytes => to_bytes });
    exact!(data, 576, |b| {
        canonical!(b; bls12_377::Gt {
            from_bytes => to_bytes,
            from_bytes_ark => to_bytes_ark,
        });
    });

    // --- Field elements and scalars.
    exact!(data, 32, |b| {
        if let Some(v) = bls::Fr::from_bytes(b) {
            assert_eq!(&v.to_bytes(), b);
        }
        if let Some(v) = bn254::Fr::from_bytes(b) {
            assert_eq!(&v.to_bytes(), b);
        }
        if let Some(v) = bn254::Fr::from_bytes_le(b) {
            assert_eq!(&v.to_bytes_le(), b);
        }
        if let Some(v) = bls12_377::Fr::from_bytes(b) {
            assert_eq!(&v.to_bytes(), b);
        }
        if let Some(v) = bls12_377::Fr::from_bytes_le(b) {
            assert_eq!(&v.to_bytes_le(), b);
        }
        if let Some(v) = bn254::Fp::from_bytes(b).into_option() {
            assert_eq!(&v.to_bytes(), b);
        }
        // BLS secret keys: a canonical nonzero scalar.
        canonical!(b;
            bls::SecretKey { from_bytes => to_bytes }
            bn254::min_pk::SecretKey { from_bytes => to_bytes }
            bn254::min_sig::SecretKey { from_bytes => to_bytes }
            bls12_377::min_pk::SecretKey { from_bytes => to_bytes }
            bls12_377::min_sig::SecretKey { from_bytes => to_bytes }
        );
    });
    exact!(data, 48, |b| {
        if let Some(v) = bls::Fp::from_bytes(b).into_option() {
            assert_eq!(&v.to_bytes(), b);
        }
        if let Some(v) = bls12_377::Fp::from_bytes(b).into_option() {
            assert_eq!(&v.to_bytes(), b);
        }
        if let Some(v) = bls12_377::Fp::from_bytes_le(b).into_option() {
            assert_eq!(&v.to_bytes_le(), b);
        }
    });
    // Wide reduction accepts every 64-byte string.
    exact!(data, 64, |b| {
        let _ = bn254::Fr::from_bytes_wide(b);
        let _ = bls12_377::Fr::from_bytes_wide(b);
    });

    // --- BLS signature scheme objects.
    canonical!(data;
        bls::PublicKey { from_bytes => to_bytes }
        bls::Signature { from_bytes => to_bytes }
        bls::ProofOfPossession { from_bytes => to_bytes }
        bn254::min_pk::PublicKey { from_bytes => to_bytes, from_uncompressed => to_uncompressed }
        bn254::min_pk::Signature { from_bytes => to_bytes, from_uncompressed => to_uncompressed }
        bn254::min_pk::ProofOfPossession { from_bytes => to_bytes }
        bn254::min_sig::PublicKey { from_bytes => to_bytes, from_uncompressed => to_uncompressed }
        bn254::min_sig::Signature { from_bytes => to_bytes, from_uncompressed => to_uncompressed }
        bn254::min_sig::ProofOfPossession { from_bytes => to_bytes }
        bls12_377::min_pk::PublicKey {
            from_bytes => to_bytes,
            from_uncompressed => to_uncompressed,
        }
        bls12_377::min_pk::Signature {
            from_bytes => to_bytes,
            from_uncompressed => to_uncompressed,
        }
        bls12_377::min_pk::ProofOfPossession { from_bytes => to_bytes }
        bls12_377::min_sig::PublicKey {
            from_bytes => to_bytes,
            from_uncompressed => to_uncompressed,
        }
        bls12_377::min_sig::Signature {
            from_bytes => to_bytes,
            from_uncompressed => to_uncompressed,
        }
        bls12_377::min_sig::ProofOfPossession { from_bytes => to_bytes }
    );

    // --- EIP-197 `ecPairing`: 192-byte (G1 ‖ G2) records, every point
    // validated before the pairing product.
    let _ = bn254::pairing_check_eip197(data);
});
