//! Key agreement for the groups whose handling is shared by the TLS 1.3,
//! DTLS 1.3 and QUIC engines: secp521r1 ECDHE (RFC 8446 §4.2.8.2) and the
//! two NIST-curve ML-KEM hybrids of RFC 10024, SecP256r1MLKEM768 and
//! SecP384r1MLKEM1024.
//!
//! # Wire layouts (RFC 10024 §4)
//!
//! | group              | client share                  | server share                  | shared secret          |
//! |--------------------|-------------------------------|-------------------------------|------------------------|
//! | SecP256r1MLKEM768  | P-256 point (65) ‖ ek (1184)  | P-256 point (65) ‖ ct (1088)  | ECDH x (32) ‖ K (32)   |
//! | SecP384r1MLKEM1024 | P-384 point (97) ‖ ek (1568)  | P-384 point (97) ‖ ct (1568)  | ECDH x (48) ‖ K (32)   |
//!
//! Both put the **ECDH part first**, in the share and in the shared secret
//! — the opposite of X25519MLKEM768, whose ML-KEM part leads "for
//! historical reasons" (§4.1). The order matters beyond interoperability:
//! §5 places the FIPS-approved scheme first so the concatenation is an
//! SP 800-56C two-secret derivation.
//!
//! # Validation
//!
//! Every peer-supplied value is checked before it is used, and every
//! failure is `illegal_parameter` (RFC 10024 §4.2 / §4.3):
//!
//! * the share has exactly the length the group fixes;
//! * the EC point is in the *uncompressed* form (RFC 8446 §4.2.8.2 —
//!   `legacy_form = 4`; TLS 1.3 has no point-format negotiation, so a
//!   compressed point is malformed even though SEC1 can decode it), both
//!   coordinates are field elements, and the point is on the curve. The
//!   point at infinity has no uncompressed encoding, and the NIST curves
//!   have cofactor 1, so an on-curve point is in the prime-order group;
//! * the ML-KEM encapsulation key passes the FIPS 203 §7.2 modulus check
//!   (every coefficient in `[0, q)`).
//!
//! An ML-KEM ciphertext of the right length cannot be "invalid": FIPS 203
//! decapsulation rejects implicitly, returning a pseudorandom secret the
//! peer does not know, and the handshake then dies at the first protected
//! record instead of at the key share.
//!
//! The secret scalar only ever meets the constant-time fixed-window
//! multiplication of [`crate::ec`]'s Weierstrass arithmetic, and ML-KEM
//! decapsulation is constant-time by construction; every transient copy of
//! a shared secret is wiped here, leaving the [`Secret`] the caller gets.

use super::Secret;
use crate::ec::{BoxedEcdhPrivateKey, BoxedEcdsaPublicKey, CurveId};
use crate::mlkem::{
    MlKem768Ciphertext, MlKem768DecapsKey, MlKem768EncapsKey, MlKem1024Ciphertext,
    MlKem1024DecapsKey, MlKem1024EncapsKey,
};
use crate::rng::RngCore;
use crate::tls::Error;
use crate::tls::conn::wipe;
use alloc::vec::Vec;

/// Length of an uncompressed SEC1 point on `curve`: `0x04 ‖ X ‖ Y`.
fn point_len(curve: CurveId) -> usize {
    1 + 2 * curve.field_len()
}

/// Parses a peer's ECDHE share as an uncompressed point on `curve`
/// (RFC 8446 §4.2.8.2), validating it as described in the module docs.
fn peer_point(curve: CurveId, bytes: &[u8]) -> Result<BoxedEcdsaPublicKey, Error> {
    // `from_sec1` also decodes the compressed forms (`0x02`/`0x03`), which
    // TLS 1.3 does not allow: pin the form and the length first.
    if bytes.len() != point_len(curve) || bytes[0] != 0x04 {
        return Err(Error::IllegalParameter);
    }
    BoxedEcdsaPublicKey::from_sec1(curve, bytes).map_err(|_| Error::IllegalParameter)
}

/// `sk · peer`: the x-coordinate of the shared point, `field_len` bytes
/// (RFC 8446 §7.4.2). The caller owns — and wipes — the returned buffer.
fn ecdh(sk: &BoxedEcdhPrivateKey, peer: &BoxedEcdsaPublicKey) -> Result<Vec<u8>, Error> {
    // Only the identity fails here, which a validated point on a
    // prime-order curve and a scalar in `[1, n-1]` cannot produce.
    sk.diffie_hellman(peer).map_err(|_| Error::IllegalParameter)
}

/// `ecdh ‖ mlkem` as a [`Secret`], wiping both inputs.
fn combine(mut ecdh_ss: Vec<u8>, mut ml_ss: [u8; 32]) -> Secret {
    // 48 (P-384) + 32 is the longest shared secret of any group.
    let mut combined = [0u8; 80];
    let n = ecdh_ss.len() + ml_ss.len();
    combined[..ecdh_ss.len()].copy_from_slice(&ecdh_ss);
    combined[ecdh_ss.len()..n].copy_from_slice(&ml_ss);
    let secret = Secret::new(&combined[..n]);
    wipe(&mut combined);
    wipe(&mut ecdh_ss);
    wipe(&mut ml_ss);
    secret
}

/// Client side of a plain ECDHE group served by the boxed curves
/// (secp521r1): the shared secret with the server's share.
pub(crate) fn ecdhe_client(sk: &BoxedEcdhPrivateKey, server_share: &[u8]) -> Result<Secret, Error> {
    let peer = peer_point(sk.curve(), server_share)?;
    let mut shared = ecdh(sk, &peer)?;
    let secret = Secret::new(&shared);
    wipe(&mut shared);
    Ok(secret)
}

/// Server side of a plain ECDHE group served by the boxed curves
/// (secp521r1): validates the client's share, draws an ephemeral key and
/// returns `(server share, shared secret)`.
pub(crate) fn ecdhe_server<R: RngCore>(
    curve: CurveId,
    rng: &mut R,
    client_share: &[u8],
) -> Result<(Vec<u8>, Secret), Error> {
    // Validate before generating anything: a hostile share costs a curve
    // check, not a key generation.
    let peer = peer_point(curve, client_share)?;
    let sk = BoxedEcdhPrivateKey::generate(curve, rng);
    let mut shared = ecdh(&sk, &peer)?;
    let secret = Secret::new(&shared);
    wipe(&mut shared);
    Ok((sk.public_key().to_sec1(), secret))
}

/// Emits the client and server halves of one ECDH + ML-KEM hybrid.
macro_rules! ecdh_mlkem_hybrid {
    (
        $curve:expr, $dk:ident, $ek:ident, $ct:ident,
        $client_share:ident, $client:ident, $server:ident, $name:literal
    ) => {
        #[doc = concat!("The client's `key_exchange` for ", $name, ": the uncompressed")]
        /// ECDH point followed by the ML-KEM encapsulation key (RFC 10024
        /// §4.1).
        pub(crate) fn $client_share(ec: &BoxedEcdhPrivateKey, dk: &$dk) -> Vec<u8> {
            debug_assert_eq!(ec.curve(), $curve);
            let mut share = ec.public_key().to_sec1();
            share.extend_from_slice(&dk.encapsulation_key().to_bytes());
            share
        }

        #[doc = concat!("Client side of ", $name, ": splits the server's share into")]
        /// the ECDH point and the ML-KEM ciphertext (RFC 10024 §4.2),
        /// and returns the ECDH secret followed by the decapsulated one
        /// (§4.3).
        pub(crate) fn $client(
            ec: &BoxedEcdhPrivateKey,
            dk: &$dk,
            server_share: &[u8],
        ) -> Result<Secret, Error> {
            let plen = point_len($curve);
            // RFC 10024 §4.2: a ciphertext (hence share) length that does
            // not match the group is `illegal_parameter`.
            if ec.curve() != $curve || server_share.len() != plen + $ct::BYTES {
                return Err(Error::IllegalParameter);
            }
            let (point, ct_bytes) = server_share.split_at(plen);
            let peer = peer_point($curve, point)?;
            let mut ct = [0u8; $ct::BYTES];
            ct.copy_from_slice(ct_bytes);
            let ecdh_ss = ecdh(ec, &peer)?;
            let ml_ss = dk.decapsulate(&$ct::from_bytes(ct));
            Ok(combine(ecdh_ss, ml_ss))
        }

        #[doc = concat!("Server side of ", $name, ": validates the client's point and")]
        /// encapsulation key (FIPS 203 §7.2), draws an ephemeral ECDH key
        /// and encapsulates. Returns `(server share, shared secret)`: the
        /// point followed by the ciphertext, and the ECDH secret followed
        /// by the ML-KEM one (RFC 10024 §4.2, §4.3).
        pub(crate) fn $server<R: RngCore>(
            rng: &mut R,
            client_share: &[u8],
        ) -> Result<(Vec<u8>, Secret), Error> {
            let plen = point_len($curve);
            if client_share.len() != plen + $ek::BYTES {
                return Err(Error::IllegalParameter);
            }
            let (point, ek_bytes) = client_share.split_at(plen);
            // Both halves are validated before any secret is drawn or any
            // operation runs on them. An encapsulation key with
            // off-modulus coefficients would otherwise let the client
            // probe the encapsulator's noise.
            let peer = peer_point($curve, point)?;
            let mut ek = [0u8; $ek::BYTES];
            ek.copy_from_slice(ek_bytes);
            let ek = $ek::from_bytes_validated(ek).map_err(|_| Error::IllegalParameter)?;

            let sk = BoxedEcdhPrivateKey::generate($curve, rng);
            let ecdh_ss = ecdh(&sk, &peer)?;
            let (ct, ml_ss) = ek.encapsulate(rng);

            let mut share = sk.public_key().to_sec1();
            share.extend_from_slice(&ct.to_bytes());
            Ok((share, combine(ecdh_ss, ml_ss)))
        }
    };
}

ecdh_mlkem_hybrid!(
    CurveId::P256,
    MlKem768DecapsKey,
    MlKem768EncapsKey,
    MlKem768Ciphertext,
    p256_mlkem768_client_share,
    p256_mlkem768_client,
    p256_mlkem768_server,
    "SecP256r1MLKEM768"
);

ecdh_mlkem_hybrid!(
    CurveId::P384,
    MlKem1024DecapsKey,
    MlKem1024EncapsKey,
    MlKem1024Ciphertext,
    p384_mlkem1024_client_share,
    p384_mlkem1024_client,
    p384_mlkem1024_server,
    "SecP384r1MLKEM1024"
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    fn rng(tag: &[u8]) -> HmacDrbg<Sha256> {
        HmacDrbg::<Sha256>::new(tag, b"kex-tests", &[])
    }

    fn assert_illegal<T>(r: Result<T, Error>) {
        match r {
            Err(Error::IllegalParameter) => {}
            Err(e) => panic!("expected IllegalParameter, got {e:?}"),
            Ok(_) => panic!("expected IllegalParameter, got Ok"),
        }
    }

    /// RFC 10024 §4: share sizes, the ECDH-first layout and the
    /// ECDH-first shared secret of SecP256r1MLKEM768, checked against the
    /// component primitives run independently.
    #[test]
    fn p256_mlkem768_layout_and_secret() {
        let mut r = rng(b"p256-768");
        let ec = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut r);
        let (dk, ek) = MlKem768DecapsKey::generate(&mut r);

        let cshare = p256_mlkem768_client_share(&ec, &dk);
        assert_eq!(cshare.len(), 1249);
        assert_eq!(&cshare[..65], ec.public_key().to_sec1().as_slice());
        assert_eq!(&cshare[65..], ek.to_bytes().as_slice());

        let (sshare, s_secret) = p256_mlkem768_server(&mut r, &cshare).unwrap();
        assert_eq!(sshare.len(), 1153);
        assert_eq!(sshare[0], 0x04);
        let c_secret = p256_mlkem768_client(&ec, &dk, &sshare).unwrap();
        assert_eq!(c_secret.as_slice(), s_secret.as_slice());
        assert_eq!(c_secret.as_slice().len(), 64);

        // Independent recomputation: x(d·Q_server) ‖ Decaps(ct).
        let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P256, &sshare[..65]).unwrap();
        let x = ec.diffie_hellman(&peer).unwrap();
        let mut ct = [0u8; 1088];
        ct.copy_from_slice(&sshare[65..]);
        let k = dk.decapsulate(&MlKem768Ciphertext::from_bytes(ct));
        assert_eq!(&c_secret.as_slice()[..32], x.as_slice());
        assert_eq!(&c_secret.as_slice()[32..], &k[..]);
    }

    /// Same for SecP384r1MLKEM1024: 1665-byte shares both ways, 80-byte
    /// secret (48 ECDH ‖ 32 ML-KEM).
    #[test]
    fn p384_mlkem1024_layout_and_secret() {
        let mut r = rng(b"p384-1024");
        let ec = BoxedEcdhPrivateKey::generate(CurveId::P384, &mut r);
        let (dk, ek) = MlKem1024DecapsKey::generate(&mut r);

        let cshare = p384_mlkem1024_client_share(&ec, &dk);
        assert_eq!(cshare.len(), 1665);
        assert_eq!(&cshare[..97], ec.public_key().to_sec1().as_slice());
        assert_eq!(&cshare[97..], ek.to_bytes().as_slice());

        let (sshare, s_secret) = p384_mlkem1024_server(&mut r, &cshare).unwrap();
        assert_eq!(sshare.len(), 1665);
        let c_secret = p384_mlkem1024_client(&ec, &dk, &sshare).unwrap();
        assert_eq!(c_secret.as_slice(), s_secret.as_slice());
        assert_eq!(c_secret.as_slice().len(), 80);

        let peer = BoxedEcdsaPublicKey::from_sec1(CurveId::P384, &sshare[..97]).unwrap();
        let x = ec.diffie_hellman(&peer).unwrap();
        let mut ct = [0u8; 1568];
        ct.copy_from_slice(&sshare[97..]);
        let k = dk.decapsulate(&MlKem1024Ciphertext::from_bytes(ct));
        assert_eq!(&c_secret.as_slice()[..48], x.as_slice());
        assert_eq!(&c_secret.as_slice()[48..], &k[..]);
    }

    #[test]
    fn p521_ecdhe_agrees() {
        let mut r = rng(b"p521");
        let ec = BoxedEcdhPrivateKey::generate(CurveId::P521, &mut r);
        let cshare = ec.public_key().to_sec1();
        assert_eq!(cshare.len(), 133);
        let (sshare, s_secret) = ecdhe_server(CurveId::P521, &mut r, &cshare).unwrap();
        assert_eq!(sshare.len(), 133);
        let c_secret = ecdhe_client(&ec, &sshare).unwrap();
        assert_eq!(c_secret.as_slice(), s_secret.as_slice());
        // RFC 8446 §7.4.2: the x-coordinate at the full field width.
        assert_eq!(c_secret.as_slice().len(), 66);
    }

    /// Hostile EC shares: wrong length, all-zero, the compressed form, a
    /// coordinate that is not a field element, a point off the curve.
    #[test]
    fn rejects_bad_points() {
        let mut r = rng(b"bad-points");
        for curve in [CurveId::P256, CurveId::P384, CurveId::P521] {
            let ec = BoxedEcdhPrivateKey::generate(curve, &mut r);
            let good = ec.public_key().to_sec1();
            let flen = curve.field_len();

            let mut cases: Vec<Vec<u8>> = Vec::new();
            cases.push(Vec::new());
            cases.push(good[..good.len() - 1].to_vec());
            let mut long = good.clone();
            long.push(0);
            cases.push(long);
            // All-zero: no SEC1 tag at all (the identity's one-byte
            // encoding padded out, as a confused peer might send).
            cases.push(alloc::vec![0u8; good.len()]);
            // (0, 0) under the right tag is not on the curve (b != 0).
            let mut zero_xy = alloc::vec![0u8; good.len()];
            zero_xy[0] = 0x04;
            cases.push(zero_xy);
            // Compressed form of a valid point.
            let mut compressed = good[..1 + flen].to_vec();
            compressed[0] = 0x02 | (good[good.len() - 1] & 1);
            cases.push(compressed);
            // Compressed tag at the uncompressed length.
            let mut tagged = good.clone();
            tagged[0] = 0x02;
            cases.push(tagged);
            // x = 2^(8·flen) − 1 ≥ p.
            let mut big_x = good.clone();
            big_x[1..1 + flen].fill(0xff);
            cases.push(big_x);
            // Off the curve: y + 1 (mod 256 in the last byte).
            let mut off = good.clone();
            let last = off.len() - 1;
            off[last] ^= 1;
            cases.push(off);

            for case in &cases {
                assert_illegal(ecdhe_client(&ec, case));
                assert_illegal(ecdhe_server(curve, &mut r, case));
            }
        }
    }

    /// Hostile hybrid shares on the server: each half is validated, and a
    /// bad half fails the whole share whatever the other one holds.
    #[test]
    fn hybrid_server_rejects_bad_shares() {
        let mut r = rng(b"hybrid-server");
        let ec = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut r);
        let (dk, _) = MlKem768DecapsKey::generate(&mut r);
        let good = p256_mlkem768_client_share(&ec, &dk);
        assert!(p256_mlkem768_server(&mut r, &good).is_ok());

        // Lengths: empty, one short, one long, the X25519MLKEM768 size,
        // and the other hybrid's size.
        for len in [0usize, 1248, 1250, 1216, 1665] {
            let mut s = good.clone();
            s.resize(len, 0);
            assert_illegal(p256_mlkem768_server(&mut r, &s));
        }
        assert_illegal(p256_mlkem768_server(&mut r, &alloc::vec![0u8; 1249]));

        // The X25519MLKEM768 order (ML-KEM first) at this group's length.
        let mut swapped = good[65..].to_vec();
        swapped.extend_from_slice(&good[..65]);
        assert_illegal(p256_mlkem768_server(&mut r, &swapped));

        // Off-curve point, valid encapsulation key.
        let mut bad_point = good.clone();
        bad_point[64] ^= 1;
        assert_illegal(p256_mlkem768_server(&mut r, &bad_point));

        // Valid point, encapsulation key with a coefficient ≥ q (FIPS 203
        // §7.2): the first 12-bit coefficient set to 0xfff.
        let mut bad_ek = good.clone();
        bad_ek[65] = 0xff;
        bad_ek[66] |= 0x0f;
        assert_illegal(p256_mlkem768_server(&mut r, &bad_ek));

        let ec384 = BoxedEcdhPrivateKey::generate(CurveId::P384, &mut r);
        let (dk1024, _) = MlKem1024DecapsKey::generate(&mut r);
        let good = p384_mlkem1024_client_share(&ec384, &dk1024);
        assert!(p384_mlkem1024_server(&mut r, &good).is_ok());
        for len in [0usize, 1664, 1666, 1249] {
            let mut s = good.clone();
            s.resize(len, 0);
            assert_illegal(p384_mlkem1024_server(&mut r, &s));
        }
        let mut bad_point = good.clone();
        bad_point[96] ^= 1;
        assert_illegal(p384_mlkem1024_server(&mut r, &bad_point));
        let mut bad_ek = good.clone();
        bad_ek[97] = 0xff;
        bad_ek[98] |= 0x0f;
        assert_illegal(p384_mlkem1024_server(&mut r, &bad_ek));
    }

    /// Hostile hybrid shares on the client. A tampered ciphertext of the
    /// right length is *not* an error: ML-KEM rejects implicitly, so the
    /// two sides just end up with different secrets.
    #[test]
    fn hybrid_client_rejects_bad_shares() {
        let mut r = rng(b"hybrid-client");
        let ec = BoxedEcdhPrivateKey::generate(CurveId::P256, &mut r);
        let (dk, _) = MlKem768DecapsKey::generate(&mut r);
        let cshare = p256_mlkem768_client_share(&ec, &dk);
        let (good, s_secret) = p256_mlkem768_server(&mut r, &cshare).unwrap();

        for len in [0usize, 1152, 1154, 1120] {
            let mut s = good.clone();
            s.resize(len, 0);
            assert_illegal(p256_mlkem768_client(&ec, &dk, &s));
        }
        assert_illegal(p256_mlkem768_client(&ec, &dk, &alloc::vec![0u8; 1153]));
        let mut bad_point = good.clone();
        bad_point[64] ^= 1;
        assert_illegal(p256_mlkem768_client(&ec, &dk, &bad_point));

        let mut bad_ct = good.clone();
        bad_ct[100] ^= 1;
        let c_secret = p256_mlkem768_client(&ec, &dk, &bad_ct).unwrap();
        assert_eq!(&c_secret.as_slice()[..32], &s_secret.as_slice()[..32]);
        assert_ne!(&c_secret.as_slice()[32..], &s_secret.as_slice()[32..]);

        // A key on the wrong curve is a caller bug, not a panic.
        let ec384 = BoxedEcdhPrivateKey::generate(CurveId::P384, &mut r);
        assert_illegal(p256_mlkem768_client(&ec384, &dk, &good));
    }
}
