//! Unified [`key`](crate::key) facade impls for the binary-curve keys:
//! ECDSA (`hash`, `prehashed` and `sig_encoding` are honoured) and ECDH.
//!
//! Every binary curve reports [`Algorithm::EcBinary`]; key agreement also
//! checks that both keys are on the same curve.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::{BinaryPrivateKey, BinaryPublicKey, BinarySignature};
use crate::key::dispatch_key_hash as dispatch_hash;
use crate::key::{
    Algorithm, Error, PrivateKey, PublicKey, Secret, SigEncoding, SignParams, downcast_peer,
};
use crate::rng::CryptoRngCore;

impl PrivateKey for BinaryPrivateKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EcBinary
    }
    fn public_key(&self) -> Result<Box<dyn PublicKey>, Error> {
        Ok(Box::new(self.public_key()))
    }
    fn sign(
        &self,
        msg: &[u8],
        params: &SignParams<'_>,
        _rng: &mut dyn CryptoRngCore,
    ) -> Result<Vec<u8>, Error> {
        let mut p = params.reader();
        let hash = p.hash();
        let prehashed = p.prehashed();
        let enc = p.sig_encoding();
        p.finish()?;
        let sig = dispatch_hash!(hash, |D| {
            if prehashed {
                self.sign_prehash::<D>(msg)
            } else {
                self.sign::<D>(msg)
            }
        })
        .map_err(|_| Error::Signature)?;
        Ok(match enc {
            SigEncoding::Raw => sig.to_bytes(),
            SigEncoding::Der => sig.to_der(),
        })
    }
    fn agree(&self, peer: &dyn PublicKey) -> Result<Secret, Error> {
        let peer = downcast_peer::<BinaryPublicKey>(peer, Algorithm::EcBinary)?;
        let shared = self.diffie_hellman(peer).map_err(|_| Error::KeyAgreement)?;
        Ok(Secret::from_bytes(shared))
    }
}

impl PublicKey for BinaryPublicKey {
    fn algorithm(&self) -> Algorithm {
        Algorithm::EcBinary
    }
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }
    fn verify(&self, msg: &[u8], sig: &[u8], params: &SignParams<'_>) -> Result<(), Error> {
        let mut p = params.reader();
        let hash = p.hash();
        let prehashed = p.prehashed();
        let enc = p.sig_encoding();
        p.finish()?;
        let curve = self.curve();
        let signature = match enc {
            SigEncoding::Raw => BinarySignature::from_bytes(curve, sig),
            SigEncoding::Der => BinarySignature::from_der(curve, sig),
        }
        .map_err(|_| Error::Signature)?;
        if prehashed {
            self.verify_prehash(msg, &signature)
        } else {
            dispatch_hash!(hash, |D| { self.verify::<D>(msg, &signature) })
        }
        .map_err(|_| Error::Signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ec::binary::BinaryCurveId;
    use crate::hash::Sha256;
    use crate::rng::HmacDrbg;

    #[test]
    fn facade_signs_verifies_and_agrees() {
        let mut rng = HmacDrbg::<Sha256>::new(b"binary-facade", b"n", &[]);
        let a = BinaryPrivateKey::generate(BinaryCurveId::Sect233k1, &mut rng);
        let b = BinaryPrivateKey::generate(BinaryCurveId::Sect233k1, &mut rng);
        let c = BinaryPrivateKey::generate(BinaryCurveId::Wtls10, &mut rng);
        let a_dyn: &dyn PrivateKey = &a;
        assert_eq!(a_dyn.algorithm(), Algorithm::EcBinary);
        let pa = a_dyn.public_key().unwrap();
        for enc in [SigEncoding::Der, SigEncoding::Raw] {
            let params = SignParams::new().sig_encoding(enc);
            let sig = a_dyn.sign(b"msg", &params, &mut rng).unwrap();
            pa.verify(b"msg", &sig, &params).unwrap();
            assert!(pa.verify(b"msh", &sig, &params).is_err());
        }
        let z1 = a_dyn.agree(&b.public_key()).unwrap();
        let z2 = (&b as &dyn PrivateKey).agree(&a.public_key()).unwrap();
        assert_eq!(z1.as_bytes(), z2.as_bytes());
        // Same parameters, other OID: not the same curve.
        assert!(a_dyn.agree(&c.public_key()).is_err());
    }
}
