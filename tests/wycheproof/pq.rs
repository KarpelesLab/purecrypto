//! Post-quantum: ML-KEM (FIPS 203) and ML-DSA (FIPS 204).
//!
//! Neither family has `acceptable` cases upstream; every case is `valid` or
//! `invalid`. The only skips are the ML-DSA `Internal` cases, which carry a
//! pre-hashed `mu` instead of a message (external-mu signing) — the crate has
//! no entry point that takes `mu` directly.

#[cfg(feature = "mldsa")]
use crate::common::from_hex;
use crate::common::{Fields, Outcome, check, check_eq};

/// Optional hex field, empty when absent (the `ctx` string).
#[cfg(feature = "mldsa")]
fn opt_hex(f: &Fields, key: &str) -> Vec<u8> {
    f.get(key).map(crate::common::from_hex).unwrap_or_default()
}

// ---------------------------------------------------------------- ML-KEM

/// One ML-KEM parameter set, abstracted over the three concrete key types.
#[cfg(feature = "mlkem")]
trait Kem {
    const PS: &'static str;
    type Dk;
    type Ek;
    type Ct;
    fn from_seeds(d: &[u8; 32], z: &[u8; 32]) -> (Self::Dk, Self::Ek);
    /// Decodes with the FIPS 203 §7.2 modulus check; `None` on any rejection.
    fn ek(b: &[u8]) -> Option<Self::Ek>;
    /// Decodes with the FIPS 203 §7.3 hash check; `None` on any rejection.
    fn dk(b: &[u8]) -> Option<Self::Dk>;
    fn ct(b: &[u8]) -> Option<Self::Ct>;
    fn ek_of(dk: &Self::Dk) -> Self::Ek;
    fn ek_bytes(ek: &Self::Ek) -> Vec<u8>;
    fn dk_bytes(dk: &Self::Dk) -> Vec<u8>;
    fn ct_bytes(ct: &Self::Ct) -> Vec<u8>;
    fn encaps(ek: &Self::Ek, m: &[u8; 32]) -> (Self::Ct, [u8; 32]);
    fn decaps(dk: &Self::Dk, ct: &Self::Ct) -> [u8; 32];
}

#[cfg(feature = "mlkem")]
macro_rules! kem_set {
    ($set:ident, $ps:literal, $dk:ident, $ek:ident, $ct:ident) => {
        struct $set;
        impl Kem for $set {
            const PS: &'static str = $ps;
            type Dk = purecrypto::mlkem::$dk;
            type Ek = purecrypto::mlkem::$ek;
            type Ct = purecrypto::mlkem::$ct;
            fn from_seeds(d: &[u8; 32], z: &[u8; 32]) -> (Self::Dk, Self::Ek) {
                Self::Dk::from_seeds(d, z)
            }
            fn ek(b: &[u8]) -> Option<Self::Ek> {
                Self::Ek::from_bytes_validated(b.try_into().ok()?).ok()
            }
            fn dk(b: &[u8]) -> Option<Self::Dk> {
                Self::Dk::from_bytes_validated(b.try_into().ok()?).ok()
            }
            fn ct(b: &[u8]) -> Option<Self::Ct> {
                Some(Self::Ct::from_bytes(b.try_into().ok()?))
            }
            fn ek_of(dk: &Self::Dk) -> Self::Ek {
                dk.encapsulation_key()
            }
            fn ek_bytes(ek: &Self::Ek) -> Vec<u8> {
                ek.to_bytes().to_vec()
            }
            fn dk_bytes(dk: &Self::Dk) -> Vec<u8> {
                dk.to_bytes().to_vec()
            }
            fn ct_bytes(ct: &Self::Ct) -> Vec<u8> {
                ct.to_bytes().to_vec()
            }
            fn encaps(ek: &Self::Ek, m: &[u8; 32]) -> (Self::Ct, [u8; 32]) {
                ek.encapsulate_deterministic(m)
            }
            fn decaps(dk: &Self::Dk, ct: &Self::Ct) -> [u8; 32] {
                dk.decapsulate(ct)
            }
        }
    };
}

#[cfg(feature = "mlkem")]
kem_set!(
    Kem512,
    "ML-KEM-512",
    MlKem512DecapsKey,
    MlKem512EncapsKey,
    MlKem512Ciphertext
);
#[cfg(feature = "mlkem")]
kem_set!(
    Kem768,
    "ML-KEM-768",
    MlKem768DecapsKey,
    MlKem768EncapsKey,
    MlKem768Ciphertext
);
#[cfg(feature = "mlkem")]
kem_set!(
    Kem1024,
    "ML-KEM-1024",
    MlKem1024DecapsKey,
    MlKem1024EncapsKey,
    MlKem1024Ciphertext
);

/// Splits the 64-byte `d‖z` keygen seed; `None` on a wrong length.
#[cfg(feature = "mlkem")]
fn kem_keypair<S: Kem>(case: &Fields) -> Option<(S::Dk, S::Ek)> {
    let seed: [u8; 64] = case.hex_array("seed")?;
    let (d, z) = seed.split_at(32);
    Some(S::from_seeds(d.try_into().unwrap(), z.try_into().unwrap()))
}

/// `mlkem_<ps>`: keygen from `seed`, compare `ek` when given, then
/// decapsulate `c` and compare the shared secret `K`. The
/// `MalleableCiphertext` cases give the implicit-rejection secret as `K`, so
/// this also pins the FIPS 203 rejection path (`J(z‖c)`).
#[cfg(feature = "mlkem")]
fn kem_base<S: Kem>(name: &str) {
    check(name, |group, case| {
        assert_eq!(group.str("parameterSet"), S::PS);
        let Some((dk, ek)) = kem_keypair::<S>(case) else {
            return Outcome::Rejected;
        };
        if case.has("ek") && S::ek_bytes(&ek) != case.hex("ek") {
            return Outcome::Wrong("encapsulation key");
        }
        let Some(ct) = S::ct(&case.hex("c")) else {
            return Outcome::Rejected;
        };
        check_eq(&S::decaps(&dk, &ct), &case.hex("K"), "shared secret")
    });
}

/// `mlkem_<ps>_encaps`: encapsulate with explicit `m` to `ek`. The key goes
/// through the §7.2 check, so `ModulusOverflow` ("Public key not reduced")
/// and wrong-length keys are rejected before any arithmetic.
#[cfg(feature = "mlkem")]
fn kem_encaps<S: Kem>(name: &str) {
    check(name, |group, case| {
        assert_eq!(group.str("parameterSet"), S::PS);
        let Some(ek) = S::ek(&case.hex("ek")) else {
            return Outcome::Rejected;
        };
        let Some(m) = case.hex_array::<32>("m") else {
            return Outcome::Rejected;
        };
        let (ct, ss) = S::encaps(&ek, &m);
        if S::ct_bytes(&ct) != case.hex("c") {
            return Outcome::Wrong("ciphertext");
        }
        check_eq(&ss, &case.hex("K"), "shared secret")
    });
}

/// `mlkem_<ps>_keygen_seed`: keygen from `seed`, compare both `ek` and `dk`.
#[cfg(feature = "mlkem")]
fn kem_keygen<S: Kem>(name: &str) {
    check(name, |group, case| {
        assert_eq!(group.str("parameterSet"), S::PS);
        let Some((dk, ek)) = kem_keypair::<S>(case) else {
            return Outcome::Rejected;
        };
        if S::ek_bytes(&ek) != case.hex("ek") {
            return Outcome::Wrong("encapsulation key");
        }
        check_eq(&S::dk_bytes(&dk), &case.hex("dk"), "decapsulation key")
    });
}

/// `mlkem_<ps>_semi_expanded_decaps`: decapsulate with an imported `dk`.
/// Wrong lengths and a hash mismatch (§7.3, which also catches a corrupted
/// embedded `ek`) must be rejected; the embedded `ek` must match the file's.
#[cfg(feature = "mlkem")]
fn kem_decaps<S: Kem>(name: &str) {
    check(name, |group, case| {
        assert_eq!(group.str("parameterSet"), S::PS);
        let Some(dk) = S::dk(&case.hex("dk")) else {
            return Outcome::Rejected;
        };
        let Some(ct) = S::ct(&case.hex("c")) else {
            return Outcome::Rejected;
        };
        if S::ek_bytes(&S::ek_of(&dk)) != case.hex("ek") {
            return Outcome::Wrong("embedded encapsulation key");
        }
        check_eq(&S::decaps(&dk, &ct), &case.hex("K"), "shared secret")
    });
}

#[cfg(feature = "mlkem")]
macro_rules! kem_tests {
    ($set:ident: $base:ident, $encaps:ident, $keygen:ident, $decaps:ident) => {
        #[test]
        fn $base() {
            kem_base::<$set>(stringify!($base));
        }
        #[test]
        fn $encaps() {
            kem_encaps::<$set>(stringify!($encaps));
        }
        #[test]
        fn $keygen() {
            kem_keygen::<$set>(stringify!($keygen));
        }
        #[test]
        fn $decaps() {
            kem_decaps::<$set>(stringify!($decaps));
        }
    };
}

#[cfg(feature = "mlkem")]
kem_tests!(Kem512: mlkem_512, mlkem_512_encaps, mlkem_512_keygen_seed, mlkem_512_semi_expanded_decaps);
#[cfg(feature = "mlkem")]
kem_tests!(Kem768: mlkem_768, mlkem_768_encaps, mlkem_768_keygen_seed, mlkem_768_semi_expanded_decaps);
#[cfg(feature = "mlkem")]
kem_tests!(Kem1024: mlkem_1024, mlkem_1024_encaps, mlkem_1024_keygen_seed, mlkem_1024_semi_expanded_decaps);

// ---------------------------------------------------------------- ML-DSA

/// Feeds a fixed byte string to the hedged `sign`, so a vector's `rnd`
/// becomes the 32-byte hedge. Panics if the signer asks for more than given.
#[cfg(feature = "mldsa")]
struct FixedRng<'a>(&'a [u8]);

#[cfg(feature = "mldsa")]
impl purecrypto::rng::RngCore for FixedRng<'_> {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let (head, tail) = self.0.split_at(dest.len());
        dest.copy_from_slice(head);
        self.0 = tail;
    }
}

/// One ML-DSA parameter set.
#[cfg(feature = "mldsa")]
trait Dsa {
    type Sk;
    type Pk;
    fn from_seed(seed: &[u8; 32]) -> (Self::Sk, Self::Pk);
    /// Decodes an expanded private key (length and `s1`/`s2` range checks).
    fn sk(b: &[u8]) -> Option<Self::Sk>;
    fn pk(b: &[u8]) -> Option<Self::Pk>;
    fn pk_of(sk: &Self::Sk) -> Self::Pk;
    fn pk_bytes(pk: &Self::Pk) -> Vec<u8>;
    /// Deterministic when `rnd` is `None`, hedged with exactly `rnd` otherwise.
    /// `None` when the crate refuses (context longer than 255 bytes).
    fn sign(sk: &Self::Sk, rnd: Option<&[u8]>, msg: &[u8], ctx: &[u8]) -> Option<Vec<u8>>;
    fn verify(pk: &Self::Pk, sig: &[u8], msg: &[u8], ctx: &[u8]) -> bool;
}

#[cfg(feature = "mldsa")]
macro_rules! dsa_set {
    ($set:ident, $sk:ident, $pk:ident) => {
        struct $set;
        impl Dsa for $set {
            type Sk = purecrypto::mldsa::$sk;
            type Pk = purecrypto::mldsa::$pk;
            fn from_seed(seed: &[u8; 32]) -> (Self::Sk, Self::Pk) {
                Self::Sk::from_seed(seed)
            }
            fn sk(b: &[u8]) -> Option<Self::Sk> {
                Self::Sk::from_bytes(b).ok()
            }
            fn pk(b: &[u8]) -> Option<Self::Pk> {
                Self::Pk::from_bytes(b).ok()
            }
            fn pk_of(sk: &Self::Sk) -> Self::Pk {
                sk.public_key()
            }
            fn pk_bytes(pk: &Self::Pk) -> Vec<u8> {
                pk.to_bytes().to_vec()
            }
            fn sign(sk: &Self::Sk, rnd: Option<&[u8]>, msg: &[u8], ctx: &[u8]) -> Option<Vec<u8>> {
                match rnd {
                    None => sk.sign_deterministic(msg, ctx).ok().map(|s| s.to_vec()),
                    Some(r) => sk.sign(&mut FixedRng(r), msg, ctx).ok().map(|s| s.to_vec()),
                }
            }
            fn verify(pk: &Self::Pk, sig: &[u8], msg: &[u8], ctx: &[u8]) -> bool {
                pk.verify(sig, msg, ctx)
            }
        }
    };
}

#[cfg(feature = "mldsa")]
dsa_set!(Dsa44, MlDsa44PrivateKey, MlDsa44PublicKey);
#[cfg(feature = "mldsa")]
dsa_set!(Dsa65, MlDsa65PrivateKey, MlDsa65PublicKey);
#[cfg(feature = "mldsa")]
dsa_set!(Dsa87, MlDsa87PrivateKey, MlDsa87PublicKey);

/// `mldsa_<ps>_verify`: the group's `publicKey` (possibly of the wrong
/// length, which must fail decoding) verifies each `sig` over `msg` with the
/// optional `ctx`. `InvalidContext` cases carry a 256-byte context that the
/// crate refuses outright, before looking at the signature.
#[cfg(feature = "mldsa")]
fn dsa_verify<S: Dsa>(name: &str) {
    check(name, |group, case| {
        let Some(pk) = S::pk(&group.hex("publicKey")) else {
            return Outcome::Rejected;
        };
        let ctx = opt_hex(case, "ctx");
        if S::verify(&pk, &case.hex("sig"), &case.hex("msg"), &ctx) {
            Outcome::Accepted
        } else {
            Outcome::Rejected
        }
    });
}

/// Signs one case with an already-decoded key whose public half must equal
/// the group's `publicKey`.
#[cfg(feature = "mldsa")]
fn dsa_sign_case<S: Dsa>(sk: &S::Sk, group: &Fields, case: &Fields) -> Outcome {
    if !case.has("msg") {
        // `Internal` cases give only `mu = H(tr ‖ M')` and expect
        // ML-DSA.Sign_internal on it (external-mu signing). The crate only
        // signs a message, so `mu` cannot be fed in.
        return Outcome::Skipped;
    }
    if S::pk_bytes(&S::pk_of(sk)) != group.hex("publicKey") {
        return Outcome::Wrong("public key");
    }
    let ctx = opt_hex(case, "ctx");
    let rnd = case.get("rnd").map(from_hex);
    match S::sign(sk, rnd.as_deref(), &case.hex("msg"), &ctx) {
        None => Outcome::Rejected,
        Some(sig) => check_eq(&sig, &case.hex("sig"), "signature"),
    }
}

/// `mldsa_<ps>_sign_noseed`: the group's expanded `privateKey` (some are
/// mis-sized or have out-of-range `s1`/`s2`, which must fail decoding) signs
/// `msg`/`ctx`; the signature must match byte for byte.
#[cfg(feature = "mldsa")]
fn dsa_sign_noseed<S: Dsa>(name: &str) {
    check(name, |group, case| {
        let Some(sk) = S::sk(&group.hex("privateKey")) else {
            return Outcome::Rejected;
        };
        dsa_sign_case::<S>(&sk, group, case)
    });
}

/// `mldsa_<ps>_sign_seed`: the group's 32-byte `privateSeed` (some are
/// mis-sized) expands to a key pair whose public half must match, then
/// signs as above.
#[cfg(feature = "mldsa")]
fn dsa_sign_seed<S: Dsa>(name: &str) {
    check(name, |group, case| {
        let Some(seed) = group.hex_array::<32>("privateSeed") else {
            return Outcome::Rejected;
        };
        let (sk, _) = S::from_seed(&seed);
        dsa_sign_case::<S>(&sk, group, case)
    });
}

#[cfg(feature = "mldsa")]
macro_rules! dsa_tests {
    ($set:ident: $verify:ident, $noseed:ident, $seed:ident) => {
        #[test]
        fn $verify() {
            dsa_verify::<$set>(stringify!($verify));
        }
        #[test]
        fn $noseed() {
            dsa_sign_noseed::<$set>(stringify!($noseed));
        }
        #[test]
        fn $seed() {
            dsa_sign_seed::<$set>(stringify!($seed));
        }
    };
}

#[cfg(feature = "mldsa")]
dsa_tests!(Dsa44: mldsa_44_verify, mldsa_44_sign_noseed, mldsa_44_sign_seed);
#[cfg(feature = "mldsa")]
dsa_tests!(Dsa65: mldsa_65_verify, mldsa_65_sign_noseed, mldsa_65_sign_seed);
#[cfg(feature = "mldsa")]
dsa_tests!(Dsa87: mldsa_87_verify, mldsa_87_sign_noseed, mldsa_87_sign_seed);
