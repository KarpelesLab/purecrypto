//! C2SP chunked encryption (Cobblestone-128 / Cobblestone-256), per
//! `doc/c2sp_chunked_encryption.md` of the Wycheproof repository.
//!
//! Each case is run through every interface the module offers:
//!
//! * one-shot [`decrypt`]: `valid` must yield `msgLength` bytes hashing to
//!   `msgSha512`, `invalid` must fail (and `InvalidKeySize` must fail on the
//!   key length specifically);
//! * streaming [`Decryptor`], fed in irregular pieces: it must release at
//!   most the `PartialPlaintext` prefix, then fail, then keep failing;
//! * raw mode ([`RawCipher`] with `aeadKey` / `baseNonce`) for every case
//!   without `HeaderFailure`, one-shot and streaming;
//! * encryption of the recovered message of every `valid` case: raw-mode
//!   re-encryption and salt-injected re-encryption (streaming, mixed piece
//!   sizes) must reproduce the vector byte for byte, and a random-salt
//!   round trip must decrypt.
//!
//! The `ct` field is zlib-compressed; it is inflated with `compcol` (the
//! crate's own optional zlib dependency, pulled in as a dev-dependency).

use crate::common::{Fields, Outcome, check};
use purecrypto::chunked::{
    Cobblestone128, Cobblestone256, Decryptor, Encryptor, Error, HEADER_LEN, Instantiation,
    RawCipher, SALT_LEN, decrypt, encrypt,
};
use purecrypto::hash::Sha256;
use purecrypto::hash::sha512;
use purecrypto::rng::HmacDrbg;

fn inflate(zlib: &[u8]) -> Vec<u8> {
    compcol::vec::decompress_to_vec::<compcol::zlib::Zlib>(zlib).expect("ct is a zlib stream")
}

/// Piece sizes for the streaming interfaces: around every boundary that
/// matters (tag, chunk, encrypted chunk), plus a large one so multi-chunk
/// pushes take the copy-free path.
const PIECES: [usize; 8] = [1, 15, 16, 16383, 16384, 16400, 16401, 100_000];

/// Feeds `body` to `dec` in [`PIECES`]-sized pieces, then finishes. Returns
/// the plaintext released and the final outcome, and checks that a failure
/// is sticky (a further push and finish return the same error and release
/// nothing).
fn stream<I: Instantiation>(mut dec: Decryptor<I>, body: &[u8]) -> (Vec<u8>, Result<(), Error>) {
    let mut out = Vec::new();
    let mut rest = body;
    let mut i = 0;
    let mut res = Ok(());
    while !rest.is_empty() && res.is_ok() {
        let n = PIECES[i % PIECES.len()].min(rest.len());
        i += 1;
        let (piece, tail) = rest.split_at(n);
        rest = tail;
        res = dec.push(piece, &mut out);
    }
    if res.is_ok() {
        res = dec.finish(&mut out);
    }
    if let Err(e) = res {
        let len = out.len();
        assert_eq!(
            dec.push(b"more", &mut out),
            Err(e),
            "error is sticky on push"
        );
        assert_eq!(dec.finish(&mut out), Err(e), "error is sticky on finish");
        assert_eq!(dec.error(), Some(e));
        assert_eq!(out.len(), len, "nothing released after a failure");
    } else {
        assert!(dec.is_finished());
    }
    (out, res)
}

/// The message described by `msgLength` / `msgSha512` (absent on invalid
/// cases with no valid prefix).
fn expected_msg(case: &Fields) -> Option<(usize, Vec<u8>)> {
    case.get("msgLength")
        .map(|_| (case.int("msgLength") as usize, case.hex("msgSha512")))
}

/// Checks that `out` is the streaming output the guide allows: for a valid
/// case, or an invalid one with `PartialPlaintext`, at most `msgLength` bytes
/// and, if the whole prefix came out, the right hash; otherwise nothing.
fn check_prefix(case: &Fields, out: &[u8], full: bool) -> Result<(), &'static str> {
    match expected_msg(case) {
        Some((len, sha)) if full || case.has_flag("PartialPlaintext") => {
            if out.len() > len {
                return Err("released bytes beyond the valid prefix");
            }
            if full && out.len() != len {
                return Err("plaintext length");
            }
            if out.len() == len && sha512(out)[..] != sha[..] {
                return Err("plaintext SHA-512");
            }
            Ok(())
        }
        _ if out.is_empty() => Ok(()),
        _ => Err("released plaintext for a case with no valid prefix"),
    }
}

fn case<I: Instantiation>(case: &Fields) -> Outcome {
    let key = case.hex("key");
    let ctx = case.hex("ctx");
    let ct = inflate(&case.hex("ct"));
    let invalid = case.expected() != crate::common::Expected::Valid;
    let header_failure = case.has_flag("HeaderFailure");

    // One-shot.
    let one = decrypt::<I>(&key, &ctx, &ct);
    if case.has_flag("InvalidKeySize") && one != Err(Error::InvalidKeyLength) {
        return Outcome::Wrong("a wrong-size key must be reported as such");
    }
    let msg = match one {
        Ok(msg) => {
            if invalid {
                return Outcome::Wrong("one-shot decrypt accepted an invalid ciphertext");
            }
            if let Err(what) = check_prefix(case, &msg, true) {
                return Outcome::Wrong(what);
            }
            Some(msg)
        }
        Err(_) if invalid => None,
        Err(_) => return Outcome::Wrong("one-shot decrypt rejected a valid ciphertext"),
    };

    // Streaming, header mode. A ciphertext too short for a header cannot
    // even construct the decryptor, which is the rejection.
    let header: Option<&[u8; HEADER_LEN]> = ct.get(..HEADER_LEN).map(|h| h.try_into().unwrap());
    let dec = header.map(|h| Decryptor::<I>::new(&key, &ctx, h));
    match dec {
        None | Some(Err(_)) => {
            if !invalid {
                return Outcome::Wrong("streaming decryptor refused a valid header");
            }
            if !header_failure {
                return Outcome::Wrong(
                    "streaming decryptor refused a header the vector calls valid",
                );
            }
        }
        Some(Ok(dec)) => {
            if header_failure {
                return Outcome::Wrong("streaming decryptor accepted a bad header");
            }
            let (out, res) = stream(dec, &ct[HEADER_LEN..]);
            if res.is_ok() != !invalid {
                return Outcome::Wrong("streaming outcome differs from one-shot");
            }
            if let Err(what) = check_prefix(case, &out, !invalid) {
                return Outcome::Wrong(what);
            }
        }
    }

    // Raw mode, one-shot and streaming, for every vector whose header is
    // fine (the guide's applicability rule).
    if !header_failure {
        let aead_key = case.hex("aeadKey");
        let base_nonce = case
            .hex_array::<12>("baseNonce")
            .expect("12-byte base nonce");
        let raw = || RawCipher::<I>::new(&aead_key, &base_nonce).expect("raw key length");
        let mut out = Vec::new();
        let res = raw().open(&ct[HEADER_LEN..], &mut out);
        if res.is_ok() != !invalid {
            return Outcome::Wrong("raw-mode outcome differs from header mode");
        }
        if !invalid && Some(&out) != msg.as_ref() {
            return Outcome::Wrong("raw-mode plaintext");
        }
        let (out, res) = stream(Decryptor::from_raw(raw()), &ct[HEADER_LEN..]);
        if res.is_ok() != !invalid {
            return Outcome::Wrong("raw-mode streaming outcome differs from header mode");
        }
        if let Err(what) = check_prefix(case, &out, !invalid) {
            return Outcome::Wrong(what);
        }

        // Encryption, for valid cases: raw mode is deterministic and must
        // reproduce the body; injecting the salt must reproduce the whole
        // ciphertext; a random salt must round-trip.
        if let Some(msg) = &msg {
            let mut sealed = Vec::new();
            raw().seal(msg, &mut sealed).unwrap();
            if sealed[..] != ct[HEADER_LEN..] {
                return Outcome::Wrong("raw-mode re-encryption");
            }
            let salt: &[u8; SALT_LEN] = ct[..SALT_LEN].try_into().unwrap();
            let mut enc = Encryptor::<I>::with_salt(&key, &ctx, salt).unwrap();
            let mut resealed = enc.header().to_vec();
            let mut rest = &msg[..];
            let mut i = 3;
            while !rest.is_empty() {
                let n = PIECES[i % PIECES.len()].min(rest.len());
                i += 1;
                let (piece, tail) = rest.split_at(n);
                rest = tail;
                enc.push(piece, &mut resealed).unwrap();
            }
            enc.finish(&mut resealed).unwrap();
            if resealed != ct {
                return Outcome::Wrong("salt-injected streaming re-encryption");
            }
            let mut rng = HmacDrbg::<Sha256>::new(b"chunked-fresh-salt", &key, &ctx);
            let fresh = encrypt::<I>(&key, &ctx, msg, &mut rng).unwrap();
            if fresh.len() != ct.len() || fresh[..SALT_LEN] == ct[..SALT_LEN] {
                return Outcome::Wrong("random-salt encryption shape");
            }
            if decrypt::<I>(&key, &ctx, &fresh).as_ref() != Ok(msg) {
                return Outcome::Wrong("random-salt round trip");
            }
        }
    }

    if invalid {
        Outcome::Rejected
    } else {
        Outcome::Accepted
    }
}

#[test]
fn cobblestone_128() {
    check("c2sp_chunked_encryption_aes_128_gcm", |group, c| {
        assert_eq!(group.str("aead"), "AEAD_AES_128_GCM");
        assert_eq!(group.str("sha"), "SHA-512");
        case::<Cobblestone128>(c)
    });
}

#[test]
fn cobblestone_256() {
    check("c2sp_chunked_encryption_aes_256_gcm", |group, c| {
        assert_eq!(group.str("aead"), "AEAD_AES_256_GCM");
        assert_eq!(group.str("sha"), "SHA-512");
        case::<Cobblestone256>(c)
    });
}
