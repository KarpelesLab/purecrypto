//! Format-preserving encryption: NIST SP 800-38G **FF1**.
//!
//! FF1 enciphers a *numeral string* — a sequence of digits in a chosen
//! `radix` (2 to 65536) — into another numeral string of the same length and
//! radix, under a key and an arbitrary-length tweak. It is a ten-round Feistel
//! network whose round function is AES-CBC-MAC over the tweak and one half of
//! the message; the halves are combined by modular addition modulo
//! `radix^m`, which is what keeps the output in the same format. It is the
//! usual choice for enciphering credit-card numbers, account identifiers or
//! other fields that must keep their length and character set.
//!
//! The implementation follows SP 800-38G as amended by its 2019 Rev. 1 draft:
//! the domain of a permitted message length `n` must satisfy
//! `radix^n >= 1_000_000` (the original 2016 edition only asked for `>= 100`;
//! [`Ff1::new_legacy`] keeps that bound for interoperating with existing data,
//! and is otherwise identical), `2 <= n < 2^32`, and the tweak may be any
//! length below `2^32` bytes. The `NUM`/`STR` conversions and the `mod
//! radix^m` additions use exact multi-precision arithmetic
//! ([`BoxedUint`]), so any message length in that range works.
//!
//! ```
//! use purecrypto::cipher::Aes128;
//! use purecrypto::fpe::{Alphabet, Ff1};
//!
//! let key = [
//!     0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F,
//!     0x3C,
//! ];
//! let ff1 = Ff1::new(Aes128::new(&key), 10).unwrap();
//! let digits = Alphabet::new("0123456789").unwrap();
//! let ct = ff1.encrypt_str(&digits, b"", "0123456789").unwrap();
//! assert_eq!(ct, "2433477484");
//! assert_eq!(ff1.decrypt_str(&digits, b"", &ct).unwrap(), "0123456789");
//! ```
//!
//! # Security notes
//!
//! * FF1 is a deterministic, unauthenticated permutation: equal plaintexts
//!   under the same key and tweak give equal ciphertexts, and a ciphertext can
//!   be altered without detection. Use a tweak that binds the ciphertext to
//!   its context (record identifier, column name, …) and add integrity
//!   elsewhere when it matters. Small domains are brute-forceable by
//!   definition; the `radix^n >= 10^6` floor is a minimum, not a comfort.
//! * The AES core is constant-time in the key. The Feistel arithmetic on the
//!   numeral string — radix conversion, the `mod radix^m` reductions, the byte
//!   lengths `b` and `d` derived from `n` — is inherently data-dependent: an
//!   FPE ciphertext *is* a function of the plaintext's length and digit
//!   values, and the bignum operations' shapes follow the message width, not
//!   the key. Round intermediates (the Feistel halves, the PRF input/output
//!   blocks) are wiped when they go out of scope.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::bignum::{BoxedUint, Limb};
use crate::cipher::BlockCipher;
use crate::zeroize::{Zeroize, Zeroizing};

/// Errors from FF1 operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The radix is outside `2..=65536`, an [`Alphabet`] has fewer than two
    /// or more than 65536 symbols or a repeated symbol, or the alphabet's
    /// size does not match the cipher's radix.
    InvalidRadix,
    /// The message is shorter than the minimum length for the radix
    /// (`radix^n >= 1_000_000`, or `>= 100` for [`Ff1::new_legacy`]) or
    /// `n >= 2^32`, or the tweak is `2^32` bytes or longer.
    InvalidLength,
    /// A digit is `>= radix`, or a character is not in the alphabet.
    InvalidDigit,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::InvalidRadix => "FF1: invalid radix or alphabet",
            Error::InvalidLength => "FF1: message or tweak length out of range",
            Error::InvalidDigit => "FF1: digit or character outside the radix",
        })
    }
}

impl core::error::Error for Error {}

/// The SP 800-38G Rev. 1 domain floor: `radix^minlen >= 1_000_000`.
const MIN_DOMAIN: u64 = 1_000_000;
/// The original (2016) SP 800-38G domain floor: `radix^minlen >= 100`.
const LEGACY_MIN_DOMAIN: u64 = 100;
/// Feistel rounds (SP 800-38G Algorithm 7, step 6).
const ROUNDS: u8 = 10;

/// An FF1 cipher: a keyed 128-bit block cipher plus the radix of the numeral
/// strings it enciphers.
///
/// Messages are slices of `u16` digits, each `< radix`; the
/// [`encrypt_str`](Self::encrypt_str) / [`decrypt_str`](Self::decrypt_str)
/// conveniences map text through an [`Alphabet`] first.
#[derive(Clone)]
pub struct Ff1<C: BlockCipher> {
    cipher: C,
    radix: u32,
    min_len: usize,
}

impl<C: BlockCipher> Ff1<C> {
    /// Creates an FF1 instance over `cipher` for numeral strings in `radix`
    /// (`2..=65536`), with the Rev. 1 minimum message length
    /// (`radix^minlen >= 1_000_000`).
    pub fn new(cipher: C, radix: u32) -> Result<Self, Error> {
        Self::with_min_domain(cipher, radix, MIN_DOMAIN)
    }

    /// Like [`new`](Self::new), but with the original 2016 SP 800-38G floor
    /// `radix^minlen >= 100` (so two decimal digits are enough). Rev. 1 raised
    /// the floor because such small domains are trivially enumerable; use
    /// this only to interoperate with data enciphered under the old rule.
    pub fn new_legacy(cipher: C, radix: u32) -> Result<Self, Error> {
        Self::with_min_domain(cipher, radix, LEGACY_MIN_DOMAIN)
    }

    fn with_min_domain(cipher: C, radix: u32, min_domain: u64) -> Result<Self, Error> {
        if !(2..=65536).contains(&radix) {
            return Err(Error::InvalidRadix);
        }
        // minlen = smallest n >= 2 with radix^n >= min_domain. radix^2 fits
        // in 64 bits for every radix <= 2^16 and min_domain <= 2^20 is
        // reached within 20 doublings, so the loop cannot overflow.
        let mut min_len = 2usize;
        let mut pow = u64::from(radix) * u64::from(radix);
        while pow < min_domain {
            pow *= u64::from(radix);
            min_len += 1;
        }
        Ok(Ff1 {
            cipher,
            radix,
            min_len,
        })
    }

    /// The radix this instance was built for.
    pub fn radix(&self) -> u32 {
        self.radix
    }

    /// The shortest message this instance accepts.
    pub fn min_len(&self) -> usize {
        self.min_len
    }

    /// Enciphers the numeral string `digits` (each `< radix`) under `tweak`.
    /// The output has the same length and radix.
    pub fn encrypt(&self, tweak: &[u8], digits: &[u16]) -> Result<Vec<u16>, Error> {
        self.feistel(tweak, digits, true)
    }

    /// Inverse of [`encrypt`](Self::encrypt).
    pub fn decrypt(&self, tweak: &[u8], digits: &[u16]) -> Result<Vec<u16>, Error> {
        self.feistel(tweak, digits, false)
    }

    /// Enciphers `text`, whose characters must all belong to `alphabet`
    /// (whose size must equal this instance's radix).
    pub fn encrypt_str(
        &self,
        alphabet: &Alphabet,
        tweak: &[u8],
        text: &str,
    ) -> Result<String, Error> {
        self.check_alphabet(alphabet)?;
        let digits = Zeroizing::new(alphabet.encode(text)?);
        let out = Zeroizing::new(self.encrypt(tweak, &digits)?);
        alphabet.decode(&out)
    }

    /// Inverse of [`encrypt_str`](Self::encrypt_str).
    pub fn decrypt_str(
        &self,
        alphabet: &Alphabet,
        tweak: &[u8],
        text: &str,
    ) -> Result<String, Error> {
        self.check_alphabet(alphabet)?;
        let digits = Zeroizing::new(alphabet.encode(text)?);
        let out = Zeroizing::new(self.decrypt(tweak, &digits)?);
        alphabet.decode(&out)
    }

    fn check_alphabet(&self, alphabet: &Alphabet) -> Result<(), Error> {
        if alphabet.radix() == self.radix {
            Ok(())
        } else {
            Err(Error::InvalidRadix)
        }
    }

    /// Algorithms 7 (`forward`) and 8 of SP 800-38G, in the equivalent
    /// integer form: the Feistel halves are kept as integers throughout and
    /// converted to numeral strings once at the end (Section 6 permits any
    /// mathematically equivalent sequence of steps).
    fn feistel(&self, tweak: &[u8], digits: &[u16], forward: bool) -> Result<Vec<u16>, Error> {
        let n = digits.len();
        if n < self.min_len || u32::try_from(n).is_err() {
            return Err(Error::InvalidLength);
        }
        let Ok(t) = u32::try_from(tweak.len()) else {
            return Err(Error::InvalidLength);
        };
        if digits.iter().any(|&d| u32::from(d) >= self.radix) {
            return Err(Error::InvalidDigit);
        }
        let radix = self.radix;

        // Step 1-2: split; the halves live as integers (NUM_radix of each).
        let u = n / 2;
        let v = n - u;
        let mut a = num_radix(&digits[..u], radix);
        let mut b = num_radix(&digits[u..], radix);
        let mod_u = radix_pow(radix, u);
        let mod_v = radix_pow(radix, v);

        // Step 3-4: b = ceil(ceil(v log2 radix) / 8) bytes, with
        // ceil(log2 x) = bit_len(x - 1) computed exactly on radix^v;
        // d = 4 ceil(b / 4) + 4.
        let blen = mod_v.sub(&BoxedUint::from_u64(1)).bit_len().div_ceil(8);
        let d = 4 * blen.div_ceil(4) + 4;

        // Step 5: P = [1][2][1] || [radix]^3 || [10] || [u mod 256] || [n]^4 || [t]^4.
        let mut p = [0u8; 16];
        p[0] = 1;
        p[1] = 2;
        p[2] = 1;
        p[3..6].copy_from_slice(&radix.to_be_bytes()[1..]);
        p[6] = ROUNDS;
        p[7] = (u % 256) as u8;
        p[8..12].copy_from_slice(&(n as u32).to_be_bytes());
        p[12..].copy_from_slice(&t.to_be_bytes());

        // Q = T || [0]^((-t-b-1) mod 16) || [i]^1 || [NUM(B)]^b, sized so that
        // P || Q is a whole number of blocks.
        let pad = (16 - (tweak.len() + blen + 1) % 16) % 16;
        let mut q = Zeroizing::new(vec![0u8; tweak.len() + pad + 1 + blen]);
        q[..tweak.len()].copy_from_slice(tweak);
        let round_pos = tweak.len() + pad;
        let mut s = Zeroizing::new(vec![0u8; d.div_ceil(16) * 16]);

        for round in 0..ROUNDS {
            let i = if forward { round } else { ROUNDS - 1 - round };
            q[round_pos] = i;
            // The half fed to the round function: B when enciphering, A when
            // deciphering (Algorithm 8 walks the rounds backwards).
            let input = if forward { &b } else { &a };
            let num = Zeroizing::new(input.to_be_bytes(blen));
            q[round_pos + 1..].copy_from_slice(&num);
            drop(num);
            // Step 6.ii-iii: R = PRF(P || Q); S = R || E(R xor [1]) || E(R xor [2]) ...
            let mut r = self.prf(&p, &q);
            s[..16].copy_from_slice(&r);
            for (j, block) in s.chunks_exact_mut(16).enumerate().skip(1) {
                block.copy_from_slice(&r);
                let ctr = (j as u128).to_be_bytes();
                for (x, c) in block.iter_mut().zip(ctr) {
                    *x ^= c;
                }
                let block: &mut [u8; 16] = block.try_into().expect("16-byte chunk");
                self.cipher.encrypt_block(block);
            }
            r.zeroize();
            // Step 6.iv-vi: y = NUM(S[..d]); m = u (even round) or v; the
            // other half moves by y modulo radix^m.
            let y = BoxedUint::from_be_bytes(&s[..d]);
            let modulus = if i % 2 == 0 { &mod_u } else { &mod_v };
            if forward {
                let c = a.add(&y).reduce(modulus);
                a = core::mem::replace(&mut b, c);
            } else {
                // (B - y) mod radix^m, without going negative:
                // B + radix^m - (y mod radix^m) lies in [1, 2 radix^m).
                let c = b.add(modulus).sub(&y.reduce(modulus)).reduce(modulus);
                b = core::mem::replace(&mut a, c);
            }
        }

        // Step 7: back to numeral strings.
        let mut out = str_radix(&a, u, radix);
        out.extend_from_slice(&str_radix(&b, v, radix));
        Ok(out)
    }

    /// `PRF(P || Q)`: CBC-MAC with a zero IV over the whole-block input, as
    /// Algorithm 6 defines it.
    fn prf(&self, p: &[u8; 16], q: &[u8]) -> [u8; 16] {
        debug_assert_eq!(q.len() % 16, 0);
        let mut r = *p;
        self.cipher.encrypt_block(&mut r);
        for block in q.chunks_exact(16) {
            for (x, y) in r.iter_mut().zip(block) {
                *x ^= y;
            }
            self.cipher.encrypt_block(&mut r);
        }
        r
    }
}

/// `NUM_radix(X)`: the integer whose base-`radix` digits are `digits`, most
/// significant first. Horner's rule with a single-limb multiplier, so the
/// cost is linear in the output width per digit.
fn num_radix(digits: &[u16], radix: u32) -> BoxedUint {
    // The limbs move into the `BoxedUint`, which wipes them on drop.
    let mut limbs: Vec<Limb> = vec![0];
    for &d in digits {
        mul_add_small(&mut limbs, Limb::from(radix), Limb::from(d));
    }
    BoxedUint::from_limbs(limbs)
}

/// `STR^m_radix(x)`: the `m`-digit base-`radix` representation of `x`
/// (`x < radix^m`), most significant first. Repeated single-limb division,
/// linear in the width per digit.
fn str_radix(x: &BoxedUint, m: usize, radix: u32) -> Vec<u16> {
    let mut limbs: Zeroizing<Vec<Limb>> = Zeroizing::new(x.as_limbs().to_vec());
    let mut out = vec![0u16; m];
    for slot in out.iter_mut().rev() {
        // The remainder is < radix <= 65536, so it fits a u16.
        *slot = divrem_small(&mut limbs, Limb::from(radix)) as u16;
    }
    debug_assert!(limbs.iter().all(|&l| l == 0), "STR: value exceeds radix^m");
    out
}

/// `radix^m` as a bignum.
fn radix_pow(radix: u32, m: usize) -> BoxedUint {
    let mut limbs: Vec<Limb> = vec![1];
    for _ in 0..m {
        mul_add_small(&mut limbs, Limb::from(radix), 0);
    }
    BoxedUint::from_limbs(limbs)
}

/// `limbs = limbs * m + a` on little-endian limbs, growing as needed.
fn mul_add_small(limbs: &mut Vec<Limb>, m: Limb, a: Limb) {
    let mut carry = u128::from(a);
    for l in limbs.iter_mut() {
        let t = u128::from(*l) * u128::from(m) + carry;
        *l = t as Limb;
        carry = t >> 64;
    }
    if carry != 0 {
        limbs.push(carry as Limb);
    }
}

/// `limbs /= d`, returning the remainder.
fn divrem_small(limbs: &mut [Limb], d: Limb) -> Limb {
    let mut rem: u128 = 0;
    for l in limbs.iter_mut().rev() {
        let t = (rem << 64) | u128::from(*l);
        *l = (t / u128::from(d)) as Limb;
        rem = t % u128::from(d);
    }
    rem as Limb
}

/// A character set for the string form of a numeral string: symbol `i` of
/// the alphabet is digit `i`, so the radix is the number of symbols.
///
/// Symbols are Unicode scalar values (`char`), compared exactly — no case
/// folding or normalization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alphabet {
    /// Digit -> symbol.
    symbols: Vec<char>,
    /// Symbol -> digit, sorted by symbol for binary search.
    index: Vec<(char, u16)>,
}

impl Alphabet {
    /// Builds an alphabet from its symbols in digit order. Fails with
    /// [`Error::InvalidRadix`] unless there are 2 to 65536 distinct symbols.
    pub fn new(symbols: &str) -> Result<Self, Error> {
        let symbols: Vec<char> = symbols.chars().collect();
        if !(2..=65536).contains(&symbols.len()) {
            return Err(Error::InvalidRadix);
        }
        let mut index: Vec<(char, u16)> = symbols
            .iter()
            .enumerate()
            .map(|(i, &c)| (c, i as u16))
            .collect();
        index.sort_unstable();
        if index.windows(2).any(|w| w[0].0 == w[1].0) {
            return Err(Error::InvalidRadix);
        }
        Ok(Alphabet { symbols, index })
    }

    /// The number of symbols.
    pub fn radix(&self) -> u32 {
        self.symbols.len() as u32
    }

    /// The symbols in digit order.
    pub fn symbols(&self) -> &[char] {
        &self.symbols
    }

    /// Maps `text` to digits; [`Error::InvalidDigit`] for a character outside
    /// the alphabet.
    pub fn encode(&self, text: &str) -> Result<Vec<u16>, Error> {
        text.chars()
            .map(|c| {
                self.index
                    .binary_search_by_key(&c, |&(s, _)| s)
                    .map(|i| self.index[i].1)
                    .map_err(|_| Error::InvalidDigit)
            })
            .collect()
    }

    /// Maps digits back to text; [`Error::InvalidDigit`] for a digit `>=`
    /// the radix.
    pub fn decode(&self, digits: &[u16]) -> Result<String, Error> {
        digits
            .iter()
            .map(|&d| self.symbols.get(usize::from(d)).copied())
            .collect::<Option<String>>()
            .ok_or(Error::InvalidDigit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::{Aes128, Aes192, Aes256};
    use crate::test_util::from_hex_vec;

    const KEY128: &str = "2B7E151628AED2A6ABF7158809CF4F3C";
    const KEY192: &str = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F";
    const KEY256: &str = "2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94";
    const TWEAK10: &str = "39383736353433323130";
    const TWEAK36: &str = "3737373770717273373737";
    const PT10: [u16; 10] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
    const PT36: [u16; 19] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,
    ];

    fn aes128() -> Aes128 {
        Aes128::new(&from_hex_vec(KEY128).try_into().unwrap())
    }
    fn aes192() -> Aes192 {
        Aes192::new(&from_hex_vec(KEY192).try_into().unwrap())
    }
    fn aes256() -> Aes256 {
        Aes256::new(&from_hex_vec(KEY256).try_into().unwrap())
    }

    fn check<C: BlockCipher>(cipher: C, radix: u32, tweak: &str, pt: &[u16], ct: &[u16]) {
        let ff1 = Ff1::new(cipher, radix).unwrap();
        let tweak = from_hex_vec(tweak);
        assert_eq!(ff1.encrypt(&tweak, pt).unwrap(), ct);
        assert_eq!(ff1.decrypt(&tweak, ct).unwrap(), pt);
    }

    /// NIST "FF1 samples" (SP 800-38G sample vectors), AES-128.
    #[test]
    fn nist_samples_aes128() {
        check(aes128(), 10, "", &PT10, &[2, 4, 3, 3, 4, 7, 7, 4, 8, 4]);
        check(
            aes128(),
            10,
            TWEAK10,
            &PT10,
            &[6, 1, 2, 4, 2, 0, 0, 7, 7, 3],
        );
        check(
            aes128(),
            36,
            TWEAK36,
            &PT36,
            &[
                10, 9, 29, 31, 4, 0, 22, 21, 21, 9, 20, 13, 30, 5, 0, 9, 14, 30, 22,
            ],
        );
    }

    /// NIST "FF1 samples", AES-192.
    #[test]
    fn nist_samples_aes192() {
        check(aes192(), 10, "", &PT10, &[2, 8, 3, 0, 6, 6, 8, 1, 3, 2]);
        check(
            aes192(),
            10,
            TWEAK10,
            &PT10,
            &[2, 4, 9, 6, 6, 5, 5, 5, 4, 9],
        );
        check(
            aes192(),
            36,
            TWEAK36,
            &PT36,
            &[
                33, 11, 19, 3, 20, 31, 3, 5, 19, 27, 10, 32, 33, 31, 3, 2, 34, 28, 27,
            ],
        );
    }

    /// NIST "FF1 samples", AES-256.
    #[test]
    fn nist_samples_aes256() {
        check(aes256(), 10, "", &PT10, &[6, 6, 5, 7, 6, 6, 7, 0, 0, 9]);
        check(
            aes256(),
            10,
            TWEAK10,
            &PT10,
            &[1, 0, 0, 1, 6, 2, 3, 4, 6, 3],
        );
        check(
            aes256(),
            36,
            TWEAK36,
            &PT36,
            &[
                33, 28, 8, 10, 0, 10, 35, 17, 2, 10, 31, 34, 10, 21, 34, 35, 30, 32, 13,
            ],
        );
    }

    #[test]
    fn string_form_matches_digits() {
        let ff1 = Ff1::new(aes128(), 36).unwrap();
        let alphabet = Alphabet::new("0123456789abcdefghijklmnopqrstuvwxyz").unwrap();
        let tweak = from_hex_vec(TWEAK36);
        let ct = ff1
            .encrypt_str(&alphabet, &tweak, "0123456789abcdefghi")
            .unwrap();
        assert_eq!(ct, "a9tv40mll9kdu509eum");
        assert_eq!(
            ff1.decrypt_str(&alphabet, &tweak, &ct).unwrap(),
            "0123456789abcdefghi"
        );
        // Characters outside the alphabet and a mismatched alphabet size.
        assert_eq!(
            ff1.encrypt_str(&alphabet, &tweak, "0123456789ABCDEFGHI"),
            Err(Error::InvalidDigit)
        );
        let decimal = Alphabet::new("0123456789").unwrap();
        assert_eq!(
            ff1.encrypt_str(&decimal, &tweak, "0123456789"),
            Err(Error::InvalidRadix)
        );
    }

    #[test]
    fn alphabet_validation() {
        assert_eq!(Alphabet::new("").err(), Some(Error::InvalidRadix));
        assert_eq!(Alphabet::new("a").err(), Some(Error::InvalidRadix));
        assert_eq!(Alphabet::new("abca").err(), Some(Error::InvalidRadix));
        let a = Alphabet::new("αβγδ").unwrap();
        assert_eq!(a.radix(), 4);
        assert_eq!(a.encode("δα").unwrap(), [3, 0]);
        assert_eq!(a.decode(&[3, 0]).unwrap(), "δα");
        assert_eq!(a.decode(&[4]), Err(Error::InvalidDigit));
        assert_eq!(a.encode("a"), Err(Error::InvalidDigit));
    }

    #[test]
    fn parameter_validation() {
        assert!(Ff1::new(aes128(), 1).is_err());
        assert!(Ff1::new(aes128(), 65537).is_err());
        assert!(Ff1::new(aes128(), 65536).is_ok());
        // Rev. 1: radix^minlen >= 10^6; legacy: >= 100.
        assert_eq!(Ff1::new(aes128(), 10).unwrap().min_len(), 6);
        assert_eq!(Ff1::new(aes128(), 2).unwrap().min_len(), 20);
        assert_eq!(Ff1::new(aes128(), 1000).unwrap().min_len(), 2);
        assert_eq!(Ff1::new(aes128(), 65536).unwrap().min_len(), 2);
        assert_eq!(Ff1::new_legacy(aes128(), 10).unwrap().min_len(), 2);
        assert_eq!(Ff1::new_legacy(aes128(), 2).unwrap().min_len(), 7);
        assert_eq!(Ff1::new_legacy(aes128(), 65536).unwrap().min_len(), 2);

        let ff1 = Ff1::new(aes128(), 10).unwrap();
        assert_eq!(
            ff1.encrypt(b"", &[1, 2, 3, 4, 5]),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            ff1.encrypt(b"", &[1, 2, 3, 4, 5, 10]),
            Err(Error::InvalidDigit)
        );
        assert!(ff1.encrypt(b"", &[1, 2, 3, 4, 5, 6]).is_ok());
        let legacy = Ff1::new_legacy(aes128(), 10).unwrap();
        assert!(legacy.encrypt(b"", &[1, 2]).is_ok());
        assert_eq!(legacy.encrypt(b"", &[1]), Err(Error::InvalidLength));
    }

    #[test]
    fn long_message_round_trips_with_long_tweak() {
        // 1000 digits in radix 7 (about 2800 bits per half) and a 100-byte
        // tweak exercise the multi-limb paths of NUM / STR / mod radix^m.
        let ff1 = Ff1::new(aes256(), 7).unwrap();
        let pt: Vec<u16> = (0..1000u32).map(|i| ((i * i + 3) % 7) as u16).collect();
        let tweak: Vec<u8> = (0..100u8).collect();
        let ct = ff1.encrypt(&tweak, &pt).unwrap();
        assert_eq!(ct.len(), pt.len());
        assert!(ct.iter().all(|&d| d < 7));
        assert_ne!(ct, pt);
        assert_eq!(ff1.decrypt(&tweak, &ct).unwrap(), pt);
        // A different tweak gives a different ciphertext.
        assert_ne!(ff1.encrypt(b"other", &pt).unwrap(), ct);
    }

    #[test]
    fn radix_conversion_round_trip() {
        for radix in [2u32, 3, 10, 255, 256, 65535, 65536] {
            let digits: Vec<u16> = (0..300u32)
                .map(|i| ((i * 7919 + 13) % radix) as u16)
                .collect();
            let x = num_radix(&digits, radix);
            assert_eq!(str_radix(&x, digits.len(), radix), digits);
            // Leading zeros are preserved by the fixed output width.
            assert_eq!(str_radix(&BoxedUint::from_u64(1), 5, radix)[..4], [0; 4]);
        }
        assert_eq!(num_radix(&[1, 2, 3], 10), BoxedUint::from_u64(123));
        assert_eq!(
            radix_pow(10, 25),
            BoxedUint::from_be_bytes(&[
                0x08, 0x45, 0x95, 0x16, 0x14, 0x01, 0x48, 0x4A, 0x00, 0x00, 0x00
            ])
        );
    }
}
