//! Fuzz the hasher-state importers: `Hasher::from_state` for every
//! `HashAlgorithm` (which is each digest's `ExportableState::from_state`,
//! including the `legacy-hashes` ones), plus the types that are not
//! reachable through `Hasher` — SHAKE128 / SHAKE256, BLAKE2Xb / BLAKE2Xs
//! and the keyed BLAKE2b / BLAKE2s MACs.
//!
//! An exported state is a resumable computation that applications persist
//! or ship between processes (PHP's `HashContext` serialization is the
//! model), so the import side reads attacker-influenced bytes. It promises
//! never to panic and to reject every inconsistent field; what this target
//! adds is that a state the importer *accepts* must also be safe to keep
//! using — `update` and the finalizer run on it, so a buffered count or
//! length counter that slipped through validation shows up as an
//! out-of-bounds index or an overflow here.
//!
//! Two properties are asserted on top of "no panic":
//!
//! * an accepted state re-exports to exactly the bytes it was imported
//!   from (the format documents one encoding per state);
//! * an *unmodified* exported state resumes to the same digest as hashing
//!   the whole message in one go.
//!
//! Input layout: `selector, flags, body…`. The selector picks the
//! algorithm. With `flags & 1` clear the body is the raw state followed by
//! bytes to absorb (`flags & 2`: the whole body is the state, to reach the
//! length check from above). With `flags & 1` set the harness builds a
//! genuine state itself — it absorbs a fuzz-chosen prefix and exports —
//! then applies up to three fuzz-chosen byte patches before importing.
//! That puts the fuzzer one mutation away from every validated field
//! without needing a seed corpus.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::hash::{
    Blake2bMac, Blake2sMac, Blake2xb, Blake2xs, ExportableState, ExtendableOutput, HashAlgorithm,
    Hasher, Shake128, Shake256, XofReader,
};

/// States are at most `HashAlgorithm::MAX_STATE_LEN` (347) bytes; leave
/// room for a few blocks of message on either side.
const MAX_INPUT: usize = 2048;

/// The non-`Hasher` exportable types, behind one interface.
trait Resumable: ExportableState {
    /// A fresh instance, parameterised (output length, key) by `param`.
    fn fresh(param: &[u8]) -> Self;
    fn absorb(&mut self, data: &[u8]);
    /// Finalizes. Must not panic for any state the importer accepted.
    fn finish(self) -> Vec<u8>;
}

macro_rules! resumable_shake {
    ($($ty:ty),+) => {$(
        impl Resumable for $ty {
            fn fresh(_: &[u8]) -> Self {
                <$ty as ExtendableOutput>::new()
            }
            fn absorb(&mut self, data: &[u8]) {
                ExtendableOutput::update(self, data);
            }
            fn finish(self) -> Vec<u8> {
                // Across a rate boundary, in two reads.
                let mut out = vec![0u8; 200];
                let mut reader = self.finalize_xof();
                reader.read(&mut out[..7]);
                reader.read(&mut out[7..]);
                out
            }
        }
    )+};
}
resumable_shake!(Shake128, Shake256);

macro_rules! resumable_blake2x {
    ($($ty:ty),+) => {$(
        impl Resumable for $ty {
            fn fresh(param: &[u8]) -> Self {
                // 1..=256 output bytes: one to five BLAKE2Xb nodes.
                <$ty>::new(1 + usize::from(param.first().copied().unwrap_or(0)))
            }
            fn absorb(&mut self, data: &[u8]) {
                self.update(data);
            }
            fn finish(self) -> Vec<u8> {
                // The declared output length travels inside the state and
                // has no accessor; reading past it is a documented panic.
                // An accepted state declares at least one byte.
                let mut out = vec![0u8; 1];
                self.finalize_into(&mut out);
                out
            }
        }
    )+};
}
resumable_blake2x!(Blake2xb, Blake2xs);

macro_rules! resumable_blake2_mac {
    ($($ty:ty => $max:literal),+) => {$(
        impl Resumable for $ty {
            fn fresh(param: &[u8]) -> Self {
                let out_len = 1 + usize::from(param.first().copied().unwrap_or(0)) % $max;
                let key = param.get(1..).unwrap_or(&[]);
                <$ty>::new(&key[..key.len().min($max)], out_len)
            }
            fn absorb(&mut self, data: &[u8]) {
                self.update(data);
            }
            fn finish(self) -> Vec<u8> {
                // `finalize_into` wants exactly the tag length, which also
                // travels inside the state; `verify` finalizes with the
                // stored length and fails closed on a mismatch.
                let _ = self.verify(&[0u8; 16]);
                Vec::new()
            }
        }
    )+};
}
resumable_blake2_mac!(Blake2bMac => 64, Blake2sMac => 32);

/// Splits `n` bytes (or as many as remain) off the front of `data`.
fn take<'a>(data: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (head, tail) = data.split_at(n.min(data.len()));
    *data = tail;
    head
}

fn take_u8(data: &mut &[u8]) -> u8 {
    take(data, 1).first().copied().unwrap_or(0)
}

/// What one iteration imports: the candidate state, the bytes to absorb
/// after it, and — for an untouched genuine state — the message it already
/// absorbed.
struct Case<'a> {
    state: Vec<u8>,
    tail: &'a [u8],
    genuine_prefix: Option<&'a [u8]>,
}

/// Decodes the body for a state of `state_len` bytes. `export` produces
/// the genuine state after absorbing a prefix (seeded mode only).
fn case<'a>(
    flags: u8,
    mut body: &'a [u8],
    state_len: usize,
    export: impl FnOnce(&[u8], &[u8]) -> Vec<u8>,
) -> Case<'a> {
    if flags & 1 == 0 {
        let n = if flags & 2 == 0 {
            state_len
        } else {
            body.len()
        };
        let state = take(&mut body, n).to_vec();
        return Case {
            state,
            tail: body,
            genuine_prefix: None,
        };
    }
    let n_param = usize::from(take_u8(&mut body) % 66);
    let param = take(&mut body, n_param);
    let n_prefix = usize::from(take_u8(&mut body)) * 2;
    let prefix = take(&mut body, n_prefix);
    let mut state = export(param, prefix);
    let patches = take_u8(&mut body) % 4;
    for _ in 0..patches {
        let pos = usize::from(u16::from_be_bytes([take_u8(&mut body), take_u8(&mut body)]));
        let xor = take_u8(&mut body);
        if !state.is_empty() {
            let len = state.len();
            state[pos % len] ^= xor;
        }
    }
    Case {
        state,
        tail: body,
        // A zero XOR leaves the state genuine too, but then the fuzzer can
        // drop the patch; only the patch-free form carries the oracle.
        genuine_prefix: (patches == 0).then_some(prefix),
    }
}

fn run_hasher(alg: HashAlgorithm, flags: u8, body: &[u8]) {
    // BLAKE3 has no exportable state: `from_state` must say so, for any
    // bytes.
    let Some(state_len) = alg.state_len() else {
        assert!(Hasher::from_state(alg, body).is_err());
        return;
    };
    let c = case(flags, body, state_len, |_, prefix| {
        let mut h = Hasher::new(alg);
        h.update(prefix);
        let mut out = vec![0u8; HashAlgorithm::MAX_STATE_LEN];
        let n = h.export_state(&mut out).expect("exportable algorithm");
        assert_eq!(n, state_len);
        out.truncate(n);
        out
    });
    let Ok(mut h) = Hasher::from_state(alg, &c.state) else {
        assert!(
            c.genuine_prefix.is_none(),
            "{}: own exported state was rejected",
            alg.name()
        );
        return;
    };
    assert_eq!(h.algorithm(), alg);
    let mut again = [0u8; HashAlgorithm::MAX_STATE_LEN];
    let n = h.export_state(&mut again).expect("exportable algorithm");
    assert_eq!(
        &again[..n],
        &c.state[..],
        "{}: accepted state does not re-export to itself",
        alg.name()
    );
    h.update(c.tail);
    let got = h.finalize();
    if let Some(prefix) = c.genuine_prefix {
        let want = alg.digest_parts([prefix, c.tail]);
        assert_eq!(
            got.as_slice(),
            want.as_slice(),
            "{}: resumed digest differs from the one-shot digest",
            alg.name()
        );
    }
}

fn run_typed<T: Resumable>(flags: u8, body: &[u8]) {
    let mut param_seen: &[u8] = &[];
    let c = case(flags, body, T::STATE_LEN, |param, prefix| {
        let mut h = T::fresh(param);
        h.absorb(prefix);
        h.export_state().as_ref().to_vec()
    });
    // Recover the parameter bytes the closure consumed, for the oracle.
    if flags & 1 == 1 {
        let mut b = body;
        let n = usize::from(take_u8(&mut b) % 66);
        param_seen = take(&mut b, n);
    }
    let Ok(mut h) = T::from_state(&c.state) else {
        assert!(
            c.genuine_prefix.is_none(),
            "own exported state was rejected"
        );
        return;
    };
    assert_eq!(
        h.export_state().as_ref(),
        &c.state[..],
        "accepted state does not re-export to itself"
    );
    h.absorb(c.tail);
    let got = h.finish();
    if let Some(prefix) = c.genuine_prefix {
        let mut whole = T::fresh(param_seen);
        whole.absorb(prefix);
        whole.absorb(c.tail);
        assert_eq!(got, whole.finish(), "resumed output differs");
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let [selector, flags, body @ ..] = data else {
        return;
    };
    let algs = HashAlgorithm::ALL;
    match usize::from(*selector) % (algs.len() + 6) {
        i if i < algs.len() => run_hasher(algs[i], *flags, body),
        i => match i - algs.len() {
            0 => run_typed::<Shake128>(*flags, body),
            1 => run_typed::<Shake256>(*flags, body),
            2 => run_typed::<Blake2xb>(*flags, body),
            3 => run_typed::<Blake2xs>(*flags, body),
            4 => run_typed::<Blake2bMac>(*flags, body),
            _ => run_typed::<Blake2sMac>(*flags, body),
        },
    }
});
