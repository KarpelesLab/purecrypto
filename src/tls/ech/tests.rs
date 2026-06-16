//! Tests for the ECH codec, key material, and GREASE producer.
//!
//! Covers wire round-trips for ECHConfig / ECHConfigList /
//! HpkeKeyConfig / encrypted_client_hello, error-path negatives,
//! retry_configs encoding, GREASE bit-shape invariants, and the
//! accept-signal helpers.

use super::accept_signal::{
    hello_retry_request_signal, patch_random_tail, random_tail, random_with_zero_tail,
    server_hello_signal, signals_eq_ct,
};
use super::config::{
    ECH_VERSION_DRAFT_22, EchConfig, EchConfigContents, EchConfigList, HpkeKeyConfig,
    HpkeSymCipherSuite,
};
use super::extension::{EchExtension, zero_payload};
use super::grease::{GreaseConfigIdStrategy, GreaseParams};
use super::hpke_setup::{ech_info, map_kem, map_sym_suite};
use super::inner::{
    compress_extensions, decode_outer_extensions, decompress_extensions, encode_outer_extensions,
    inner_extension_body,
};
use super::keys::{EchKeyPair, EchKeyRing};
use super::retry::{decode_retry_configs, encode_retry_configs};
use crate::hpke::{HpkeAead, HpkeKdf, HpkeKem};
use crate::rng::HmacDrbg;
use crate::tls::Error;
use crate::tls::codec::ExtensionType;
use crate::tls::crypto::HashAlg;
use alloc::vec::Vec;

/// A small deterministic RNG for codec tests: HmacDrbg-SHA-256
/// re-keyed per test so cross-test interference can't muddy KAT
/// reasoning.
fn drbg(seed: &[u8]) -> HmacDrbg<crate::hash::Sha256> {
    HmacDrbg::<crate::hash::Sha256>::new(seed, b"ech test seed", b"")
}

fn sample_sym_suites() -> Vec<HpkeSymCipherSuite> {
    alloc::vec![
        HpkeSymCipherSuite {
            kdf_id: 0x0001,
            aead_id: 0x0001,
        },
        HpkeSymCipherSuite {
            kdf_id: 0x0001,
            aead_id: 0x0003,
        },
    ]
}

fn sample_config() -> EchConfig {
    let contents = EchConfigContents {
        key_config: HpkeKeyConfig {
            config_id: 7,
            kem_id: HpkeKem::DhkemX25519HkdfSha256.id(),
            public_key: alloc::vec![0x11u8; 32],
            cipher_suites: sample_sym_suites(),
        },
        maximum_name_length: 64,
        public_name: b"public.example".to_vec(),
        extensions: Vec::new(),
    };
    EchConfig::new(contents)
}

#[test]
fn hpke_sym_cipher_suite_roundtrip() {
    let s = HpkeSymCipherSuite {
        kdf_id: 0x0002,
        aead_id: 0x0003,
    };
    let mut buf = Vec::new();
    s.encode_into(&mut buf);
    assert_eq!(buf, alloc::vec![0x00, 0x02, 0x00, 0x03]);
    let back = HpkeSymCipherSuite::decode(&buf).unwrap();
    assert_eq!(back, s);
}

#[test]
fn hpke_sym_cipher_suite_wrong_length_rejected() {
    assert!(matches!(
        HpkeSymCipherSuite::decode(&[0u8; 3]),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn ech_config_list_roundtrip() {
    let cfg = sample_config();
    let list = EchConfigList::new(alloc::vec![cfg.clone()]);
    let bytes = list.encode();
    let parsed = EchConfigList::decode(&bytes).unwrap();
    assert_eq!(parsed.configs.len(), 1);
    let first = parsed.first_supported().unwrap();
    assert_eq!(first.version, ECH_VERSION_DRAFT_22);
    let c = first.contents.as_ref().unwrap();
    assert_eq!(c.key_config.config_id, 7);
    assert_eq!(c.key_config.kem_id, HpkeKem::DhkemX25519HkdfSha256.id());
    assert_eq!(c.public_name, b"public.example");
}

#[test]
fn ech_config_list_unknown_version_preserved_but_unsupported() {
    // Build a list with one entry at version 0xFEEE (unknown) plus
    // one at the supported version.
    let supported = sample_config();
    let unknown = EchConfig {
        version: 0xFEEE,
        contents: None,
        raw_contents: alloc::vec![0xde, 0xad, 0xbe, 0xef],
    };
    let list = EchConfigList::new(alloc::vec![unknown.clone(), supported.clone()]);
    let bytes = list.encode();
    let parsed = EchConfigList::decode(&bytes).unwrap();
    assert_eq!(parsed.configs.len(), 2);
    assert!(!parsed.configs[0].is_supported());
    assert!(parsed.configs[1].is_supported());
    // The first supported entry must be the second one.
    let first = parsed.first_supported().unwrap();
    assert_eq!(first.version, ECH_VERSION_DRAFT_22);
}

#[test]
fn ech_config_list_empty_rejected() {
    let bytes = alloc::vec![0x00, 0x00];
    assert!(matches!(
        EchConfigList::decode(&bytes),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn ech_config_list_trailing_bytes_rejected() {
    let cfg = sample_config();
    let list = EchConfigList::new(alloc::vec![cfg]);
    let mut bytes = list.encode();
    bytes.push(0x99);
    assert!(matches!(
        EchConfigList::decode(&bytes),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn ech_config_truncated_rejected() {
    let cfg = sample_config();
    let list = EchConfigList::new(alloc::vec![cfg]);
    let bytes = list.encode();
    // Decapitate the last byte.
    let truncated = &bytes[..bytes.len() - 1];
    assert!(matches!(
        EchConfigList::decode(truncated),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn ech_config_public_name_must_be_non_empty() {
    let mut contents = EchConfigContents {
        key_config: HpkeKeyConfig {
            config_id: 1,
            kem_id: HpkeKem::DhkemX25519HkdfSha256.id(),
            public_key: alloc::vec![0u8; 32],
            cipher_suites: sample_sym_suites(),
        },
        maximum_name_length: 32,
        public_name: Vec::new(), // empty — should fail decode
        extensions: Vec::new(),
    };
    let mut raw = Vec::new();
    contents.key_config.encode_into(&mut raw);
    raw.push(contents.maximum_name_length);
    raw.push(0); // public_name length = 0 (illegal)
    raw.extend_from_slice(&[0x00, 0x00]); // ext_len = 0
    let cfg = EchConfig {
        version: ECH_VERSION_DRAFT_22,
        contents: None,
        raw_contents: raw,
    };
    let list = EchConfigList::new(alloc::vec![cfg]);
    let bytes = list.encode();
    assert!(matches!(
        EchConfigList::decode(&bytes),
        Err(Error::EchDecodeError)
    ));
    // Touch the field so the linter doesn't complain.
    contents.public_name = b"x".to_vec();
}

#[test]
fn mandatory_unknown_extension_rejected() {
    // Build ECHConfigContents.extensions with one mandatory (high
    // bit set) unknown extension type. Decode must reject.
    let key_config = HpkeKeyConfig {
        config_id: 1,
        kem_id: HpkeKem::DhkemX25519HkdfSha256.id(),
        public_key: alloc::vec![0u8; 32],
        cipher_suites: sample_sym_suites(),
    };
    let mut raw = Vec::new();
    key_config.encode_into(&mut raw);
    raw.push(64);
    raw.push(7);
    raw.extend_from_slice(b"example");
    // extensions: one (mandatory) extension of type 0x8001, empty data
    let mut ext_bytes = Vec::new();
    ext_bytes.extend_from_slice(&0x8001u16.to_be_bytes());
    ext_bytes.extend_from_slice(&0u16.to_be_bytes());
    raw.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
    raw.extend_from_slice(&ext_bytes);
    let cfg = EchConfig {
        version: ECH_VERSION_DRAFT_22,
        contents: None,
        raw_contents: raw,
    };
    let list = EchConfigList::new(alloc::vec![cfg]);
    let bytes = list.encode();
    assert!(matches!(
        EchConfigList::decode(&bytes),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn ext_outer_roundtrip() {
    let ext = EchExtension::Outer {
        cipher_suite: HpkeSymCipherSuite {
            kdf_id: 0x0001,
            aead_id: 0x0003,
        },
        config_id: 0x42,
        enc: alloc::vec![0xAA; 32],
        payload: alloc::vec![0xBB; 144],
    };
    let bytes = ext.encode();
    // 1 type + 4 cs + 1 cid + 2 enc_len + 32 enc + 2 pl_len + 144 pl = 186
    assert_eq!(bytes.len(), 186);
    let back = EchExtension::decode(&bytes).unwrap();
    assert_eq!(back, ext);
}

#[test]
fn ext_inner_roundtrip() {
    let ext = EchExtension::Inner;
    let bytes = ext.encode();
    assert_eq!(bytes, alloc::vec![0x01]);
    let back = EchExtension::decode(&bytes).unwrap();
    assert_eq!(back, ext);
}

#[test]
fn ext_inner_extra_bytes_rejected() {
    assert!(matches!(
        EchExtension::decode(&[0x01, 0x00]),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn ext_outer_empty_payload_rejected() {
    let bytes = alloc::vec![
        0x00, // type=outer
        0x00, 0x01, 0x00, 0x01, // cipher_suite
        0x07, // config_id
        0x00, 0x01, 0xAA, // enc<1>
        0x00, 0x00, // payload<0> — illegal
    ];
    assert!(matches!(
        EchExtension::decode(&bytes),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn ext_outer_unknown_type_rejected() {
    let bytes = alloc::vec![0x02, 0x00, 0x00];
    assert!(matches!(
        EchExtension::decode(&bytes),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn zero_payload_keeps_other_fields() {
    let ext = EchExtension::Outer {
        cipher_suite: HpkeSymCipherSuite {
            kdf_id: 0x0001,
            aead_id: 0x0003,
        },
        config_id: 0x42,
        enc: alloc::vec![0xAA; 16],
        payload: alloc::vec![0xBB; 32],
    };
    let bytes = ext.encode();
    let zeroed = zero_payload(&bytes).unwrap();
    assert_eq!(zeroed.len(), bytes.len());
    // The header (type + cs + config_id + enc_len + enc + pl_len) is
    // 1 + 4 + 1 + 2 + 16 + 2 = 26 bytes; the next 32 bytes should
    // be zero, prefix should match.
    assert_eq!(&zeroed[..26], &bytes[..26]);
    assert!(zeroed[26..].iter().all(|&b| b == 0));
    // The original is unchanged.
    let parsed = EchExtension::decode(&bytes).unwrap();
    match parsed {
        EchExtension::Outer { payload, .. } => assert!(payload.iter().all(|&b| b == 0xBB)),
        _ => panic!("expected outer"),
    }
}

#[test]
fn zero_payload_rejects_inner_form() {
    assert!(matches!(zero_payload(&[0x01]), Err(Error::EchDecodeError)));
}

#[test]
fn retry_configs_roundtrip() {
    let list = EchConfigList::new(alloc::vec![sample_config()]);
    let bytes = encode_retry_configs(&list);
    let back = decode_retry_configs(&bytes).unwrap();
    assert_eq!(back.configs.len(), 1);
    assert!(back.configs[0].is_supported());
}

#[test]
fn key_pair_generate_produces_published_pubkey() {
    let mut rng = drbg(b"keygen-pubkey-roundtrip");
    let kp = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        17,
        b"public.example.com",
        64,
        sample_sym_suites(),
    )
    .expect("generate");
    assert_eq!(kp.config_id(), 17);
    let contents = kp.config().contents.as_ref().unwrap();
    assert_eq!(
        contents.key_config.kem_id,
        HpkeKem::DhkemX25519HkdfSha256.id()
    );
    assert_eq!(contents.key_config.public_key.len(), 32);
    assert_eq!(contents.public_name, b"public.example.com");
    // The pair must accept the cipher suites it published.
    assert!(kp.accepts(HpkeKdf::HkdfSha256, HpkeAead::Aes128Gcm));
    assert!(kp.accepts(HpkeKdf::HkdfSha256, HpkeAead::ChaCha20Poly1305));
    assert!(!kp.accepts(HpkeKdf::HkdfSha384, HpkeAead::Aes128Gcm));
}

#[test]
fn key_pair_rejects_empty_public_name() {
    let mut rng = drbg(b"keygen-empty-name");
    let res = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0,
        b"",
        64,
        sample_sym_suites(),
    );
    assert!(matches!(res, Err(Error::EchDecodeError)));
}

#[test]
fn key_pair_rejects_empty_suite_list() {
    let mut rng = drbg(b"keygen-empty-suites");
    let res = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0,
        b"x",
        64,
        Vec::new(),
    );
    assert!(matches!(res, Err(Error::EchDecodeError)));
}

#[test]
fn key_ring_lookup_by_config_id() {
    let mut rng = drbg(b"ring");
    let kp1 = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        1,
        b"a",
        32,
        sample_sym_suites(),
    )
    .unwrap();
    let kp2 = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        2,
        b"b",
        32,
        sample_sym_suites(),
    )
    .unwrap();
    let ring = EchKeyRing::from_pairs(alloc::vec![kp1, kp2]);
    assert_eq!(ring.matching_by_config_id(1).count(), 1);
    assert_eq!(ring.matching_by_config_id(2).count(), 1);
    assert_eq!(ring.matching_by_config_id(99).count(), 0);
    let list = ring.to_config_list();
    assert_eq!(list.configs.len(), 2);
}

#[test]
fn grease_extension_has_expected_shape() {
    let mut rng = drbg(b"grease-shape");
    let params = GreaseParams {
        cipher_suite: HpkeSymCipherSuite {
            kdf_id: 0x0001,
            aead_id: 0x0001,
        },
        enc_len: 32,
        payload_len: 144,
        config_id_strategy: GreaseConfigIdStrategy::Fixed(0xab),
    };
    let body = params.build_extension_bytes(&mut rng);
    let ext = EchExtension::decode(&body).unwrap();
    match ext {
        EchExtension::Outer {
            cipher_suite,
            config_id,
            enc,
            payload,
        } => {
            assert_eq!(cipher_suite.kdf_id, 0x0001);
            assert_eq!(cipher_suite.aead_id, 0x0001);
            assert_eq!(config_id, 0xab);
            assert_eq!(enc.len(), 32);
            assert_eq!(payload.len(), 144);
        }
        _ => panic!("expected Outer"),
    }
    // 1 type + 4 cs + 1 cid + 2 enc_len + 32 enc + 2 pl_len + 144 pl = 186
    assert_eq!(body.len(), 186);
}

#[test]
fn grease_default_is_well_formed() {
    let mut rng = drbg(b"grease-default");
    let body = GreaseParams::default().build_extension_bytes(&mut rng);
    let ext = EchExtension::decode(&body).unwrap();
    assert!(matches!(ext, EchExtension::Outer { .. }));
}

/// TLS-1 regression: distinct per-connection seeds with the same
/// public CH random MUST produce distinct GREASE payloads. The old
/// implementation HKDF-expanded only `ch_random` and so let any
/// observer reconstruct the GREASE bytes byte-for-byte from the
/// wire CH — defeating the only purpose of GREASE. With a private
/// seed mixed in as IKM and `ch_random` as salt, two clients on the
/// same `ch_random` (which an attacker might force in a replay-style
/// experiment) get completely different GREASE bytes.
#[test]
fn grease_from_seed_differs_per_seed_for_same_ch_random() {
    let params = GreaseParams {
        cipher_suite: HpkeSymCipherSuite {
            kdf_id: 0x0001,
            aead_id: 0x0001,
        },
        enc_len: 32,
        payload_len: 144,
        config_id_strategy: GreaseConfigIdStrategy::Random,
    };
    let ch_random = [0x42u8; 32];
    let seed_a = [0x01u8; 32];
    let seed_b = [0x02u8; 32];
    let a = params.build_extension_from_seed(&seed_a, &ch_random);
    let b = params.build_extension_from_seed(&seed_b, &ch_random);
    assert_ne!(a, b, "GREASE must differ across distinct private seeds");
    // Same seed + same CH random must of course reproduce.
    let a2 = params.build_extension_from_seed(&seed_a, &ch_random);
    assert_eq!(a, a2);
}

/// TLS-1 secondary check: keeping the seed fixed but varying the
/// CH random still produces uncorrelated GREASE. This is the
/// expected behaviour anyway (HKDF on different salts), but the
/// test pins the contract.
#[test]
fn grease_from_seed_differs_per_ch_random_for_same_seed() {
    let params = GreaseParams::default();
    let seed = [0x77u8; 32];
    let r1 = [0x11u8; 32];
    let r2 = [0x99u8; 32];
    let a = params.build_extension_from_seed(&seed, &r1);
    let b = params.build_extension_from_seed(&seed, &r2);
    assert_ne!(a, b);
}

#[test]
fn map_sym_suite_resolves_supported_pairs() {
    let kdfs: &[(u16, HpkeKdf)] = &[
        (0x0001, HpkeKdf::HkdfSha256),
        (0x0002, HpkeKdf::HkdfSha384),
        (0x0003, HpkeKdf::HkdfSha512),
    ];
    let aeads: &[(u16, HpkeAead)] = &[
        (0x0001, HpkeAead::Aes128Gcm),
        (0x0002, HpkeAead::Aes256Gcm),
        (0x0003, HpkeAead::ChaCha20Poly1305),
    ];
    for &(kid, kexp) in kdfs {
        for &(aid, aexp) in aeads {
            let s = HpkeSymCipherSuite {
                kdf_id: kid,
                aead_id: aid,
            };
            let (k, a) = map_sym_suite(s).unwrap();
            assert_eq!(k, kexp);
            assert_eq!(a, aexp);
        }
    }
}

#[test]
fn map_sym_suite_rejects_export_only_and_unknowns() {
    // ExportOnly is 0xFFFF.
    let s = HpkeSymCipherSuite {
        kdf_id: 0x0001,
        aead_id: 0xFFFF,
    };
    assert!(matches!(map_sym_suite(s), Err(Error::EchDecodeError)));
    // Unknown KDF.
    let s = HpkeSymCipherSuite {
        kdf_id: 0xABCD,
        aead_id: 0x0001,
    };
    assert!(matches!(map_sym_suite(s), Err(Error::EchDecodeError)));
}

#[test]
fn map_kem_resolves_all_supported() {
    assert_eq!(map_kem(0x0010).unwrap(), HpkeKem::DhkemP256HkdfSha256);
    assert_eq!(map_kem(0x0011).unwrap(), HpkeKem::DhkemP384HkdfSha384);
    assert_eq!(map_kem(0x0012).unwrap(), HpkeKem::DhkemP521HkdfSha512);
    assert_eq!(map_kem(0x0020).unwrap(), HpkeKem::DhkemX25519HkdfSha256);
    assert!(matches!(map_kem(0xDEAD), Err(Error::EchDecodeError)));
}

#[test]
fn ech_info_prefix_and_shape() {
    let cfg = sample_config();
    let info = ech_info(&cfg).expect("sample config raw_contents fits in u16");
    // Must begin with "tls ech\0" then the 4-byte (version || length) header.
    assert!(info.starts_with(b"tls ech\0"));
    let after_prefix = &info[8..];
    assert_eq!(&after_prefix[..2], &ECH_VERSION_DRAFT_22.to_be_bytes());
    let len = u16::from_be_bytes([after_prefix[2], after_prefix[3]]) as usize;
    assert_eq!(len, cfg.raw_contents.len());
    assert_eq!(&after_prefix[4..], &cfg.raw_contents[..]);
}

/// An `ech_info` for a config whose `raw_contents` exceeds `u16::MAX`
/// returns [`Error::EchDecodeError`] rather than silently clamping the
/// length field (audit F4 / draft-ietf-tls-esni-22 §4 — ECHConfig length
/// is a `u16`).
#[test]
fn ech_info_rejects_oversize_raw_contents() {
    let mut cfg = sample_config();
    cfg.raw_contents = alloc::vec![0u8; (u16::MAX as usize) + 1];
    assert!(matches!(ech_info(&cfg), Err(Error::EchDecodeError)));
}

#[test]
fn inner_extension_body_matches_marker() {
    assert_eq!(inner_extension_body(), alloc::vec![0x01]);
}

#[test]
fn accept_signal_deterministic_and_label_separated() {
    let inner_random = [0x42u8; 32];
    let th = [0x33u8; 32];
    let sh = server_hello_signal(HashAlg::Sha256, &inner_random, &th);
    let sh2 = server_hello_signal(HashAlg::Sha256, &inner_random, &th);
    assert_eq!(sh, sh2);
    let hrr = hello_retry_request_signal(HashAlg::Sha256, &inner_random, &th);
    // Distinct labels MUST yield distinct outputs.
    assert_ne!(sh, hrr);
}

/// RFC 9849 §7.2 / §7.2.1: both acceptance signals equal
/// `HKDF-Expand-Label(HKDF-Extract(0, ClientHelloInner.random), label,
/// transcript_ech_conf, 8)` — recomputed here from the raw HKDF
/// primitives (manual `HkdfLabel` encoding included) so a regression in
/// `server_hello_signal` / `hello_retry_request_signal` toward any
/// key-schedule-derived variant fails loudly. The derivation must be
/// fully independent of the TLS 1.3 key schedule.
#[test]
fn accept_signals_match_raw_hkdf_formula() {
    use crate::hash::{Sha256, Sha384};
    use crate::kdf::{hkdf_expand, hkdf_extract};

    fn raw<D: crate::hash::Digest>(
        label: &[u8],
        inner_random: &[u8; 32],
        transcript_hash: &[u8],
    ) -> [u8; 8] {
        // HKDF-Extract(0, random): "0" is Hash.length zero bytes.
        let zeros = alloc::vec![0u8; D::OUTPUT_LEN];
        let prk = hkdf_extract::<D>(&zeros, inner_random);
        // HkdfLabel { length(2), label<7..255> = "tls13 " + label,
        //             context<0..255> = transcript_hash } (RFC 8446 §7.1).
        let mut info = Vec::new();
        info.extend_from_slice(&8u16.to_be_bytes());
        info.push((6 + label.len()) as u8);
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(transcript_hash.len() as u8);
        info.extend_from_slice(transcript_hash);
        let mut out = [0u8; 8];
        hkdf_expand::<D>(&prk, &info, &mut out);
        out
    }

    let inner_random: [u8; 32] = core::array::from_fn(|i| i as u8);
    let th256 = HashAlg::Sha256.hash(b"transcript_ech_conf");
    let th384 = HashAlg::Sha384.hash(b"transcript_ech_conf");

    assert_eq!(
        server_hello_signal(HashAlg::Sha256, &inner_random, th256.as_slice()),
        raw::<Sha256>(b"ech accept confirmation", &inner_random, th256.as_slice()),
    );
    assert_eq!(
        server_hello_signal(HashAlg::Sha384, &inner_random, th384.as_slice()),
        raw::<Sha384>(b"ech accept confirmation", &inner_random, th384.as_slice()),
    );
    assert_eq!(
        hello_retry_request_signal(HashAlg::Sha256, &inner_random, th256.as_slice()),
        raw::<Sha256>(
            b"hrr ech accept confirmation",
            &inner_random,
            th256.as_slice()
        ),
    );
    assert_eq!(
        hello_retry_request_signal(HashAlg::Sha384, &inner_random, th384.as_slice()),
        raw::<Sha384>(
            b"hrr ech accept confirmation",
            &inner_random,
            th384.as_slice()
        ),
    );
}

#[test]
fn accept_signal_constant_time_eq_matches_plain_eq() {
    let mut a = [0u8; 8];
    let mut b = [0u8; 8];
    assert!(signals_eq_ct(&a, &b));
    a[3] = 1;
    assert!(!signals_eq_ct(&a, &b));
    b[3] = 1;
    assert!(signals_eq_ct(&a, &b));
}

#[test]
fn random_tail_helpers_invert_each_other() {
    let r = [0xAAu8; 32];
    let signal = [0xBBu8; 8];
    let patched = patch_random_tail(&r, &signal);
    assert_eq!(&patched[..24], &r[..24]);
    assert_eq!(random_tail(&patched), signal);
    let zeroed = random_with_zero_tail(&r);
    assert_eq!(&zeroed[..24], &r[..24]);
    assert_eq!(&zeroed[24..], &[0u8; 8]);
}

#[test]
fn ech_config_list_supports_first_supported_when_first_is_unknown() {
    // Putting an unknown-version config first must not break selection
    // of the second supported one (draft §6.1).
    let unknown = EchConfig {
        version: 0xFFFF,
        contents: None,
        raw_contents: alloc::vec![0xCA, 0xFE],
    };
    let supported = sample_config();
    let list = EchConfigList::new(alloc::vec![unknown, supported]);
    let first = list.first_supported().expect("a supported entry");
    assert_eq!(first.version, ECH_VERSION_DRAFT_22);
}

// ---------------------------------------------------------------------
// ech_outer_extensions codec (inner.rs) — compression / decompression
// round-trips plus the draft §5.1 fatal-decompression-error matrix.
// ---------------------------------------------------------------------

fn ext(t: ExtensionType, body: &[u8]) -> (ExtensionType, Vec<u8>) {
    (t, body.to_vec())
}

#[test]
fn outer_extensions_body_roundtrip() {
    let types = [
        ExtensionType::SUPPORTED_GROUPS,
        ExtensionType::KEY_SHARE,
        ExtensionType::SUPPORTED_VERSIONS,
    ];
    let body = encode_outer_extensions(&types);
    let decoded = decode_outer_extensions(&body).expect("decode");
    assert_eq!(decoded, types);
    // Wire shape: 1-byte length prefix of len = N*2, followed by N u16s.
    assert_eq!(body[0] as usize, types.len() * 2);
    assert_eq!(body.len(), 1 + types.len() * 2);
}

#[test]
fn outer_extensions_body_rejects_malformed() {
    // Empty body.
    assert!(matches!(
        decode_outer_extensions(&[]),
        Err(Error::EchDecodeError)
    ));
    // Length byte mismatch.
    assert!(matches!(
        decode_outer_extensions(&[0x04, 0x00, 0x0a]),
        Err(Error::EchDecodeError)
    ));
    // Odd length not divisible by 2.
    assert!(matches!(
        decode_outer_extensions(&[0x03, 0x00, 0x0a, 0x00]),
        Err(Error::EchDecodeError)
    ));
    // Empty list (length 0) — must reference at least one type per draft.
    assert!(matches!(
        decode_outer_extensions(&[0x00]),
        Err(Error::EchDecodeError)
    ));
    // Trailing bytes after declared length.
    assert!(matches!(
        decode_outer_extensions(&[0x02, 0x00, 0x0a, 0xff]),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn compress_then_decompress_yields_canonical() {
    let outer = alloc::vec![
        ext(ExtensionType::SERVER_NAME, b"public.example"),
        ext(ExtensionType::SUPPORTED_GROUPS, &[0x00, 0x02, 0x00, 0x1d]),
        ext(
            ExtensionType::SIGNATURE_ALGORITHMS,
            &[0x00, 0x02, 0x08, 0x07]
        ),
        ext(ExtensionType::KEY_SHARE, &[0x00, 0x00]),
        ext(ExtensionType::SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04]),
    ];
    let canonical_inner = alloc::vec![
        ext(ExtensionType::SERVER_NAME, b"secret.example"),
        ext(ExtensionType::SUPPORTED_GROUPS, &[0x00, 0x02, 0x00, 0x1d]),
        ext(
            ExtensionType::SIGNATURE_ALGORITHMS,
            &[0x00, 0x02, 0x08, 0x07]
        ),
        ext(ExtensionType::KEY_SHARE, &[0x00, 0x00]),
        ext(ExtensionType::SUPPORTED_VERSIONS, &[0x02, 0x03, 0x04]),
        (
            ExtensionType::ENCRYPTED_CLIENT_HELLO,
            inner_extension_body()
        ),
    ];
    let share = [
        ExtensionType::SUPPORTED_GROUPS,
        ExtensionType::SIGNATURE_ALGORITHMS,
        ExtensionType::KEY_SHARE,
        ExtensionType::SUPPORTED_VERSIONS,
    ];
    let compressed = compress_extensions(&canonical_inner, &outer, &share).expect("compress");
    // The compressed list keeps the SNI (unique to inner), then the
    // single placeholder, then the inner ECH marker.
    assert_eq!(compressed.len(), 3);
    assert_eq!(compressed[0].0, ExtensionType::SERVER_NAME);
    assert_eq!(compressed[1].0, ExtensionType::ECH_OUTER_EXTENSIONS);
    assert_eq!(compressed[2].0, ExtensionType::ENCRYPTED_CLIENT_HELLO);
    let decompressed = decompress_extensions(&compressed, &outer).expect("decompress");
    assert_eq!(decompressed, canonical_inner);
}

#[test]
fn compress_empty_share_is_identity() {
    let outer = alloc::vec![ext(ExtensionType::SERVER_NAME, b"public.example")];
    let canonical = alloc::vec![
        ext(ExtensionType::SERVER_NAME, b"secret.example"),
        (
            ExtensionType::ENCRYPTED_CLIENT_HELLO,
            inner_extension_body()
        ),
    ];
    let out = compress_extensions(&canonical, &outer, &[]).expect("identity");
    assert_eq!(out, canonical);
}

#[test]
fn compress_rejects_duplicate_share_types() {
    let outer = alloc::vec![
        ext(ExtensionType::SUPPORTED_GROUPS, &[0x00]),
        ext(ExtensionType::KEY_SHARE, &[0x00]),
    ];
    let canonical = alloc::vec![
        ext(ExtensionType::SUPPORTED_GROUPS, &[0x00]),
        ext(ExtensionType::KEY_SHARE, &[0x00]),
    ];
    let share = [
        ExtensionType::SUPPORTED_GROUPS,
        ExtensionType::KEY_SHARE,
        ExtensionType::SUPPORTED_GROUPS,
    ];
    assert!(matches!(
        compress_extensions(&canonical, &outer, &share),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn compress_rejects_reserved_share_types() {
    let outer = alloc::vec![ext(ExtensionType::SUPPORTED_GROUPS, &[0x00])];
    let canonical = alloc::vec![ext(ExtensionType::SUPPORTED_GROUPS, &[0x00])];
    let share_a = [ExtensionType::ECH_OUTER_EXTENSIONS];
    let share_b = [ExtensionType::ENCRYPTED_CLIENT_HELLO];
    assert!(matches!(
        compress_extensions(&canonical, &outer, &share_a),
        Err(Error::EchDecodeError)
    ));
    assert!(matches!(
        compress_extensions(&canonical, &outer, &share_b),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn compress_rejects_when_share_block_not_contiguous_in_inner() {
    let outer = alloc::vec![
        ext(ExtensionType::SUPPORTED_GROUPS, &[0x00]),
        ext(ExtensionType::KEY_SHARE, &[0x00]),
    ];
    let canonical = alloc::vec![
        ext(ExtensionType::SUPPORTED_GROUPS, &[0x00]),
        ext(ExtensionType::SERVER_NAME, b"x"),
        ext(ExtensionType::KEY_SHARE, &[0x00]),
    ];
    // The share types appear in `canonical` but separated by SERVER_NAME,
    // so no contiguous slice matches.
    let share = [ExtensionType::SUPPORTED_GROUPS, ExtensionType::KEY_SHARE];
    assert!(matches!(
        compress_extensions(&canonical, &outer, &share),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn decompress_rejects_unknown_type_referenced() {
    let outer = alloc::vec![ext(ExtensionType::SUPPORTED_GROUPS, &[0x00])];
    let compressed = alloc::vec![
        ext(ExtensionType::SERVER_NAME, b"x"),
        (
            ExtensionType::ECH_OUTER_EXTENSIONS,
            encode_outer_extensions(&[ExtensionType::KEY_SHARE]),
        ),
    ];
    assert!(matches!(
        decompress_extensions(&compressed, &outer),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn decompress_rejects_wrong_order_in_outer() {
    // Outer has KEY_SHARE then SUPPORTED_GROUPS; the placeholder asks
    // for them in the opposite order. Per draft §5.1 the referenced
    // outer extensions MUST appear in the order indicated.
    let outer = alloc::vec![
        ext(ExtensionType::KEY_SHARE, &[0x00]),
        ext(ExtensionType::SUPPORTED_GROUPS, &[0x00]),
    ];
    let compressed = alloc::vec![(
        ExtensionType::ECH_OUTER_EXTENSIONS,
        encode_outer_extensions(&[ExtensionType::SUPPORTED_GROUPS, ExtensionType::KEY_SHARE,]),
    )];
    assert!(matches!(
        decompress_extensions(&compressed, &outer),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn decompress_rejects_multiple_placeholders() {
    let outer = alloc::vec![ext(ExtensionType::SUPPORTED_GROUPS, &[0x00])];
    let compressed = alloc::vec![
        (
            ExtensionType::ECH_OUTER_EXTENSIONS,
            encode_outer_extensions(&[ExtensionType::SUPPORTED_GROUPS]),
        ),
        (
            ExtensionType::ECH_OUTER_EXTENSIONS,
            encode_outer_extensions(&[ExtensionType::SUPPORTED_GROUPS]),
        ),
    ];
    assert!(matches!(
        decompress_extensions(&compressed, &outer),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn decompress_rejects_reserved_in_list() {
    let outer = alloc::vec![ext(ExtensionType::SUPPORTED_GROUPS, &[0x00])];
    // Inner asks to substitute `encrypted_client_hello` from outer
    // (which is not allowed). Encode the body by hand because the
    // helper's validation would refuse to produce it.
    let mut body = alloc::vec![2u8];
    body.extend_from_slice(&ExtensionType::ENCRYPTED_CLIENT_HELLO.0.to_be_bytes());
    let compressed = alloc::vec![(ExtensionType::ECH_OUTER_EXTENSIONS, body)];
    assert!(matches!(
        decompress_extensions(&compressed, &outer),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn decompress_passes_through_when_no_placeholder() {
    let outer = alloc::vec![ext(ExtensionType::SUPPORTED_GROUPS, &[0x00])];
    let compressed = alloc::vec![
        ext(ExtensionType::SERVER_NAME, b"secret.example"),
        (
            ExtensionType::ENCRYPTED_CLIENT_HELLO,
            inner_extension_body()
        ),
    ];
    let out = decompress_extensions(&compressed, &outer).expect("passthrough");
    assert_eq!(out, compressed);
}

// ============================================================================
// Outer-CH HPKE seal pipeline (outer.rs)
// ============================================================================

use super::outer::{
    HPKE_TAG_LEN, build_outer_ext_body, locate_payload_in_handshake, pad_inner, seal_with,
    try_decap_inner,
};

/// Build a minimal but syntactically-valid ClientHello handshake message
/// containing exactly one extension: an outer-form `encrypted_client_hello`
/// with the given body.
fn build_outer_ch_with_ech(ech_ext_body: &[u8]) -> Vec<u8> {
    // CH body: version(2) + random(32) + sid_len(1)+sid + cs_len(2)+cs +
    // cm_len(1)+cm + ext_len(2)+ext.
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
    body.extend_from_slice(&[0x42u8; 32]); // random
    body.push(0); // sid_len = 0
    body.extend_from_slice(&2u16.to_be_bytes()); // cs_len
    body.extend_from_slice(&0x1301u16.to_be_bytes()); // AES-128-GCM-SHA256
    body.push(1); // cm_len
    body.push(0); // null compression
    let mut exts: Vec<u8> = Vec::new();
    let ty = ExtensionType::ENCRYPTED_CLIENT_HELLO.0;
    exts.extend_from_slice(&ty.to_be_bytes());
    let bl: u16 = u16::try_from(ech_ext_body.len()).unwrap();
    exts.extend_from_slice(&bl.to_be_bytes());
    exts.extend_from_slice(ech_ext_body);
    let el: u16 = u16::try_from(exts.len()).unwrap();
    body.extend_from_slice(&el.to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg: Vec<u8> = Vec::new();
    msg.push(crate::tls::codec::hs_type::CLIENT_HELLO);
    let bl_u32 = u32::try_from(body.len()).unwrap();
    msg.push(((bl_u32 >> 16) & 0xff) as u8);
    msg.push(((bl_u32 >> 8) & 0xff) as u8);
    msg.push((bl_u32 & 0xff) as u8);
    msg.extend_from_slice(&body);
    msg
}

/// Variant of [`build_inner_ch_marker`] used for negative tests: the
/// inner CH is otherwise well-formed but does NOT carry the
/// `encrypted_client_hello` inner-form marker. The decap code MUST
/// reject this with `EchDecodeError` (which the connection layer maps
/// to `illegal_parameter(47)`, per draft-ietf-tls-esni-22 §7.1).
fn build_inner_ch_without_marker() -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0x55u8; 32]);
    body.push(0); // sid_len
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);
    // Empty extensions list — no ECH inner marker. We add an unrelated
    // benign extension (`server_name` with empty body) so the
    // extension area parses as a list rather than appearing absent.
    let mut exts: Vec<u8> = Vec::new();
    exts.extend_from_slice(&ExtensionType::SERVER_NAME.0.to_be_bytes());
    exts.extend_from_slice(&0u16.to_be_bytes());
    let el: u16 = u16::try_from(exts.len()).unwrap();
    body.extend_from_slice(&el.to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg: Vec<u8> = Vec::new();
    msg.push(crate::tls::codec::hs_type::CLIENT_HELLO);
    let bl_u32 = u32::try_from(body.len()).unwrap();
    msg.push(((bl_u32 >> 16) & 0xff) as u8);
    msg.push(((bl_u32 >> 8) & 0xff) as u8);
    msg.push((bl_u32 & 0xff) as u8);
    msg.extend_from_slice(&body);
    msg
}

/// Build a minimal encoded inner CH for the round-trip test: an
/// otherwise-empty CH carrying just the inner-form ECH marker so the
/// server can confirm what it decrypted is an ECH inner.
fn build_inner_ch_marker() -> Vec<u8> {
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0x55u8; 32]);
    body.push(0); // sid_len
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);
    let mut exts: Vec<u8> = Vec::new();
    let ech_inner = inner_extension_body();
    exts.extend_from_slice(&ExtensionType::ENCRYPTED_CLIENT_HELLO.0.to_be_bytes());
    let bl: u16 = u16::try_from(ech_inner.len()).unwrap();
    exts.extend_from_slice(&bl.to_be_bytes());
    exts.extend_from_slice(&ech_inner);
    let el: u16 = u16::try_from(exts.len()).unwrap();
    body.extend_from_slice(&el.to_be_bytes());
    body.extend_from_slice(&exts);

    let mut msg: Vec<u8> = Vec::new();
    msg.push(crate::tls::codec::hs_type::CLIENT_HELLO);
    let bl_u32 = u32::try_from(body.len()).unwrap();
    msg.push(((bl_u32 >> 16) & 0xff) as u8);
    msg.push(((bl_u32 >> 8) & 0xff) as u8);
    msg.push((bl_u32 & 0xff) as u8);
    msg.extend_from_slice(&body);
    msg
}

#[test]
fn pad_inner_rounds_up_to_multiple_of_32_with_min_32() {
    // Tiny CH → bumped to 32.
    let p = pad_inner(&[0x11u8; 5], 0, 0);
    assert_eq!(p.len(), 32);
    assert_eq!(&p[..5], &[0x11; 5]);
    assert!(p[5..].iter().all(|b| *b == 0));
}

#[test]
fn pad_inner_extra_for_sni_shorter_than_maximum_name_length() {
    const L_IN: usize = 40;
    let l_sni = 5usize;
    let l_max = 64u8;
    let p = pad_inner(&[0xAAu8; L_IN], l_sni, l_max);
    // extra = 64 - 5 = 59; target = 40 + 59 = 99; rounded up to 128.
    assert_eq!(p.len(), 128);
    assert!(p[L_IN..].iter().all(|b| *b == 0));
}

#[test]
fn pad_inner_no_extra_when_sni_at_least_max() {
    let p = pad_inner(&[0xBBu8; 50], 200, 64);
    // extra collapses to 0; target = 50 rounded up to 64.
    assert_eq!(p.len(), 64);
}

#[test]
fn locate_payload_finds_ech_payload_offset_and_length() {
    let ext_body = build_outer_ext_body(
        HpkeSymCipherSuite {
            kdf_id: 0x0001,
            aead_id: 0x0001,
        },
        0xab,
        &[0x77u8; 32],
        48,
    );
    let msg = build_outer_ch_with_ech(&ext_body);
    let (off, len) = locate_payload_in_handshake(&msg).expect("locate");
    assert_eq!(len, 48 + HPKE_TAG_LEN);
    // Verify the bytes at the located range are zero (skeleton).
    assert!(msg[off..off + len].iter().all(|b| *b == 0));
}

#[test]
fn locate_payload_rejects_wrong_handshake_type() {
    let mut msg = build_outer_ch_with_ech(&build_outer_ext_body(
        HpkeSymCipherSuite {
            kdf_id: 0x0001,
            aead_id: 0x0001,
        },
        1,
        &[0x00u8; 8],
        32,
    ));
    msg[0] = crate::tls::codec::hs_type::SERVER_HELLO;
    assert!(matches!(
        locate_payload_in_handshake(&msg),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn locate_payload_rejects_no_ech_extension() {
    // Build a CH with only one non-ECH extension.
    let mut body: Vec<u8> = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);
    let mut exts: Vec<u8> = Vec::new();
    exts.extend_from_slice(&ExtensionType::SERVER_NAME.0.to_be_bytes());
    exts.extend_from_slice(&0u16.to_be_bytes());
    let el: u16 = u16::try_from(exts.len()).unwrap();
    body.extend_from_slice(&el.to_be_bytes());
    body.extend_from_slice(&exts);
    let mut msg: Vec<u8> = Vec::new();
    msg.push(crate::tls::codec::hs_type::CLIENT_HELLO);
    let bl = u32::try_from(body.len()).unwrap();
    msg.extend_from_slice(&[
        ((bl >> 16) & 0xff) as u8,
        ((bl >> 8) & 0xff) as u8,
        (bl & 0xff) as u8,
    ]);
    msg.extend_from_slice(&body);
    assert!(matches!(
        locate_payload_in_handshake(&msg),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn seal_and_decap_round_trip_x25519_aes128gcm() {
    // Mint a server-side X25519 ECH key.
    let mut rng = drbg(b"seal-x25519");
    let suites = alloc::vec![HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    }];
    let pair = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0x42,
        b"public.example",
        64,
        suites,
    )
    .expect("generate");
    let config = pair.config().clone();
    let ring = EchKeyRing::from_pairs(alloc::vec![pair]);

    // Build a plain inner CH carrying the inner-form ECH marker.
    let inner = build_inner_ch_marker();

    // Seal it into an outer skeleton. The closure produces the outer
    // CH bytes whose ECH extension payload is zeroed.
    let sym = HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    };
    let sealed = seal_with(&config, sym, &inner, 5, &mut rng, |enc, padded_len| {
        let body = build_outer_ext_body(sym, 0x42, enc, padded_len);
        build_outer_ch_with_ech(&body)
    })
    .expect("seal");

    // Decap on the server side and recover the inner CH.
    let recovered = try_decap_inner(&sealed.outer_ch, &ring).expect("decap");
    assert_eq!(recovered.inner_ch_bytes, inner);
}

/// Privacy regression: the 8-bit `config_id` is only a lookup hint and
/// collides readily, so during operator key rotation two distinct
/// `EchKeyPair`s can share one `config_id`. A client that picked the
/// NEWER key must still decap even when an OLDER key with the same
/// `config_id` sits earlier in the ring. draft-ietf-tls-esni-22 §7.1
/// says the server SHOULD try ALL configs whose `config_id` matches;
/// the old code committed to the first match, decap failed, and the
/// connection was pushed onto the cleartext-SNI public_name path — the
/// exact exposure ECH exists to prevent. Here both keys publish
/// `config_id = 0x42`; the client seals under the second (newer) key,
/// and decap MUST recover the inner CH by trying the second candidate.
#[test]
fn seal_and_decap_matches_second_key_sharing_config_id() {
    let mut rng = drbg(b"seal-rotation-collision");
    let suites = alloc::vec![HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    }];
    // Two independent keys, SAME config_id (0x42), different key
    // material (different public keys), as happens on an 8-bit
    // config_id collision during rotation.
    let old_pair = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0x42,
        b"public.example",
        64,
        suites.clone(),
    )
    .expect("generate old");
    let new_pair = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0x42,
        b"public.example",
        64,
        suites,
    )
    .expect("generate new");
    // The client holds the NEWER config and seals under it.
    let new_config = new_pair.config().clone();
    // The ring lists the OLDER key first, so a first-match-only server
    // would attempt (and fail) decap against the old key.
    let ring = EchKeyRing::from_pairs(alloc::vec![old_pair, new_pair]);

    let inner = build_inner_ch_marker();
    let sym = HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    };
    let sealed = seal_with(&new_config, sym, &inner, 5, &mut rng, |enc, padded_len| {
        let body = build_outer_ext_body(sym, 0x42, enc, padded_len);
        build_outer_ch_with_ech(&body)
    })
    .expect("seal");

    // Must succeed by sweeping past the colliding older key to the one
    // the client actually used.
    let recovered = try_decap_inner(&sealed.outer_ch, &ring).expect("decap newer key");
    assert_eq!(recovered.inner_ch_bytes, inner);
    assert_eq!(recovered.config_id, 0x42);
}

/// TLS-4 regression: the server-side decap path MUST verify that the
/// decrypted inner CH carries the inner-form
/// `encrypted_client_hello` marker (draft-ietf-tls-esni-22 §6.1.1
/// step 8 — "the client_hello MUST contain an ECH inner extension").
/// Without this check, a peer who can decap (e.g. via a leaked
/// private key) could feed back an ECH-shaped outer CH and trick the
/// server into treating it as inner. We require the marker and
/// surface `EchDecodeError` (mapped to `illegal_parameter(47)` at the
/// alert layer).
#[test]
fn decap_rejects_inner_ch_without_marker() {
    let mut rng = drbg(b"decap-no-marker");
    let suites = alloc::vec![HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    }];
    let pair = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0x42,
        b"public.example",
        64,
        suites,
    )
    .expect("generate");
    let config = pair.config().clone();
    let ring = EchKeyRing::from_pairs(alloc::vec![pair]);

    // Seal an inner CH that omits the inner-form ECH marker.
    let inner = build_inner_ch_without_marker();
    let sym = HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    };
    let sealed = seal_with(&config, sym, &inner, 5, &mut rng, |enc, padded_len| {
        let body = build_outer_ext_body(sym, 0x42, enc, padded_len);
        build_outer_ch_with_ech(&body)
    })
    .expect("seal");

    assert!(matches!(
        try_decap_inner(&sealed.outer_ch, &ring),
        Err(Error::EchDecodeError)
    ));
}

#[test]
fn decap_rejects_unknown_config_id() {
    let mut rng = drbg(b"decap-cfg-id");
    let suites = alloc::vec![HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    }];
    let pair = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0x42,
        b"public.example",
        64,
        suites,
    )
    .expect("generate");
    let config = pair.config().clone();
    let ring = EchKeyRing::from_pairs(alloc::vec![pair]);

    let inner = build_inner_ch_marker();
    let sym = HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    };
    // Seal under config_id = 0x99 (not in ring).
    let sealed = seal_with(&config, sym, &inner, 5, &mut rng, |enc, padded_len| {
        let body = build_outer_ext_body(sym, 0x99, enc, padded_len);
        build_outer_ch_with_ech(&body)
    })
    .expect("seal");
    assert!(matches!(
        try_decap_inner(&sealed.outer_ch, &ring),
        Err(Error::EchDecryptionFailed)
    ));
}

/// F6 regression: the server MUST reject an ECH whose HPKE symmetric
/// suite `(kdf, aead)` is not among those published in the matching
/// ECHConfig's `cipher_suites`, treating it as a rejection (fall back
/// to the outer CH / retry_configs) per draft-ietf-tls-esni-22 §7.1.
/// Here the key publishes only HKDF-SHA256/AES-128-GCM; a client that
/// seals under HKDF-SHA256/AES-256-GCM (a valid suite, just not
/// announced for this config) must be rejected before decap, while a
/// published suite still decaps normally.
#[test]
fn decap_rejects_unpublished_hpke_suite() {
    let mut rng = drbg(b"decap-unpublished-suite");
    // Published suites: only AES-128-GCM with HKDF-SHA256.
    let suites = alloc::vec![HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    }];
    let pair = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0x42,
        b"public.example",
        64,
        suites,
    )
    .expect("generate");
    let config = pair.config().clone();
    let ring = EchKeyRing::from_pairs(alloc::vec![pair]);

    let inner = build_inner_ch_marker();

    // Seal under AES-256-GCM — a supported suite, but NOT published for
    // this config. Sealing succeeds (it depends only on the public key
    // and the chosen suite), but the server must reject it at decap.
    let unpublished = HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes256Gcm.id(),
    };
    let sealed = seal_with(
        &config,
        unpublished,
        &inner,
        5,
        &mut rng,
        |enc, padded_len| {
            let body = build_outer_ext_body(unpublished, 0x42, enc, padded_len);
            build_outer_ch_with_ech(&body)
        },
    )
    .expect("seal");
    assert!(matches!(
        try_decap_inner(&sealed.outer_ch, &ring),
        Err(Error::EchDecryptionFailed)
    ));

    // Control: the published suite still decaps and recovers the inner.
    let published = HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    };
    let ok = seal_with(
        &config,
        published,
        &inner,
        5,
        &mut rng,
        |enc, padded_len| {
            let body = build_outer_ext_body(published, 0x42, enc, padded_len);
            build_outer_ch_with_ech(&body)
        },
    )
    .expect("seal");
    let recovered = try_decap_inner(&ok.outer_ch, &ring).expect("decap");
    assert_eq!(recovered.inner_ch_bytes, inner);
}

#[test]
fn decap_rejects_aead_corruption() {
    let mut rng = drbg(b"decap-corrupt");
    let suites = alloc::vec![HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    }];
    let pair = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0x07,
        b"public.example",
        64,
        suites,
    )
    .expect("generate");
    let config = pair.config().clone();
    let ring = EchKeyRing::from_pairs(alloc::vec![pair]);
    let inner = build_inner_ch_marker();
    let sym = HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    };
    let sealed = seal_with(&config, sym, &inner, 5, &mut rng, |enc, padded_len| {
        let body = build_outer_ext_body(sym, 0x07, enc, padded_len);
        build_outer_ch_with_ech(&body)
    })
    .expect("seal");

    // Flip a byte in the ciphertext.
    let (off, len) = locate_payload_in_handshake(&sealed.outer_ch).expect("locate");
    let mut corrupted = sealed.outer_ch.clone();
    let _ = len;
    corrupted[off] ^= 0x01;
    assert!(matches!(
        try_decap_inner(&corrupted, &ring),
        Err(Error::EchDecryptionFailed)
    ));
}

#[test]
fn decap_rejects_aad_mutation_outside_payload() {
    // Mutate a byte in the outer CH outside the payload (e.g. a byte
    // in the random) — AEAD should reject because the AAD differs.
    let mut rng = drbg(b"decap-aad");
    let suites = alloc::vec![HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    }];
    let pair = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0x11,
        b"public.example",
        64,
        suites,
    )
    .expect("generate");
    let config = pair.config().clone();
    let ring = EchKeyRing::from_pairs(alloc::vec![pair]);
    let inner = build_inner_ch_marker();
    let sym = HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    };
    let sealed = seal_with(&config, sym, &inner, 5, &mut rng, |enc, padded_len| {
        let body = build_outer_ext_body(sym, 0x11, enc, padded_len);
        build_outer_ch_with_ech(&body)
    })
    .expect("seal");

    // Tamper with a random byte (well outside the payload).
    let mut tampered = sealed.outer_ch.clone();
    tampered[10] ^= 0xff;
    assert!(matches!(
        try_decap_inner(&tampered, &ring),
        Err(Error::EchDecryptionFailed)
    ));
}

#[test]
fn full_ech_round_trip_seal_decap_and_accept_signal() {
    // This integration test exercises the seal + decap pipeline in
    // wave 3a together with the accept-signal helpers from wave 1 —
    // i.e. everything Phase 5 needs at the cryptographic layer,
    // wired in the order the connection state machines will use.
    //
    // Mocks (not yet covered): the handshake_secret (here a fixed
    // test value, in reality the inner-transcript handshake secret),
    // the inner CH carrying real extensions (here we use the
    // marker-only inner from `build_inner_ch_marker`).
    let mut rng = drbg(b"phase5-e2e");
    let suites = alloc::vec![HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    }];
    let pair = EchKeyPair::generate(
        &mut rng,
        HpkeKem::DhkemX25519HkdfSha256,
        0x42,
        b"public.example",
        64,
        suites,
    )
    .expect("generate");
    let config = pair.config().clone();
    let ring = EchKeyRing::from_pairs(alloc::vec![pair]);

    // === Client side: build inner CH, seal into outer CH ===
    let inner_ch = build_inner_ch_marker();
    let sym = HpkeSymCipherSuite {
        kdf_id: HpkeKdf::HkdfSha256.id(),
        aead_id: HpkeAead::Aes128Gcm.id(),
    };
    let sealed = seal_with(&config, sym, &inner_ch, 5, &mut rng, |enc, padded_len| {
        let body = build_outer_ext_body(sym, 0x42, enc, padded_len);
        build_outer_ch_with_ech(&body)
    })
    .expect("seal");

    // === Server side: decap to recover the inner CH ===
    let recovered_inner = try_decap_inner(&sealed.outer_ch, &ring).expect("decap");
    assert_eq!(recovered_inner.inner_ch_bytes, inner_ch);

    // === Server side: build an SH with the accept signal patched in ===
    // The "inner transcript" up to this point is just the inner CH bytes.
    // The SH gets its random's tail zeroed before signal computation, then
    // the signal is patched in.
    let sh_random = [0x77u8; 32];
    let sh_with_zero_tail_random = random_with_zero_tail(&sh_random);
    // Compute transcript_hash over `(inner_ch || zero_tail_SH_bytes)`. We
    // approximate the "zero-tail SH bytes" by just including the random:
    // for a real handshake the transcript would include the SH wire
    // bytes; this test uses the random alone since the rest is fixed.
    let alg = HashAlg::Sha256;
    let mut to_hash = inner_ch.clone();
    to_hash.extend_from_slice(&sh_with_zero_tail_random);
    let th = alg.hash(&to_hash);
    // The signal's IKM is the inner CH's `random` (RFC 9849 §7.2) —
    // offset 6 in the handshake-message bytes (type 1 + length 3 +
    // legacy_version 2).
    let mut inner_ch_random = [0u8; 32];
    inner_ch_random.copy_from_slice(&inner_ch[6..38]);
    let signal = server_hello_signal(alg, &inner_ch_random, th.as_slice());
    let patched_random = patch_random_tail(&sh_random, &signal);
    assert_eq!(random_tail(&patched_random), signal);

    // === Client side: recompute the expected signal and compare ===
    // Same inputs in the inner transcript → same signal expected.
    let mut client_hash_input = inner_ch.clone();
    client_hash_input.extend_from_slice(&random_with_zero_tail(&patched_random));
    let client_th = alg.hash(&client_hash_input);
    let expected = server_hello_signal(alg, &inner_ch_random, client_th.as_slice());
    let received = random_tail(&patched_random);
    assert!(signals_eq_ct(&expected, &received));

    // === Negative: wrong inner-CH random → mismatch ===
    let wrong_random = [0xCDu8; 32];
    let wrong_expected = server_hello_signal(alg, &wrong_random, client_th.as_slice());
    assert!(!signals_eq_ct(&wrong_expected, &received));
}

#[test]
fn ech_rejected_retry_configs_round_trip_in_ee_body() {
    // On ECH reject, the server's EE carries an `encrypted_client_hello`
    // extension whose body is the wire ECHConfigList. The client surfaces
    // those bytes via `Error::EchRejected(...)` for the caller to retry.
    let list = EchConfigList::new(alloc::vec![sample_config()]);
    let encoded = encode_retry_configs(&list);
    let decoded = decode_retry_configs(&encoded).expect("decode");
    assert_eq!(list.encode(), decoded.encode());

    // The carrier path: the EE extension body is the encoded list
    // verbatim; an `Error::EchRejected(bytes)` is constructed from
    // those bytes and re-decoded on the other side of the API.
    let err = Error::EchRejected(encoded.clone());
    match err {
        Error::EchRejected(bytes) => {
            let again = decode_retry_configs(&bytes).expect("re-decode");
            assert_eq!(again.encode(), list.encode());
        }
        _ => panic!("wrong variant"),
    }
}
