//! Fuzz the TLS certificate-chain verifier (`tls::pki::verify_chain` +
//! `verify_hostname`, reached through the fuzz-only
//! `tls::fuzz::verify_server_chain` wrapper) against a pinned,
//! deterministic root.
//!
//! Two modes, selected by the first byte:
//!
//! * **Raw** (`mode & 1 == 0`): the rest is the leaf DER, or — with
//!   `mode & 2` — a `u16`-prefixed leaf followed by an intermediate. This
//!   exercises chain building over arbitrary certificates: DER parsing,
//!   issuer/anchor matching, the signature-algorithm allowlist and the
//!   verifier's rejection of garbage signatures. It can never get past
//!   the signature stage, so the checks that follow it are unreachable
//!   here.
//! * **Structured** (`mode & 1 == 1`): a flag byte and `NUL`-separated
//!   fields (host, then names) drive a chain the pinned root *actually
//!   signs* — optionally through an intermediate with `nameConstraints`
//!   built from the fuzz names — so the post-signature logic runs on
//!   attacker-shaped data: validity windows, `basicConstraints` /
//!   `pathLenConstraint`, EKU (`serverAuth` / `clientAuth` / none),
//!   permitted / excluded subtrees across dNSName / iPAddress /
//!   rfc822Name / URI / directoryName, and the RFC 6125 hostname match
//!   (dNSName wildcards, the IP-literal path, the CN fallback) against
//!   both the fuzz host and the leaf's own first SAN.
//!
//! The target asserts nothing about accept / reject: it exists to catch
//! panics, hangs and over-allocation in the verifier.

#![no_main]
use libfuzzer_sys::fuzz_target;
use purecrypto::ec::{BoxedEcdsaPrivateKey, CurveId};
use purecrypto::hash::Sha256;
use purecrypto::rng::HmacDrbg;
use purecrypto::tls::RootCertStore;
use purecrypto::tls::fuzz::verify_server_chain;
use purecrypto::x509::extension::{self, Extension};
use purecrypto::x509::{
    AnyPublicKey, CertSigner, Certificate, DistinguishedName, GeneralName, Time, Validity, oid,
};
use std::sync::OnceLock;

/// Upper bound on the number of names pulled out of one input, so a long
/// input can't turn one iteration into a thousand-SAN certificate.
const MAX_NAMES: usize = 24;

struct Pinned {
    /// Trust store holding exactly the pinned root.
    roots: RootCertStore,
    /// The root's subject, used as the issuer of whatever it signs.
    root_name: DistinguishedName,
    /// The root's signing key.
    ca_key: BoxedEcdsaPrivateKey,
    /// The intermediate's key (structured mode).
    sub_key: BoxedEcdsaPrivateKey,
    /// The leaf's public key (its private half is never needed).
    leaf_key: AnyPublicKey,
}

static PINNED: OnceLock<Pinned> = OnceLock::new();

fn pinned() -> &'static Pinned {
    PINNED.get_or_init(|| {
        let mut rng = HmacDrbg::<Sha256>::new(b"fuzz-x509-verify-chain", b"keys", &[]);
        let ca_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let sub_key = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let leaf = BoxedEcdsaPrivateKey::generate(CurveId::P256, &mut rng);
        let root_name = DistinguishedName::common_name("fuzz root");
        let root = Certificate::self_signed_general(
            &CertSigner::Ecdsa(&ca_key),
            &root_name,
            &ca_validity(),
            1,
            true,
            &[],
        )
        .unwrap();
        let mut roots = RootCertStore::new();
        roots.add_der(root.to_der().to_vec()).unwrap();
        Pinned {
            roots,
            root_name,
            ca_key,
            sub_key,
            leaf_key: AnyPublicKey::Ecdsa(leaf.public_key()),
        }
    })
}

fn ca_validity() -> Validity {
    Validity::new(
        Time::utc(2024, 1, 1, 0, 0, 0),
        Time::utc(2099, 1, 1, 0, 0, 0),
    )
}

/// The verification instant: inside the CA window, and inside the
/// structured leaf's window unless the input asked for an expired leaf.
fn now() -> Time {
    Time::utc(2026, 6, 1, 0, 0, 0)
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Turns one `NUL`-separated field into a `GeneralName`; the first byte
/// picks the variant so every subtree / SAN form is reachable.
fn general_name(field: &[u8]) -> GeneralName {
    match field.split_first() {
        Some((b'i', rest)) if rest.len() >= 4 => {
            GeneralName::IpV4([rest[0], rest[1], rest[2], rest[3]])
        }
        Some((b'6', rest)) if rest.len() >= 16 => {
            let mut v6 = [0u8; 16];
            v6.copy_from_slice(&rest[..16]);
            GeneralName::IpV6(v6)
        }
        Some((b'e', rest)) => GeneralName::Email(lossy(rest)),
        Some((b'u', rest)) => GeneralName::Uri(lossy(rest)),
        Some((b'n', rest)) => {
            GeneralName::DirectoryName(DistinguishedName::common_name(&lossy(rest)))
        }
        _ => GeneralName::Dns(lossy(field)),
    }
}

/// Builds the root-signed chain described by `flags` and `fields` and
/// returns it leaf-first, with the hostnames to try.
fn structured_chain(p: &Pinned, flags: u8, fields: &[u8]) -> Option<(Vec<Vec<u8>>, Vec<String>)> {
    let mut it = fields.split(|&b| b == 0);
    let host = lossy(it.next().unwrap_or(&[]));
    let names: Vec<GeneralName> = it.take(MAX_NAMES).map(general_name).collect();
    // Even-indexed names become the leaf's SANs, odd-indexed ones the
    // intermediate's name-constraint subtrees.
    let sans: Vec<GeneralName> = names.iter().step_by(2).cloned().collect();
    let subtrees: Vec<GeneralName> = names.iter().skip(1).step_by(2).cloned().collect();

    let with_intermediate = flags & 0x01 != 0;
    let permitted = flags & 0x02 != 0;
    let excluded = flags & 0x04 != 0;
    let eku_server = flags & 0x08 != 0;
    let eku_client = flags & 0x10 != 0;
    let leaf_is_ca = flags & 0x20 != 0;
    let path_len_zero = flags & 0x40 != 0;
    let expired = flags & 0x80 != 0;

    // --- optional intermediate, issued by the root
    let sub_name = DistinguishedName::common_name("fuzz intermediate");
    let mut chain_tail = Vec::new();
    let (issuer_name, issuer_key): (&DistinguishedName, &BoxedEcdsaPrivateKey) =
        if with_intermediate {
            let mut exts = vec![extension::basic_constraints(
                true,
                if path_len_zero { Some(0) } else { None },
            )];
            let permitted_names: &[GeneralName] = if permitted { &subtrees } else { &[] };
            let excluded_names: &[GeneralName] = if excluded { &subtrees } else { &[] };
            if !permitted_names.is_empty() || !excluded_names.is_empty() {
                exts.push(extension::name_constraints(permitted_names, excluded_names));
            }
            let sub = Certificate::issue_with_extensions(
                &CertSigner::Ecdsa(&p.ca_key),
                &p.root_name,
                &sub_name,
                &AnyPublicKey::Ecdsa(p.sub_key.public_key()),
                &ca_validity(),
                2,
                &exts,
            )
            .ok()?;
            chain_tail.push(sub.to_der().to_vec());
            (&sub_name, &p.sub_key)
        } else {
            (&p.root_name, &p.ca_key)
        };

    // --- the leaf
    let mut exts: Vec<Extension> = vec![extension::basic_constraints(leaf_is_ca, None)];
    if !sans.is_empty() {
        exts.push(extension::subject_alt_name(&sans));
    }
    match (eku_server, eku_client) {
        (true, true) => exts.push(extension::extended_key_usage(&[
            oid::ID_KP_SERVER_AUTH,
            oid::ID_KP_CLIENT_AUTH,
        ])),
        (true, false) => exts.push(extension::extended_key_usage(&[oid::ID_KP_SERVER_AUTH])),
        (false, true) => exts.push(extension::extended_key_usage(&[oid::ID_KP_CLIENT_AUTH])),
        (false, false) => {}
    }
    let validity = if expired {
        Validity::new(
            Time::utc(2020, 1, 1, 0, 0, 0),
            Time::utc(2021, 1, 1, 0, 0, 0),
        )
    } else {
        Validity::new(
            Time::utc(2025, 1, 1, 0, 0, 0),
            Time::utc(2027, 1, 1, 0, 0, 0),
        )
    };
    // The subject CN is the fuzz host, so directoryName constraints and
    // the no-SAN commonName fallback both see attacker text.
    let leaf = Certificate::issue_with_extensions(
        &CertSigner::Ecdsa(issuer_key),
        issuer_name,
        &DistinguishedName::common_name(&host),
        &p.leaf_key,
        &validity,
        3,
        &exts,
    )
    .ok()?;

    let mut chain = vec![leaf.to_der().to_vec()];
    chain.extend(chain_tail);

    let mut hosts = vec![host];
    if let Some(GeneralName::Dns(first)) = sans.first() {
        hosts.push(first.clone());
    }
    Some((chain, hosts))
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let p = pinned();
    let now = now();

    if mode & 1 == 0 {
        // Raw mode: fuzz bytes are the DER certificates themselves.
        let chain: Vec<Vec<u8>> = if mode & 2 != 0 && rest.len() >= 2 {
            let split = usize::from(u16::from_be_bytes([rest[0], rest[1]]));
            let body = &rest[2..];
            let split = split.min(body.len());
            vec![body[..split].to_vec(), body[split..].to_vec()]
        } else {
            vec![rest.to_vec()]
        };
        let _ = verify_server_chain(&p.roots, &chain, "fuzz.example", Some(&now));
        // `None` skips the validity checks and takes the other branch.
        let _ = verify_server_chain(&p.roots, &chain, "fuzz.example", None);
        return;
    }

    // Structured mode: a chain the pinned root really signs.
    let Some((&flags, fields)) = rest.split_first() else {
        return;
    };
    let Some((chain, hosts)) = structured_chain(p, flags, fields) else {
        return;
    };
    for host in &hosts {
        let _ = verify_server_chain(&p.roots, &chain, host, Some(&now));
    }
    let _ = verify_server_chain(&p.roots, &chain, "fuzz.example", None);
});
