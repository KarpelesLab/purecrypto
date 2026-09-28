//! Encrypted Client Hello (RFC 9849) support for the CLI: the
//! `generate-ech` subcommand and the `s_client` / `s_server` ECH options.
//!
//! File formats match BoringSSL's `bssl generate-ech` / `bssl server
//! -ech-key -ech-config` / `bssl client -ech-config-list`, so key material
//! moves between the two tools unchanged:
//!
//! - an `ECHConfigList` file holds the wire `ECHConfigList` (the value a
//!   DNS HTTPS record's `ech=` parameter carries). `s_client` also accepts
//!   it base64-encoded, as `dig` prints it;
//! - an `ECHConfig` file holds one wire `ECHConfig`;
//! - a private-key file holds the raw HPKE private key (32 bytes for
//!   DHKEM(X25519, HKDF-SHA256)).
//!
//! Everything here is compiled only with the `ech` feature. Without it the
//! flags are still recognised, but refused with a message saying how to get
//! them, rather than being silently ignored (which would send the real
//! server name in the clear).

use crate::util::{Args, die};
use purecrypto::tls::ConfigBuilder;

/// The value-taking ECH flags of `s_client`, for positional parsing.
pub(crate) const CLIENT_VALUE_FLAGS: [&str; 2] = ["-ech-config-list", "-ech-retry-configs-out"];

/// Where the `s_client` ECH options ended up: what to report after the
/// handshake and where to save a rejection's `retry_configs`.
#[derive(Default, Clone)]
pub(crate) struct ClientEch {
    /// A real `ECHConfigList` was configured.
    pub(crate) real: bool,
    /// GREASE ECH was requested instead.
    pub(crate) grease: bool,
    /// `-ech-retry-configs-out`: file to write the server's `retry_configs`.
    /// (Only a build with `ech` can be rejected, hence ever read it.)
    #[cfg_attr(not(feature = "ech"), allow(dead_code))]
    pub(crate) retry_out: Option<String>,
}

impl ClientEch {
    /// Whether any ECH option is in play (the protocol must be TLS 1.3).
    pub(crate) fn any(&self) -> bool {
        self.real || self.grease
    }
}

#[cfg(not(feature = "ech"))]
fn no_ech(flag: &str) -> ! {
    die(format!(
        "{flag}: this purecrypto binary was built without Encrypted Client Hello support; \
         rebuild with `--features ech`"
    ))
}

/// Applies `s_client`'s ECH options (`-ech-config-list FILE`, `-ech-grease`,
/// `-ech-retry-configs-out FILE`) to `builder`.
pub(crate) fn apply_client(args: &Args, builder: ConfigBuilder) -> (ConfigBuilder, ClientEch) {
    let list = args.value("-ech-config-list");
    let grease = args.flag("-ech-grease");
    let retry_out = args.value("-ech-retry-configs-out").map(str::to_string);
    if list.is_some() && grease {
        die("-ech-config-list and -ech-grease are mutually exclusive");
    }
    if retry_out.is_some() && list.is_none() {
        die("-ech-retry-configs-out needs -ech-config-list");
    }
    let state = ClientEch {
        real: list.is_some(),
        grease,
        retry_out,
    };
    #[cfg(not(feature = "ech"))]
    {
        if list.is_some() {
            no_ech("-ech-config-list");
        }
        if grease {
            no_ech("-ech-grease");
        }
        (builder, state)
    }
    #[cfg(feature = "ech")]
    {
        use purecrypto::tls::ech::EchClient;
        let mut builder = builder;
        if let Some(path) = list {
            let bytes = read_config_list(path);
            let client = EchClient::from_config_list_bytes(&bytes)
                .unwrap_or_else(|e| die(format!("{path}: not a valid ECHConfigList: {e}")));
            builder = builder.ech(client);
        } else if grease {
            builder = builder.ech(EchClient::default_grease());
        }
        (builder, state)
    }
}

/// Reads an `ECHConfigList` file: the raw wire encoding, or the same bytes
/// in base64 (surrounding whitespace ignored).
#[cfg(feature = "ech")]
fn read_config_list(path: &str) -> Vec<u8> {
    let raw = crate::util::read_input(Some(path));
    if purecrypto::tls::ech::EchConfigList::decode(&raw).is_ok() {
        return raw;
    }
    match core::str::from_utf8(&raw)
        .ok()
        .and_then(|s| purecrypto::der::base64_decode(s.trim()).ok())
    {
        Some(decoded) => decoded,
        None => raw,
    }
}

/// Reports the ECH outcome of a completed client handshake on stderr.
pub(crate) fn report_client(conn: &purecrypto::tls::Connection, state: &ClientEch) {
    #[cfg(feature = "ech")]
    {
        if state.real {
            // A rejected real-ECH offer never completes the handshake (it
            // fails with `EchRejected`), so a completed one was accepted.
            if conn.ech_accepted() {
                eprintln!("ECH: accepted");
            } else {
                eprintln!("ECH: not accepted");
            }
        } else if state.grease {
            eprintln!("ECH: GREASE (not negotiated)");
        }
    }
    #[cfg(not(feature = "ech"))]
    let _ = (conn, state);
}

/// If `e` is an ECH rejection, reports it (and saves the server's
/// `retry_configs` when asked) and returns `true`; the caller still fails
/// the connection — RFC 9849 §6.1.6 forbids using it for application data.
pub(crate) fn report_client_error(e: &purecrypto::tls::Error, state: &ClientEch) -> bool {
    #[cfg(feature = "ech")]
    if let purecrypto::tls::Error::EchRejected(retry) = e {
        eprintln!("ECH: rejected (server authenticated as the ECHConfig public_name)");
        if retry.is_empty() {
            eprintln!("ECH retry_configs: none (the server disabled ECH)");
        } else {
            eprintln!(
                "ECH retry_configs: {}",
                purecrypto::der::base64_encode(retry)
            );
            if let Some(path) = &state.retry_out {
                std::fs::write(path, retry)
                    .unwrap_or_else(|err| die(format!("cannot write {path}: {err}")));
                eprintln!("ECH retry_configs written to {path}");
            }
        }
        return true;
    }
    let _ = (e, state);
    false
}

/// Applies `s_server`'s ECH options (`-ech-key FILE -ech-config FILE`) to
/// `builder`. Returns whether ECH is configured.
pub(crate) fn apply_server(args: &Args, builder: ConfigBuilder) -> (ConfigBuilder, bool) {
    let key = args.value("-ech-key");
    let config = args.value("-ech-config");
    match (key, config) {
        (None, None) => (builder, false),
        (Some(_), None) | (None, Some(_)) => die("-ech-key and -ech-config must be given together"),
        #[cfg(not(feature = "ech"))]
        (Some(_), Some(_)) => no_ech("-ech-key"),
        #[cfg(feature = "ech")]
        (Some(key_path), Some(config_path)) => {
            use purecrypto::tls::ech::{EchConfig, EchKeyPair, EchKeyRing, EchServer};
            let config_bytes = crate::util::read_input(Some(config_path));
            let config = EchConfig::decode(&config_bytes)
                .unwrap_or_else(|e| die(format!("{config_path}: not a valid ECHConfig: {e}")));
            let mut sk = crate::util::read_secret_file(key_path);
            let pair = EchKeyPair::from_private_key(config, &sk);
            crate::util::zero_buf(&mut sk);
            let pair = pair.unwrap_or_else(|_| {
                die(format!(
                    "{key_path}: not the HPKE private key of {config_path} \
                     (or the ECHConfig's version / KEM is unsupported)"
                ))
            });
            let ring = EchKeyRing::from_pairs(vec![pair]);
            let retry = ring.to_config_list();
            (builder.ech_server(EchServer::new(ring, retry)), true)
        }
    }
}

/// Reports the ECH outcome of a server handshake on stderr.
pub(crate) fn report_server(conn: &purecrypto::tls::Connection, configured: bool) {
    #[cfg(feature = "ech")]
    if configured {
        if conn.ech_accepted() {
            eprintln!("ECH: accepted");
        } else {
            eprintln!("ECH: not accepted");
        }
    }
    #[cfg(not(feature = "ech"))]
    let _ = (conn, configured);
}

/// `purecrypto generate-ech` — create an ECH key pair and its `ECHConfig`,
/// written in the formats `bssl generate-ech` uses.
pub(crate) fn run_generate(args: Args) {
    const USAGE: &str = "usage: purecrypto generate-ech -public-name NAME \
        -out-ech-config-list FILE -out-ech-config FILE -out-private-key FILE \
        [-config-id N] [-max-name-length N]";
    let public_name = args.value("-public-name").unwrap_or_else(|| die(USAGE));
    let out_list = args
        .value("-out-ech-config-list")
        .unwrap_or_else(|| die(USAGE));
    let out_config = args.value("-out-ech-config").unwrap_or_else(|| die(USAGE));
    let out_key = args.value("-out-private-key").unwrap_or_else(|| die(USAGE));
    let config_id = parse_u8(args.value("-config-id"), "-config-id");
    let max_name_length = parse_u8(args.value("-max-name-length"), "-max-name-length");
    crate::util::reject_extra_positionals(
        &args.positionals(&[
            "-public-name",
            "-out-ech-config-list",
            "-out-ech-config",
            "-out-private-key",
            "-config-id",
            "-max-name-length",
        ]),
        0,
    );
    #[cfg(not(feature = "ech"))]
    {
        let _ = (
            public_name,
            out_list,
            out_config,
            out_key,
            config_id,
            max_name_length,
        );
        no_ech("generate-ech")
    }
    #[cfg(feature = "ech")]
    {
        use purecrypto::hpke::HpkeKem;
        use purecrypto::tls::ech::{
            EchConfig, EchConfigContents, EchConfigList, HpkeKeyConfig, HpkeSymCipherSuite,
        };
        if public_name.is_empty() || public_name.len() > 255 {
            die("-public-name must be 1..=255 bytes");
        }
        let kem = HpkeKem::DhkemX25519HkdfSha256;
        let (mut sk, pk) = kem
            .generate_key_pair(&mut purecrypto::rng::OsRng)
            .unwrap_or_else(|e| die(format!("HPKE key generation failed: {e:?}")));
        // The suites BoringSSL's `SSL_marshal_ech_config` publishes, in its
        // order: HKDF-SHA256 with AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305.
        let cipher_suites = [0x0001u16, 0x0002, 0x0003]
            .iter()
            .map(|&aead_id| HpkeSymCipherSuite {
                kdf_id: 0x0001,
                aead_id,
            })
            .collect();
        let config = EchConfig::new(EchConfigContents {
            key_config: HpkeKeyConfig {
                config_id,
                kem_id: kem.id(),
                public_key: pk,
                cipher_suites,
            },
            maximum_name_length: max_name_length,
            public_name: public_name.as_bytes().to_vec(),
            extensions: Vec::new(),
        });
        let list = EchConfigList::new(vec![config.clone()]).encode();
        crate::util::write_output_with_mode(Some(out_key), &sk, true);
        crate::util::zero_buf(&mut sk);
        crate::util::write_output(Some(out_config), &config.encode());
        crate::util::write_output(Some(out_list), &list);
        eprintln!(
            "ECHConfigList (base64): {}",
            purecrypto::der::base64_encode(&list)
        );
    }
}

fn parse_u8(value: Option<&str>, flag: &str) -> u8 {
    match value {
        None => 0,
        Some(v) => v
            .parse::<u8>()
            .unwrap_or_else(|_| die(format!("{flag} expects a number in 0..=255"))),
    }
}
