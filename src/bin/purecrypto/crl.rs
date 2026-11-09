//! `purecrypto crl -in FILE [-CAfile CA [-verify]] [-text] [-serial SERIAL -is-revoked]`
//!
//! Every requested mode runs, signature verification first. Exit status:
//! 0 success (for `-is-revoked`: the serial is revoked), 1 the serial is
//! *not* revoked, 2 any error — so `crl -is-revoked … && reject` cannot
//! mistake an unreadable or forged CRL for an answer.

use crate::pki::display_dn;
use crate::util::{Args, die, from_hex, read_input, set_error_exit_status, terminal_safe, to_hex};
use purecrypto::x509::{Certificate, CertificateRevocationList};

/// Exit status for "the serial is not on the list" (`-is-revoked` only).
const EXIT_NOT_REVOKED: i32 = 1;
/// Exit status for every error: usage, I/O, parse, signature failure.
const EXIT_ERROR: i32 = 2;

const USAGE: &str = "usage: purecrypto crl -in FILE [-CAfile FILE [-verify]] [-text] [-serial S -is-revoked]\n\
     exit status: 0 ok / revoked, 1 not revoked, 2 error (including a failed -verify)";

fn load_crl(path: Option<&str>) -> CertificateRevocationList {
    let raw = read_input(path);
    let s = core::str::from_utf8(&raw).unwrap_or("");
    if s.contains("-----BEGIN") {
        CertificateRevocationList::from_pem(s)
            .unwrap_or_else(|e| die(format!("could not parse CRL PEM: {e}")))
    } else {
        CertificateRevocationList::from_der(raw)
            .unwrap_or_else(|e| die(format!("could not parse CRL DER: {e}")))
    }
}

/// The magnitude of a big-endian serial: every leading zero octet dropped
/// (one is kept for the value zero). Both the `-serial` argument and the
/// CRL's entries are reduced to this before they are compared or printed.
fn magnitude(bytes: &[u8]) -> &[u8] {
    let first = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    &bytes[first..]
}

/// A serial as `-text` prints it and `-serial` reads it back: `0x` plus the
/// hex magnitude. The prefix is what makes it unambiguous — an unprefixed
/// all-digit `-serial` is decimal.
fn serial_display(serial: &[u8]) -> String {
    format!("0x{}", to_hex(magnitude(serial)))
}

/// Parses `-serial`: `0x…` hex (the form `crl -text` and `ca issue` print;
/// `:` separators and an odd digit count are fine), an all-digit decimal
/// number, or bare hex containing at least one of `a`–`f`.
fn parse_serial(arg: &str) -> Result<Vec<u8>, String> {
    let hex = |digits: &str| -> Result<Vec<u8>, String> {
        let mut cleaned: String = digits.chars().filter(|c| *c != ':').collect();
        if cleaned.is_empty() {
            return Err(format!("invalid serial: {arg}"));
        }
        if cleaned.len() % 2 == 1 {
            cleaned.insert(0, '0'); // `ca` prints `{:#x}`, e.g. 0x123
        }
        // `from_hex` skips whitespace; a serial has none.
        if cleaned.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(format!("invalid serial hex: {arg}"));
        }
        from_hex(&cleaned).ok_or_else(|| format!("invalid serial hex: {arg}"))
    };
    let bytes = if let Some(rest) = arg.strip_prefix("0x").or_else(|| arg.strip_prefix("0X")) {
        hex(rest)?
    } else if !arg.is_empty() && arg.bytes().all(|b| b.is_ascii_digit()) {
        let n: u128 = arg.parse().map_err(|_| {
            format!("decimal serial {arg} is too large; give it as hex with a 0x prefix")
        })?;
        n.to_be_bytes().to_vec()
    } else {
        hex(arg)?
    };
    Ok(magnitude(&bytes).to_vec())
}

fn text(crl: &CertificateRevocationList) {
    let issuer = crl
        .issuer()
        .unwrap_or_else(|e| die(format!("bad issuer: {e}")));
    let this = crl
        .this_update()
        .unwrap_or_else(|e| die(format!("bad thisUpdate: {e}")));
    let next = crl
        .next_update()
        .unwrap_or_else(|e| die(format!("bad nextUpdate: {e}")));
    println!("Certificate Revocation List:");
    println!("    Issuer:      {}", display_dn(&issuer));
    println!("    This Update: {}", terminal_safe(this.as_str()));
    if let Some(n) = next {
        println!("    Next Update: {}", terminal_safe(n.as_str()));
    }
    // RFC 5280 §5.2.3 cRLNumber: an unsigned big-endian magnitude of up to
    // 20 octets, so print it as hex rather than squeezing it into a u64.
    match crl.crl_number() {
        Ok(Some(n)) => println!("    CRL Number:  0x{}", to_hex(&n)),
        Ok(None) => println!("    CRL Number:  (absent)"),
        Err(e) => die(format!("bad cRLNumber: {e}")),
    }
    let entries = crl
        .entries()
        .unwrap_or_else(|e| die(format!("bad entries: {e}")));
    println!("    Revoked entries: {}", entries.len());
    for e in &entries {
        // `0x`-prefixed, exactly what `-serial` takes back: unprefixed hex
        // made of digits only would be read as a decimal number there.
        let serial = serial_display(&e.serial);
        let date = terminal_safe(e.revocation_date.as_str());
        match e.reason {
            Some(r) => println!("        serial={serial} date={date} reason={r:?}"),
            None => println!("        serial={serial} date={date}"),
        }
    }
}

/// Verifies the CRL's signature under the certificate in `ca_path`; fatal
/// (exit 2) when it does not verify.
fn verify(crl: &CertificateRevocationList, ca_path: &str) {
    let ca_pem = read_input(Some(ca_path));
    let ca_pem = core::str::from_utf8(&ca_pem).unwrap_or_else(|_| die("CA file is not UTF-8 PEM"));
    let ca =
        Certificate::from_pem(ca_pem).unwrap_or_else(|e| die(format!("cannot parse CA cert: {e}")));
    let key = ca
        .subject_public_key()
        .unwrap_or_else(|e| die(format!("CA has no public key: {e}")));
    match crl.verify_signature_with(&key) {
        Ok(()) => println!("verify OK"),
        Err(_) => {
            eprintln!("verify FAIL");
            std::process::exit(EXIT_ERROR);
        }
    }
}

/// Whether `serial` (a [`magnitude`]) is on the list. Compared here rather
/// than through `CertificateRevocationList::is_revoked`, which strips only a
/// single leading zero octet from either side.
fn is_revoked(crl: &CertificateRevocationList, serial: &[u8]) -> bool {
    crl.entries()
        .unwrap_or_else(|e| die(format!("CRL parse error: {e}")))
        .iter()
        .any(|e| magnitude(&e.serial) == serial)
}

pub(crate) fn run(args: Args) {
    // Before anything that can fail: from here on every `die` — a usage
    // error, an unreadable `-in`, a corrupt CRL — exits 2, never the 1 that
    // means "not revoked".
    set_error_exit_status(EXIT_ERROR);
    let args = args.declare(&["-in", "-CAfile", "-cafile", "-serial"]);
    crate::util::reject_extra_positionals(&args.positionals(), 0);

    let want_text = args.flag("-text");
    let want_revoked = args.flag("-is-revoked");
    let ca = args.value("-CAfile").or_else(|| args.value("-cafile"));
    // A CA handed over is a CA to verify under, `-verify` or not: silently
    // ignoring `-CAfile` would answer from a list nobody authenticated.
    let want_verify = args.flag("-verify") || ca.is_some();
    if !(want_text || want_verify || want_revoked) {
        die(USAGE);
    }
    // Validate the arguments of every requested mode before producing any
    // output, so a typo cannot follow a reassuring `verify OK`.
    let serial = if want_revoked {
        let raw = args
            .value("-serial")
            .unwrap_or_else(|| die("-is-revoked requires -serial SERIAL"));
        Some(parse_serial(raw).unwrap_or_else(|e| die(e)))
    } else {
        None
    };
    if want_verify && ca.is_none() {
        die("-verify requires -CAfile CA.pem");
    }

    let crl = load_crl(args.value("-in"));

    // Every requested mode runs. Verification goes first and is fatal: the
    // text and the revocation answer of a list that failed it must not be
    // printed at all (`-verify -text` used to print the text, exit 0 and
    // never verify; `-verify -is-revoked` never consulted the list).
    if let Some(ca) = ca {
        verify(&crl, ca);
    }
    if want_text {
        text(&crl);
    }
    if let Some(serial) = serial {
        if is_revoked(&crl, &serial) {
            println!("revoked");
        } else {
            println!("not revoked");
            std::process::exit(EXIT_NOT_REVOKED);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_forms_normalise_to_one_magnitude() {
        let want = [0x1a, 0x2b];
        for s in [
            "0x1A2B",
            "0X1a2b",
            "0x00001A2B",
            "0x0000000000000000000000000000000000001a2b",
            "1a2b",
            "001A2B",
            "1a:2b",
            "0x1a:2b",
            "6699", // decimal
        ] {
            assert_eq!(parse_serial(s).as_deref(), Ok(&want[..]), "{s}");
        }
        // Odd digit counts (`ca` prints `{:#x}`).
        assert_eq!(parse_serial("0x123"), Ok(vec![0x01, 0x23]));
        assert_eq!(parse_serial("abc"), Ok(vec![0x0a, 0xbc]));
        // All digits without a prefix is decimal, with one it is hex.
        assert_eq!(parse_serial("1234"), Ok(vec![0x04, 0xd2]));
        assert_eq!(parse_serial("0x1234"), Ok(vec![0x12, 0x34]));
        // Zero keeps one octet.
        assert_eq!(parse_serial("0"), Ok(vec![0]));
        assert_eq!(parse_serial("0x0000"), Ok(vec![0]));
        for bad in ["", "0x", "0xzz", "12 34", "0x12 34", "-5", "1g", ":"] {
            assert!(parse_serial(bad).is_err(), "{bad:?}");
        }
        // A decimal serial beyond u128 is an error, not a wrong answer.
        assert!(parse_serial("999999999999999999999999999999999999999999").is_err());
    }

    #[test]
    fn text_serial_round_trips_through_dash_serial() {
        for raw in [
            &[0x00, 0x12, 0x34][..],
            &[0x12, 0x34],
            &[0x00],
            &[0x00, 0xff],
        ] {
            let shown = serial_display(raw);
            assert!(shown.starts_with("0x"), "{shown}");
            assert_eq!(parse_serial(&shown).unwrap(), magnitude(raw), "{shown}");
        }
        // The digits-only case that used to be ambiguous.
        assert_eq!(serial_display(&[0x12, 0x34]), "0x1234");
    }
}
