//! `purecrypto rand <nbytes>` — emit cryptographically secure random bytes.

use crate::util::{Args, die, to_hex, write_output_with_mode};
use purecrypto::rng::{OsRng, RngCore};

/// Cap on a single `rand` invocation: 1 GiB. Above this we refuse rather
/// than `vec![0u8; n]` and OOM (a typo with `cat /dev/zero | xargs` shouldn't
/// crash the tool).
const MAX_RAND_BYTES: usize = 1 << 30;

pub(crate) fn run(args: Args) {
    let pos = args.positionals(&["-out"]);
    let Some(&n) = pos.first() else {
        die("usage: purecrypto rand <nbytes> [--binary] [-out file]");
    };
    let n: usize = n
        .parse()
        .unwrap_or_else(|_| die(format!("invalid byte count: {n}")));
    if n > MAX_RAND_BYTES {
        die(format!(
            "byte count {n} exceeds the {MAX_RAND_BYTES}-byte cap"
        ));
    }

    let mut buf = vec![0u8; n];
    OsRng.fill_bytes(&mut buf);

    // These bytes are key material as often as not (`rand 32 -out aes.key`),
    // so a `-out FILE` gets the same 0600/create_new treatment `kdf::emit`
    // gives identical material rather than a world-readable 0644 file.
    let dest = args.value("-out");
    if args.flag("--binary") || args.flag("-binary") {
        // Raw bytes: private, which also refuses to spray them at a TTY.
        write_output_with_mode(dest, &buf, /* private = */ true);
    } else {
        // Hex is the same key material re-encoded, so `-out FILE` is private
        // too; hex to stdout (or `-out -`) stays allowed — printing hex to a
        // terminal is the intended interactive use.
        let private = matches!(dest, Some(p) if p != "-");
        let mut line = to_hex(&buf);
        line.push('\n');
        write_output_with_mode(dest, line.as_bytes(), private);
    }
}
