//! `purecrypto rand <nbytes>` — emit cryptographically secure random bytes.

use crate::util::{Args, die, to_hex, write_output};
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

    let dest = args.value("-out");
    if args.flag("--binary") || args.flag("-binary") {
        write_output(dest, &buf);
    } else {
        let mut line = to_hex(&buf);
        line.push('\n');
        write_output(dest, line.as_bytes());
    }
}
