//! `purecrypto rand <nbytes>` — emit cryptographically secure random bytes.

use crate::util::{Args, die, to_hex, write_output};
use purecrypto::rng::{OsRng, RngCore};

pub(crate) fn run(args: Args) {
    let pos = args.positionals(&["-out"]);
    let Some(&n) = pos.first() else {
        die("usage: purecrypto rand <nbytes> [--binary] [-out file]");
    };
    let n: usize = n
        .parse()
        .unwrap_or_else(|_| die(format!("invalid byte count: {n}")));

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
