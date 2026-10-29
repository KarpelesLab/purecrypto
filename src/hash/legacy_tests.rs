//! Cross-algorithm checks for the `legacy-hashes` digests: PHP's HMAC, HKDF
//! and `hash_file` vectors (which also pin the block lengths HMAC keys on and
//! cover the 4-pass Tiger and truncated variants), and streaming
//! consistency across block boundaries.

use super::*;
use crate::test_util::from_hex;

fn hex_eq(got: &[u8], want: &str, what: &str) {
    let mut buf = [0u8; 64];
    let n = want.len() / 2;
    for (i, b) in buf[..n].iter_mut().enumerate() {
        *b = u8::from_str_radix(&want[2 * i..2 * i + 2], 16).unwrap();
    }
    assert_eq!(got, &buf[..n], "{what}");
}

fn hmac<D: Digest>(key: &[u8], msg: &[u8]) -> D::Output {
    let mut m = Hmac::<D>::new(key);
    Mac::update(&mut m, msg);
    let mut out = D::zeroed_output();
    Mac::finalize_into(m, out.as_mut());
    out
}

// php-src ext/hash/tests/hash_hmac_basic.phpt.
#[test]
fn php_hmac() {
    let key = b"secret";
    let msg = b"This is a sample string used to test the hash_hmac function with various hashing algorithms";
    hex_eq(
        &hmac::<Gost94>(key, msg),
        "a4a3c80bdf3f8665bf07376a34dc9c1b11af7c813f4928f62e39f0c0dc564dad",
        "gost",
    );
    hex_eq(
        &hmac::<Haval128_3>(key, msg),
        "4d1318607f0406bd1b7bd50907772672",
        "haval128,3",
    );
    hex_eq(
        &hmac::<Ripemd128>(key, msg),
        "26c2f694a65b1928b668cf55f65529b4",
        "ripemd128",
    );
    hex_eq(
        &hmac::<Ripemd256>(key, msg),
        "4e4e5ec19322895a727f272dfe68f87bc1af66cc6ce27c6c1360a5ee78a14b30",
        "ripemd256",
    );
    hex_eq(
        &hmac::<Ripemd320>(key, msg),
        "f10a8ff82e828b92a5ff0a02fc9032bc61352d0d824821fc42f7e09cf5b5f41ee59fd33a730d7469",
        "ripemd320",
    );
    hex_eq(
        &hmac::<Snefru256>(key, msg),
        "67af483046f9cf16fe19f9087929ccfc6ad176ade3290b4d33f43e0ddb07e711",
        "snefru",
    );
    hex_eq(
        &hmac::<Tiger192_3>(key, msg),
        "00a0f884f15a9e5549ed0e40ca0190522d369027e16d5b59",
        "tiger192,3",
    );
}

// php-src ext/hash/tests/hash_file_basic1.phpt (a 91-byte message).
#[test]
fn php_hash_file() {
    let msg = b"This is a sample string used to test the hash_file function with various hashing algorithms";
    assert_eq!(
        gost94(msg),
        from_hex::<32>("d9e65f0c0c2ef944e4f8a01f4a46365c4f33a2853756878182a7f03e1490a4cd")
    );
    assert_eq!(
        Haval128_3::digest(msg),
        from_hex::<16>("c25962b13383c3ed9f13817c8f2ae7d6")
    );
    assert_eq!(
        ripemd128(msg),
        from_hex::<16>("d02a5f320a11c54c7d51f933b0bd8471")
    );
    assert_eq!(
        ripemd256(msg),
        from_hex::<32>("0edd779587c11cf32781111b264251eb37529832fb207121cd45dd95002e48a8")
    );
    assert_eq!(
        ripemd320(msg),
        from_hex::<40>(
            "bf162fa2ff20491b3016c5d8190f8ee47d7dcda8c38eaf6779349a243a029d275eec9adf16ec1b35"
        )
    );
    assert_eq!(
        snefru256(msg),
        from_hex::<32>("d414b2345d3e7fa1a31c044cf334bfc1fec24d89e464411998d579d24663895f")
    );
    assert_eq!(
        tiger(msg),
        from_hex::<24>("7acf4ebea075fac6fc8ea0e2b4af3cfa71b9460e4c53403a")
    );
}

// php-src ext/hash/tests/hash_hkdf_basic.phpt: HKDF with an empty salt and
// info and one digest's worth of output. The only PHP vectors for the 4-pass
// Tiger and the truncated Tigers.
#[cfg(feature = "kdf")]
#[test]
fn php_hkdf() {
    fn check<D: Digest>(want: &str, what: &str) {
        let mut out = [0u8; 64];
        let n = D::OUTPUT_LEN;
        crate::kdf::hkdf::<D>(b"", b"input key material", b"", &mut out[..n]);
        hex_eq(&out[..n], want, what);
    }
    check::<Ripemd128>("cb6418fc0dc9efaeb7e9654390fa7f14", "ripemd128");
    check::<Ripemd256>(
        "f2e96b292935e2395b59833ed89d928ac1197ff62c8031ebc06a3f5bad19513f",
        "ripemd256",
    );
    check::<Ripemd320>(
        "a13a682072525ceb4c4a5fef59096e682096e1096e6e7e238c7bd48a6f6c6a9ba3d7d9fbee6b68c4",
        "ripemd320",
    );
    check::<Tiger128_3>("e13c2e7262892c6bd8dfc24121e7cb34", "tiger128,3");
    check::<Tiger160_3>("48cc5a9f5e5d7029eb0544662222c0ba13822b7b", "tiger160,3");
    check::<Tiger192_3>(
        "5a665d23b6cbb405668160e58b01aebef74eba979f4bc70b",
        "tiger192,3",
    );
    check::<Tiger128_4>("8acf517ecf58cccbd65c1186d71e4116", "tiger128,4");
    check::<Tiger160_4>("cc0e33ee26700a2eb9a994bbb0e6cef29b429441", "tiger160,4");
    check::<Tiger192_4>(
        "97fa02d42331321fdc05c7f8dbc756d751ca36ce1aee69b0",
        "tiger192,4",
    );
    check::<Haval128_3>("2accab8029d42fb15fdbe9d3e2a470ca", "haval128,3");
    check::<Haval160_3>("496fd29e7fc8351d2971b96a3733a7b3de000064", "haval160,3");
    check::<Haval192_3>(
        "238a731801439b1f195e1a1568ce75251e1dd719d904a8a2",
        "haval192,3",
    );
    check::<Haval224_3>(
        "d863e596ff6b2bdba1ed7b313df1c3d177176312e81b47e9290f7566",
        "haval224,3",
    );
    check::<Haval256_3>(
        "96f555fe41255c34fe57b275f1ae40bbb8f07c6a2a6d68c849748fbb393ff443",
        "haval256,3",
    );
    check::<Haval128_4>("9822af229cc59527a72e231a690fad3b", "haval128,4");
    check::<Haval160_4>("1bbbc4d632daaf94d5ba167efaa70af5b753effe", "haval160,4");
    check::<Haval192_4>(
        "dd12a8f8919cbf5632497f0918b30236371dd1b55f71e824",
        "haval192,4",
    );
    check::<Haval224_4>(
        "8af449fb4eb627eb8887507c1279a116ac4325b5806dd22e2f2af410",
        "haval224,4",
    );
    check::<Haval256_4>(
        "bd74a6d5fa1ec23a92ce1fd76c36bc8be36f5eddbea821545a91810e1f8d6fc5",
        "haval256,4",
    );
    check::<Haval128_5>("84564f3450a6ccf6041162207dc8acba", "haval128,5");
    check::<Haval160_5>("b55cd1b3c514457b9e61c51ad22f302f6ec7cca1", "haval160,5");
    check::<Haval192_5>(
        "d1db7a8e69b327455d530d1ac60f774023b8b4bdd6bbbf92",
        "haval192,5",
    );
    check::<Haval224_5>(
        "c5a2576511f1143c6e29f63d82d6e0be8f67d0bea448e27238be5000",
        "haval224,5",
    );
    check::<Haval256_5>(
        "9dbab73d13f1fd3a1b41398fe90ba1f298329681d861b023373c33f1051bd4d3",
        "haval256,5",
    );
    check::<Snefru256>(
        "798eac954e5ece38e9acb63b50c1c2ecb799d34356358cec5a80eeeea91c8de9",
        "snefru",
    );
    check::<Gost94>(
        "64edd584b87a2dfdd1f2b44ed2db8bd27af8386aafe751c2aebaed32dfa3852e",
        "gost",
    );
}

/// Every split of a 300-byte message into two updates, and byte-at-a-time
/// feeding, must give the one-shot digest.
fn streaming<D: Digest>() {
    let msg: [u8; 300] = core::array::from_fn(|i| (i * 7 + 3) as u8);
    let want = D::digest(&msg);
    for split in 0..=msg.len() {
        let mut h = D::new();
        h.update(&msg[..split]);
        h.update(&msg[split..]);
        assert_eq!(h.finalize().as_ref(), want.as_ref(), "split at {split}");
    }
    let mut h = D::new();
    for b in &msg {
        h.update(core::slice::from_ref(b));
    }
    assert_eq!(h.finalize().as_ref(), want.as_ref(), "byte at a time");
}

#[test]
fn streaming_matches_one_shot() {
    streaming::<Ripemd128>();
    streaming::<Ripemd256>();
    streaming::<Ripemd320>();
    streaming::<Tiger192_3>();
    streaming::<Tiger128_4>();
    streaming::<Snefru256>();
    streaming::<Gost94>();
    streaming::<Gost94CryptoPro>();
    streaming::<Haval128_3>();
    streaming::<Haval224_4>();
    streaming::<Haval256_5>();
}
