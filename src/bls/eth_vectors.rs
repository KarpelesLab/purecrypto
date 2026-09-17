//! Ethereum 2.0 BLS test vectors (github.com/ethereum/bls12-381-tests, v0.1.2),
//! converted verbatim by `tools/bls/eth_vectors.py`. The signature cases use
//! the Proof of Possession ciphersuite DST; the `hash_to_G2` cases are the
//! RFC 9380 J.10.1 vectors (QUUX DST). Hex is without the `0x` prefix.

#![allow(dead_code)]

pub(crate) struct SignCase {
    pub name: &'static str,
    pub privkey: &'static str,
    pub message: &'static str,
    /// `None` when signing must fail (zero secret key).
    pub output: Option<&'static str>,
}

pub(crate) struct VerifyCase {
    pub name: &'static str,
    pub pubkey: &'static str,
    pub message: &'static str,
    pub signature: &'static str,
    pub output: bool,
}

pub(crate) struct AggregateCase {
    pub name: &'static str,
    pub input: &'static [&'static str],
    pub output: Option<&'static str>,
}

pub(crate) struct AggregateVerifyCase {
    pub name: &'static str,
    pub pubkeys: &'static [&'static str],
    pub messages: &'static [&'static str],
    pub signature: &'static str,
    pub output: bool,
}

pub(crate) struct FastAggregateVerifyCase {
    pub name: &'static str,
    pub pubkeys: &'static [&'static str],
    pub message: &'static str,
    pub signature: &'static str,
    pub output: bool,
}

pub(crate) struct DeserializationCase {
    pub name: &'static str,
    pub input: &'static str,
    pub output: bool,
}

pub(crate) struct HashToG2Case {
    pub name: &'static str,
    /// The ASCII message.
    pub msg: &'static str,
    /// `(c0, c1)` of the affine x-coordinate.
    pub x: (&'static str, &'static str),
    /// `(c0, c1)` of the affine y-coordinate.
    pub y: (&'static str, &'static str),
}

pub(crate) const SIGN: &[SignCase] = &[
    SignCase {
        name: "sign_case_11b8c7cad5238946",
        privkey: "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        output: Some(
            "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        ),
    },
    SignCase {
        name: "sign_case_142f678a8d05fcd1",
        privkey: "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        output: Some(
            "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        ),
    },
    SignCase {
        name: "sign_case_37286e1a6d1f6eb3",
        privkey: "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138",
        message: "abababababababababababababababababababababababababababababababab",
        output: Some(
            "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
        ),
    },
    SignCase {
        name: "sign_case_7055381f640f2c1d",
        privkey: "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        output: Some(
            "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        ),
    },
    SignCase {
        name: "sign_case_84d45c9c7cca6b92",
        privkey: "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
        message: "abababababababababababababababababababababababababababababababab",
        output: Some(
            "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        ),
    },
    SignCase {
        name: "sign_case_8cd3d4d0d9a5b265",
        privkey: "328388aff0d4a5b7dc9205abd374e7e98f3cd9f3418edb4eafda5fb16473d216",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        output: Some(
            "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        ),
    },
    SignCase {
        name: "sign_case_c82df61aa3ee60fb",
        privkey: "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        output: Some(
            "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        ),
    },
    SignCase {
        name: "sign_case_d0e28d7e76eb6e9c",
        privkey: "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        output: Some(
            "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        ),
    },
    SignCase {
        name: "sign_case_f2ae1097e7d0e18b",
        privkey: "263dbd792f5b1be47ed85f8938c0f29586af0d3ac7b977f21c278fe1462040e3",
        message: "abababababababababababababababababababababababababababababababab",
        output: Some(
            "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
        ),
    },
    SignCase {
        name: "sign_case_zero_privkey",
        privkey: "0000000000000000000000000000000000000000000000000000000000000000",
        message: "abababababababababababababababababababababababababababababababab",
        output: None,
    },
];

pub(crate) const VERIFY: &[VerifyCase] = &[
    VerifyCase {
        name: "verify_infinity_pubkey_and_infinity_signature",
        pubkey: "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        message: "1212121212121212121212121212121212121212121212121212121212121212",
        signature: "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    VerifyCase {
        name: "verify_tampered_signature_case_195246ee3bd3b6ec",
        pubkey: "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        message: "abababababababababababababababababababababababababababababababab",
        signature: "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9ffffffff",
        output: false,
    },
    VerifyCase {
        name: "verify_tampered_signature_case_2ea479adf8c40300",
        pubkey: "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972ffffffff",
        output: false,
    },
    VerifyCase {
        name: "verify_tampered_signature_case_2f09d443ab8a3ac2",
        pubkey: "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dffffffff",
        output: false,
    },
    VerifyCase {
        name: "verify_tampered_signature_case_3208262581c8fc09",
        pubkey: "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363ffffffff",
        output: false,
    },
    VerifyCase {
        name: "verify_tampered_signature_case_6b3b17f6962a490c",
        pubkey: "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffffffff",
        output: false,
    },
    VerifyCase {
        name: "verify_tampered_signature_case_6eeb7c52dfd9baf0",
        pubkey: "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        message: "abababababababababababababababababababababababababababababababab",
        signature: "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5ffffffff",
        output: false,
    },
    VerifyCase {
        name: "verify_tampered_signature_case_8761a0b7e920c323",
        pubkey: "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        message: "abababababababababababababababababababababababababababababababab",
        signature: "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b71ffffffff",
        output: false,
    },
    VerifyCase {
        name: "verify_tampered_signature_case_d34885d766d5f705",
        pubkey: "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075effffffff",
        output: false,
    },
    VerifyCase {
        name: "verify_tampered_signature_case_e8a50c445c855360",
        pubkey: "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380bffffffff",
        output: false,
    },
    VerifyCase {
        name: "verify_valid_case_195246ee3bd3b6ec",
        pubkey: "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        message: "abababababababababababababababababababababababababababababababab",
        signature: "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        output: true,
    },
    VerifyCase {
        name: "verify_valid_case_2ea479adf8c40300",
        pubkey: "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        output: true,
    },
    VerifyCase {
        name: "verify_valid_case_2f09d443ab8a3ac2",
        pubkey: "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        output: true,
    },
    VerifyCase {
        name: "verify_valid_case_3208262581c8fc09",
        pubkey: "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        output: true,
    },
    VerifyCase {
        name: "verify_valid_case_6b3b17f6962a490c",
        pubkey: "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        output: true,
    },
    VerifyCase {
        name: "verify_valid_case_6eeb7c52dfd9baf0",
        pubkey: "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        message: "abababababababababababababababababababababababababababababababab",
        signature: "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
        output: true,
    },
    VerifyCase {
        name: "verify_valid_case_8761a0b7e920c323",
        pubkey: "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        message: "abababababababababababababababababababababababababababababababab",
        signature: "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
        output: true,
    },
    VerifyCase {
        name: "verify_valid_case_d34885d766d5f705",
        pubkey: "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        output: true,
    },
    VerifyCase {
        name: "verify_valid_case_e8a50c445c855360",
        pubkey: "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        output: true,
    },
    VerifyCase {
        name: "verify_wrong_pubkey_case_195246ee3bd3b6ec",
        pubkey: "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        message: "abababababababababababababababababababababababababababababababab",
        signature: "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
        output: false,
    },
    VerifyCase {
        name: "verify_wrong_pubkey_case_2ea479adf8c40300",
        pubkey: "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        output: false,
    },
    VerifyCase {
        name: "verify_wrong_pubkey_case_2f09d443ab8a3ac2",
        pubkey: "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        output: false,
    },
    VerifyCase {
        name: "verify_wrong_pubkey_case_3208262581c8fc09",
        pubkey: "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
        output: false,
    },
    VerifyCase {
        name: "verify_wrong_pubkey_case_6b3b17f6962a490c",
        pubkey: "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
        output: false,
    },
    VerifyCase {
        name: "verify_wrong_pubkey_case_6eeb7c52dfd9baf0",
        pubkey: "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        message: "abababababababababababababababababababababababababababababababab",
        signature: "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
        output: false,
    },
    VerifyCase {
        name: "verify_wrong_pubkey_case_8761a0b7e920c323",
        pubkey: "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        message: "abababababababababababababababababababababababababababababababab",
        signature: "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        output: false,
    },
    VerifyCase {
        name: "verify_wrong_pubkey_case_d34885d766d5f705",
        pubkey: "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
        output: false,
    },
    VerifyCase {
        name: "verify_wrong_pubkey_case_e8a50c445c855360",
        pubkey: "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        output: false,
    },
    VerifyCase {
        name: "verifycase_one_privkey_47117849458281be",
        pubkey: "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        message: "1212121212121212121212121212121212121212121212121212121212121212",
        signature: "a42ae16f1c2a5fa69c04cb5998d2add790764ce8dd45bf25b29b4700829232052b52352dcff1cf255b3a7810ad7269601810f03b2bc8b68cf289cf295b206770605a190b6842583e47c3d1c0f73c54907bfb2a602157d46a4353a20283018763",
        output: true,
    },
];

pub(crate) const AGGREGATE: &[AggregateCase] = &[
    AggregateCase {
        name: "aggregate_0x0000000000000000000000000000000000000000000000000000000000000000",
        input: &[
            "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
            "b23c46be3a001c63ca711f87a005c200cc550b9429d5f4eb38d74322144f1b63926da3388979e5321012fb1a0526bcd100b5ef5fe72628ce4cd5e904aeaa3279527843fae5ca9ca675f4f51ed8f83bbf7155da9ecc9663100a885d5dc6df96d9",
            "948a7cb99f76d616c2c564ce9bf4a519f1bea6b0a624a02276443c245854219fabb8d4ce061d255af5330b078d5380681751aa7053da2c98bae898edc218c75f07e24d8802a17cd1f6833b71e58f5eb5b94208b4d0bb3848cecb075ea21be115",
        ],
        output: Some(
            "9683b3e6701f9a4b706709577963110043af78a5b41991b998475a3d3fd62abf35ce03b33908418efc95a058494a8ae504354b9f626231f6b3f3c849dfdeaf5017c4780e2aee1850ceaf4b4d9ce70971a3d2cfcd97b7e5ecf6759f8da5f76d31",
        ),
    },
    AggregateCase {
        name: "aggregate_0x5656565656565656565656565656565656565656565656565656565656565656",
        input: &[
            "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
            "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe",
            "a4efa926610b8bd1c8330c918b7a5e9bf374e53435ef8b7ec186abf62e1b1f65aeaaeb365677ac1d1172a1f5b44b4e6d022c252c58486c0a759fbdc7de15a756acc4d343064035667a594b4c2a6f0b0b421975977f297dba63ee2f63ffe47bb6",
        ],
        output: Some(
            "ad38fc73846583b08d110d16ab1d026c6ea77ac2071e8ae832f56ac0cbcdeb9f5678ba5ce42bd8dce334cc47b5abcba40a58f7f1f80ab304193eb98836cc14d8183ec14cc77de0f80c4ffd49e168927a968b5cdaa4cf46b9805be84ad7efa77b",
        ),
    },
    AggregateCase {
        name: "aggregate_0xabababababababababababababababababababababababababababababababab",
        input: &[
            "91347bccf740d859038fcdcaf233eeceb2a436bcaaee9b2aa3bfb70efe29dfb2677562ccbea1c8e061fb9971b0753c240622fab78489ce96768259fc01360346da5b9f579e5da0d941e4c6ba18a0e64906082375394f337fa1af2b7127b0d121",
            "9674e2228034527f4c083206032b020310face156d4a4685e2fcaec2f6f3665aa635d90347b6ce124eb879266b1e801d185de36a0a289b85e9039662634f2eea1e02e670bc7ab849d006a70b2f93b84597558a05b879c8d445f387a5d5b653df",
            "ae82747ddeefe4fd64cf9cedb9b04ae3e8a43420cd255e3c7cd06a8d88b7c7f8638543719981c5d16fa3527c468c25f0026704a6951bde891360c7e8d12ddee0559004ccdbe6046b55bae1b257ee97f7cdb955773d7cf29adf3ccbb9975e4eb9",
        ],
        output: Some(
            "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930",
        ),
    },
    AggregateCase {
        name: "aggregate_infinity_signature",
        input: &[
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ],
        output: Some(
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
    },
    AggregateCase {
        name: "aggregate_na_signatures",
        input: &[],
        output: None,
    },
    AggregateCase {
        name: "aggregate_single_signature",
        input: &[
            "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        ],
        output: Some(
            "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        ),
    },
];

pub(crate) const AGGREGATE_VERIFY: &[AggregateVerifyCase] = &[
    AggregateVerifyCase {
        name: "aggregate_verify_infinity_pubkey",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ],
        messages: &[
            "0000000000000000000000000000000000000000000000000000000000000000",
            "5656565656565656565656565656565656565656565656565656565656565656",
            "abababababababababababababababababababababababababababababababab",
            "1212121212121212121212121212121212121212121212121212121212121212",
        ],
        signature: "9104e74b9dfd3ad502f25d6a5ef57db0ed7d9a0e00f3500586d8ce44231212542fcfaf87840539b398bf07626705cf1105d246ca1062c6c2e1a53029a0f790ed5e3cb1f52f8234dc5144c45fc847c0cd37a92d68e7c5ba7c648a8a339f171244",
        output: false,
    },
    AggregateVerifyCase {
        name: "aggregate_verify_na_pubkeys_and_infinity_signature",
        pubkeys: &[],
        messages: &[],
        signature: "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    AggregateVerifyCase {
        name: "aggregate_verify_na_pubkeys_and_na_signature",
        pubkeys: &[],
        messages: &[],
        signature: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    AggregateVerifyCase {
        name: "aggregate_verify_tampered_signature",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        ],
        messages: &[
            "0000000000000000000000000000000000000000000000000000000000000000",
            "5656565656565656565656565656565656565656565656565656565656565656",
            "abababababababababababababababababababababababababababababababab",
        ],
        signature: "9104e74bffffffff",
        output: false,
    },
    AggregateVerifyCase {
        name: "aggregate_verify_valid",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        ],
        messages: &[
            "0000000000000000000000000000000000000000000000000000000000000000",
            "5656565656565656565656565656565656565656565656565656565656565656",
            "abababababababababababababababababababababababababababababababab",
        ],
        signature: "9104e74b9dfd3ad502f25d6a5ef57db0ed7d9a0e00f3500586d8ce44231212542fcfaf87840539b398bf07626705cf1105d246ca1062c6c2e1a53029a0f790ed5e3cb1f52f8234dc5144c45fc847c0cd37a92d68e7c5ba7c648a8a339f171244",
        output: true,
    },
];

pub(crate) const FAST_AGGREGATE_VERIFY: &[FastAggregateVerifyCase] = &[
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_extra_pubkey_4f079f946446fabf",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        ],
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1",
        output: false,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_extra_pubkey_5a38e6b4017fe4dd",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        ],
        message: "abababababababababababababababababababababababababababababababab",
        signature: "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930",
        output: false,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_extra_pubkey_a698ea45b109f303",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        ],
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        output: false,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_infinity_pubkey",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
            "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ],
        message: "1212121212121212121212121212121212121212121212121212121212121212",
        signature: "afcb4d980f079265caa61aee3e26bf48bebc5dc3e7f2d7346834d76cbc812f636c937b6b44a9323d8bc4b1cdf71d6811035ddc2634017faab2845308f568f2b9a0356140727356eae9eded8b87fd8cb8024b440c57aee06076128bb32921f584",
        output: false,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_na_pubkeys_and_infinity_signature",
        pubkeys: &[],
        message: "abababababababababababababababababababababababababababababababab",
        signature: "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_na_pubkeys_and_na_signature",
        pubkeys: &[],
        message: "abababababababababababababababababababababababababababababababab",
        signature: "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_tampered_signature_3d7576f3c0e3570a",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        ],
        message: "abababababababababababababababababababababababababababababababab",
        signature: "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfcffffffff",
        output: false,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_tampered_signature_5e745ad0c6199a6c",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        ],
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380bffffffff",
        output: false,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_tampered_signature_652ce62f09290811",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        ],
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f7797ffffffff",
        output: false,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_valid_3d7576f3c0e3570a",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
            "b53d21a4cfd562c469cc81514d4ce5a6b577d8403d32a394dc265dd190b47fa9f829fdd7963afdf972e5e77854051f6f",
        ],
        message: "abababababababababababababababababababababababababababababababab",
        signature: "9712c3edd73a209c742b8250759db12549b3eaf43b5ca61376d9f30e2747dbcf842d8b2ac0901d2a093713e20284a7670fcf6954e9ab93de991bb9b313e664785a075fc285806fa5224c82bde146561b446ccfc706a64b8579513cfc4ff1d930",
        output: true,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_valid_5e745ad0c6199a6c",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        ],
        message: "0000000000000000000000000000000000000000000000000000000000000000",
        signature: "b6ed936746e01f8ecf281f020953fbf1f01debd5657c4a383940b020b26507f6076334f91e2366c96e9ab279fb5158090352ea1c5b0c9274504f4f0e7053af24802e51e4568d164fe986834f41e55c8e850ce1f98458c0cfc9ab380b55285a55",
        output: true,
    },
    FastAggregateVerifyCase {
        name: "fast_aggregate_verify_valid_652ce62f09290811",
        pubkeys: &[
            "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
            "b301803f8b5ac4a1133581fc676dfedc60d891dd5fa99028805e5ea5b08d3491af75d0707adab3b70c6a6a580217bf81",
        ],
        message: "5656565656565656565656565656565656565656565656565656565656565656",
        signature: "912c3615f69575407db9392eb21fee18fff797eeb2fbe1816366ca2a08ae574d8824dbfafb4c9eaa1cf61b63c6f9b69911f269b664c42947dd1b53ef1081926c1e82bb2a465f927124b08391a5249036146d6f3f1e17ff5f162f779746d830d1",
        output: true,
    },
];

pub(crate) const DESERIALIZATION_G1: &[DeserializationCase] = &[
    DeserializationCase {
        name: "deserialization_fails_infinity_with_false_b_flag",
        input: "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_infinity_with_true_b_flag",
        input: "c01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_not_in_G1",
        input: "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_not_in_curve",
        input: "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_too_few_bytes",
        input: "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_too_many_bytes",
        input: "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaa900",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_with_b_flag_and_a_flag_true",
        input: "e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_with_b_flag_and_x_nonzero",
        input: "c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_with_wrong_c_flag",
        input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_x_equal_to_modulus",
        input: "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_x_greater_than_modulus",
        input: "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaac",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_succeeds_correct_point",
        input: "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
        output: true,
    },
    DeserializationCase {
        name: "deserialization_succeeds_infinity_with_true_b_flag",
        input: "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: true,
    },
];

pub(crate) const DESERIALIZATION_G2: &[DeserializationCase] = &[
    DeserializationCase {
        name: "deserialization_fails_infinity_with_false_b_flag",
        input: "800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_infinity_with_true_b_flag",
        input: "c01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_not_in_G2",
        input: "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_not_in_curve",
        input: "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde0",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_too_few_bytes",
        input: "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_too_many_bytes",
        input: "8123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefff",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_with_b_flag_and_a_flag_true",
        input: "e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_with_b_flag_and_x_nonzero",
        input: "c123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_with_wrong_c_flag",
        input: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_xim_equal_to_modulus",
        input: "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_xim_greater_than_modulus",
        input: "9a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaac000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_xre_equal_to_modulus",
        input: "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_fails_xre_greater_than_modulus",
        input: "8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaac",
        output: false,
    },
    DeserializationCase {
        name: "deserialization_succeeds_correct_point",
        input: "b2cc74bc9f089ed9764bbceac5edba416bef5e73701288977b9cac1ccb6964269d4ebf78b4e8aa7792ba09d3e49c8e6a1351bdf582971f796bbaf6320e81251c9d28f674d720cca07ed14596b96697cf18238e0e03ebd7fc1353d885a39407e0",
        output: true,
    },
    DeserializationCase {
        name: "deserialization_succeeds_infinity_with_true_b_flag",
        input: "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        output: true,
    },
];

pub(crate) const HASH_TO_G2: &[HashToG2Case] = &[
    HashToG2Case {
        name: "hash_to_G2__2782afaa8406d038",
        msg: "a512_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        x: (
            "01a6ba2f9a11fa5598b2d8ace0fbe0a0eacb65deceb476fbbcb64fd24557c2f4b18ecfc5663e54ae16a84f5ab7f62534",
            "11fca2ff525572795a801eed17eb12785887c7b63fb77a42be46ce4a34131d71f7a73e95fee3f812aea3de78b4d01569",
        ),
        y: (
            "0b6798718c8aed24bc19cb27f866f1c9effcdbf92397ad6448b5c9db90d2b9da6cbabf48adc1adf59a1a28344e79d57e",
            "03a47f8e6d1763ba0cad63d6114c0accbef65707825a511b251a660a9b3994249ae4e63fac38b23da0c398689ee2ab52",
        ),
    },
    HashToG2Case {
        name: "hash_to_G2__7590bd067999bbfb",
        msg: "abc",
        x: (
            "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
            "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
        ),
        y: (
            "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
            "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16",
        ),
    },
    HashToG2Case {
        name: "hash_to_G2__a54942c8e365f378",
        msg: "",
        x: (
            "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
            "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d",
        ),
        y: (
            "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
            "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
        ),
    },
    HashToG2Case {
        name: "hash_to_G2__c938b486cf69e8f7",
        msg: "abcdef0123456789",
        x: (
            "121982811d2491fde9ba7ed31ef9ca474f0e1501297f68c298e9f4c0028add35aea8bb83d53c08cfc007c1e005723cd0",
            "190d119345b94fbd15497bcba94ecf7db2cbfd1e1fe7da034d26cbba169fb3968288b3fafb265f9ebd380512a71c3f2c",
        ),
        y: (
            "05571a0f8d3c08d094576981f4a3b8eda0a8e771fcdcc8ecceaf1356a6acf17574518acb506e435b639353c2e14827c8",
            "0bb5e7572275c567462d91807de765611490205a941a5a6af3b1691bfe596c31225d3aabdf15faff860cb4ef17c7c3be",
        ),
    },
];
